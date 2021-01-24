#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include <cstdarg>
#include <typeinfo>
#include "ModuleIterator.hpp" // Iterator class used to iterate over the module list

// Comment this line below to enable debug messages, and vice-versa
#define TRACE
// I'll keep working on this until i can import functions like a pro. And I plan on adding more modularity
int main(int argc, char **argv) {
	// Function we want to retrieve
    const char* func = "LoadLibraryA";
	// Function pointer var with it's signature (refer to https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
	const void *(*pLoadLibrary)(const char*) = NULL;
	// Read PEB at fs:[0x30]
	const WinDecls::PEB_T* pebPtr = (WinDecls::PEB_T*)__readfsdword(0x30);

#if defined(TRACE)
	printf("[+] PEB @: %p\n", pebPtr);
#endif

	// Retrieve LDR_DATA structure
	const WinDecls::PEB_LDR_DATA_T* Ldr = pebPtr->Ldr;
	// Retrieve the first link and typecast to an entry type
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* modPtr = (const WinDecls::LDR_DATA_TABLE_ENTRY_T*)(Ldr->InLoadOrderModuleList.Flink);
	
	ModuleIterator iter(modPtr);

	do {
		// Retrieve module base addr
		const char* base		= iter.get_base();
		// Retrieve module name
		const wchar_t* modName =  iter.get_modName();
		// Retrieve ntHeader
		const WinDecls::IMAGE_NT_HEADERS* ntHeaders = (const WinDecls::IMAGE_NT_HEADERS*)(base + ((WinDecls::IMAGE_DOS_HEADER*)base)->e_lfanew);

		// Retrieve first entry on DATA_DIRECTORY list
		const WinDecls::IMAGE_DATA_DIRECTORY dataDir = (const WinDecls::IMAGE_DATA_DIRECTORY)(ntHeaders->OptionalHeader.DataDirectory[0]);
		// Retrieve the RVA from this entry (the first entry on DataDirectory is the EXPORT_DIRECTORY)
		const unsigned long exportDirRVA = dataDir.VirtualAddress;
   
		if (exportDirRVA == NULL) {
			wprintf(L"[-] Couldn't find export directory on module \"%s\", skipping...\n", modName);
			iter = iter.next();
			continue;
		}

		// Retrieve export directory
		const WinDecls::IMAGE_EXPORT_DIRECTORY* exportDir = (const WinDecls::IMAGE_EXPORT_DIRECTORY*)(base + exportDirRVA);
		// Retrieve NumberOfNames
		unsigned long NumberOfNames = exportDir->NumberOfNames;
		// Retrieve RVA to string table
		const unsigned long RVAOfNames = exportDir->AddressOfNames;

#if defined(TRACE)
		wprintf(L"NumberOfNames in \"%s\" = %d\n", iter.get_modName(), NumberOfNames);
#endif
		// Iterate over the string table, comparing the strings with the one we want to find
		for (int index = NumberOfNames-1; index > 0; index--){
			// Had to use reinterpret_cast here, otherwise VS wouldn't compile
			// Retrieve symbol name @ index on string table
			const char* namePtr = (const char*)(base + reinterpret_cast<const unsigned long*>(base + RVAOfNames)[index]);
			
#if defined(TRACE)
			printf("[%d] = \"%s\"\n", index, namePtr);
#endif
			
			//Compares with our intended function
			if (strcmp(func, namePtr) == 0) {
				// Retrieve pointer to ordinal Table
				const unsigned short* ordTable    = (const unsigned short*)(base + exportDir->AddressOfNameOrdinals);
				// Retrieve pointer to RVA table
				const unsigned long* funcPtrTable = (const unsigned long*)(base + exportDir->AddressOfFunctions);

				// Retrieve and store function pointer
				pLoadLibrary = (const void*(*)(const char*))(base + funcPtrTable[ordTable[index]]);
			
				break;
			}
		}

		iter = iter.next();
	} while (iter.get_base() != NULL);

	// Calls intended function
	if (pLoadLibrary != NULL) {
		printf("[!] LOADING USER32.DLL...\n");
		const void *pHandle = pLoadLibrary("user32.dll");
		if (pHandle != NULL) {
			printf("  [!] MODULE LOADED @ %p\n", pHandle);
		}
	}

    return 0;
}