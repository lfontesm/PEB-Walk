#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include "ModuleIterator.hpp" // Iterator class used to iterate over the module list

// Comment this line below to enable debug messages, and vice-versa
#define TRACE

template <typename T>
T retrieve_function_by_name(const char* funcName, const char *base, const wchar_t* modName) {
	// Retrieve ntHeader
	const WinDecls::IMAGE_NT_HEADERS* ntHeaders = (const WinDecls::IMAGE_NT_HEADERS*)(base + ((WinDecls::IMAGE_DOS_HEADER*)base)->e_lfanew);
	// Retrieve first entry on DATA_DIRECTORY list
	const WinDecls::IMAGE_DATA_DIRECTORY dataDir = (const WinDecls::IMAGE_DATA_DIRECTORY)(ntHeaders->OptionalHeader.DataDirectory[0]);
	// Retrieve the RVA from this entry (the first entry on DataDirectory is the EXPORT_DIRECTORY)
	const unsigned long exportDirRVA = dataDir.VirtualAddress;

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

#if defined(TRACE)
		printf("[%d] = \"%s\"\n", index, namePtr);
#endif

		//Compares with our intended function
		if (strcmp(funcName, namePtr) == 0) {
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
T iterate_modules(const char* funcName, ModuleIterator &iter) {
	do {
		// Retrieve module base addr
		const char* base = iter.get_base();
		// Retrieve module name
		const wchar_t* modName = iter.get_modName();

		// Looks for function inside module, and if found, return and reset iterator to base module
		// If you are patient enough you could elaborate a correct order of import so you wouldn't need to reset the iterator after every function found
		// It would drastically improve performance
		T funcPtr = retrieve_function_by_name<T>(funcName, base, modName);
		if (funcPtr != NULL) {
			iter.reset();
			return funcPtr;
		}

		iter.next();
	} while (iter.get_base() != NULL);

	return NULL;
}

// I'm thinking about storing these in a different file
typedef const void* (*LoadLibrary_t)(const char*);
typedef int (*MessageBox_t)(void*, const char*, const char*, unsigned int);
LoadLibrary_t pLoadLibrary;
MessageBox_t  pMessageBox;

// I'll keep working on this until i can import functions like a pro. And I plan on adding more modularity
int main(int argc, char **argv) {
	// Function we want to retrieve
    const char* func = "LoadLibraryA";
	// Function pointer var with it's signature (refer to https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
	pLoadLibrary = NULL;
	pMessageBox =  NULL;
	// Read PEB at fs:[0x30]
	const WinDecls::PEB_T* pebPtr = (WinDecls::PEB_T*)__readfsdword(0x30);

#if defined(TRACE)
	printf("[+] PEB @: %p\n", pebPtr);
#endif

	// Retrieve LDR_DATA structure
	const WinDecls::PEB_LDR_DATA_T* Ldr = pebPtr->Ldr;
	// Retrieve the first link and typecast to an entry type
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* modPtr = (const WinDecls::LDR_DATA_TABLE_ENTRY_T*)(Ldr->InLoadOrderModuleList.Flink);
	
	ModuleIterator iter(modPtr, Ldr);

	pLoadLibrary = iterate_modules<decltype(pLoadLibrary)>(func, iter);

	// Calls intended function
	// The code below needs trimming, but it is still new and I was checking if it worked, and it did! :D
	if (pLoadLibrary != NULL) {
		printf("[!] LOADING USER32.DLL...\n");
		const char *pHandle = (const char *)pLoadLibrary("user32.dll");
		if (pHandle != NULL) {
			printf("  [!] MODULE LOADED @ %p\n", pHandle);
			pMessageBox = retrieve_function_by_name<MessageBox_t>("MessageBoxA", pHandle, L"user32.dll");
			if (pMessageBox != NULL)
				pMessageBox(NULL, "Hello", "From the other side", 0x00000000L);
		}
	}

    return 0;
}
