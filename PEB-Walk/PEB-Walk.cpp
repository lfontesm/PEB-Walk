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

    struct PEB_LDR_DATA_T {
        unsigned long Length;
        unsigned long Initialized;
        const char* SsHandle;
        LIST_ENTRY_T  InLoadOrderModuleList;
    };

    struct PEB_T {
        unsigned char   Reserved1[2];
        unsigned char   BeingDebugged;
        unsigned char   Reserved2[1];
        const char* Reserved3[2];
        PEB_LDR_DATA_T* Ldr;
    };

    struct LDR_DATA_TABLE_ENTRY_T {
        LIST_ENTRY_T InLoadOrderLinks;
        LIST_ENTRY_T InMemoryOrderLinks;
        LIST_ENTRY_T InInitializationOrderLinks;
        const char* DllBase;
        const char* EntryPoint;
        union {
            unsigned long SizeOfImage;
            const char* _dummy;
        };
        UNICODE_STRING_T FullDllName;
        UNICODE_STRING_T BaseDllName;

		// Retrieve first entry on DATA_DIRECTORY list
		const WinDecls::IMAGE_DATA_DIRECTORY dataDir = (const WinDecls::IMAGE_DATA_DIRECTORY)(ntHeaders->OptionalHeader.DataDirectory[0]);
		// Retrieve the RVA from this entry (the first entry on DataDirectory is the EXPORT_DIRECTORY)
		const unsigned long exportDirRVA = dataDir.VirtualAddress;

    struct IMAGE_DOS_HEADER { 
        unsigned short e_magic;
        unsigned short e_cblp;
        unsigned short e_cp; 
        unsigned short e_crlc;
        unsigned short e_cparhdr; 
        unsigned short e_minalloc; 
        unsigned short e_maxalloc;
        unsigned short e_ss; 
        unsigned short e_sp; 
        unsigned short e_csum;
        unsigned short e_ip; 
        unsigned short e_cs;
        unsigned short e_lfarlc;
        unsigned short e_ovno; 
        unsigned short e_res[4];
        unsigned short e_oemid; 
        unsigned short e_oeminfo;
        unsigned short e_res2[10];
        long           e_lfanew;
    };

    struct IMAGE_FILE_HEADER {
        unsigned short Machine;
        unsigned short NumberOfSections;
        unsigned long  TimeDateStamp;
        unsigned long  PointerToSymbolTable;
        unsigned long  NumberOfSymbols;
        unsigned short SizeOfOptionalHeader;
        unsigned short Characteristics;
    };

    struct IMAGE_EXPORT_DIRECTORY {
        unsigned long  Characteristics;
        unsigned long  TimeDateStamp;
        unsigned short MajorVersion;
        unsigned short MinorVersion;
        unsigned long  Name;
        unsigned long  Base;
        unsigned long  NumberOfFunctions;
        unsigned long  NumberOfNames;
        unsigned long  AddressOfFunctions;
        unsigned long  AddressOfNames;
        unsigned long  AddressOfNameOrdinals; 
    };

    struct IMAGE_DATA_DIRECTORY {
        unsigned long VirtualAddress;
        unsigned long Size;
    };

    struct IMAGE_OPTIONAL_HEADER32 {
        unsigned short       Magic;
        unsigned char        MajorLinkerVersion;
        unsigned char        MinorLinkerVersion;
        unsigned long        SizeOfCode;
        unsigned long        SizeOfInitializedData;
        unsigned long        SizeOfUninitializedData;
        unsigned long        AddressOfEntryPoint;
        unsigned long        BaseOfCode;
        unsigned long        BaseOfData;
        unsigned long        ImageBase;
        unsigned long        SectionAlignment;
        unsigned long        FileAlignment;
        unsigned short       MajorOperatingSystemVersion;
        unsigned short       MinorOperatingSystemVersion;
        unsigned short       MajorImageVersion;
        unsigned short       MinorImageVersion;
        unsigned short       MajorSubsystemVersion;
        unsigned short       MinorSubsystemVersion;
        unsigned long        Win32VersionValue;
        unsigned long        SizeOfImage;
        unsigned long        SizeOfHeaders;
        unsigned long        CheckSum;
        unsigned short       Subsystem;
        unsigned short       DllCharacteristics;
        unsigned long        SizeOfStackReserve;
        unsigned long        SizeOfStackCommit;
        unsigned long        SizeOfHeapReserve;
        unsigned long        SizeOfHeapCommit;
        unsigned long        LoaderFlags;
        unsigned long        NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    };

    struct IMAGE_NT_HEADERS {
        unsigned long     Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    };

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