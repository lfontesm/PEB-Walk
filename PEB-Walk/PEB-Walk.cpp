#include <string.h>
#include <stdio.h>
#include <intrin.h>

// These are my own definitions of the structures the are to be used in this code.
// Some of those you can find on Microsoft Documentation, such as LIST_ENTRY and UNICODE_STRING.
// Others, you would have to google search in order to get a more complete and uncensored version of them,
// and there's also some there are completely undocumented, but you can still find them with google search.
// I prefered to use my own for better data management and also to avoid importing Windows.h (since I hate Windows)

// Also, specifically the LDR_DATA_TABLE_ENTRY_, the lazy_importer by @JustasMasiulis defined a nice function called load_next().
// And I decided to add it, because Bruce Lee told me to adapt whats useful >:O
namespace WinDecls {
    struct LIST_ENTRY_T {
        const char* Flink;
        const char* Blink;
    };

    struct UNICODE_STRING_T {
        unsigned short Length;
        unsigned short MaximumLength;
        wchar_t*       Buffer;
    };

    struct PEB_LDR_DATA_T {
        unsigned long Length;
        unsigned long Initialized;
        const char*   SsHandle;
        LIST_ENTRY_T  InLoadOrderModuleList;
    };

    struct PEB_T {
        unsigned char   Reserved1[2];
        unsigned char   BeingDebugged;
        unsigned char   Reserved2[1];
        const char*     Reserved3[2];
        PEB_LDR_DATA_T* Ldr;
    };

    struct LDR_DATA_TABLE_ENTRY_T {
        LIST_ENTRY_T InLoadOrderLinks;
        LIST_ENTRY_T InMemoryOrderLinks;
        LIST_ENTRY_T InInitializationOrderLinks;
        const char*  DllBase;
        const char*  EntryPoint;
        union {
            unsigned long SizeOfImage;
            const char* _dummy;
        };
        UNICODE_STRING_T FullDllName;
        UNICODE_STRING_T BaseDllName;

        __forceinline const LDR_DATA_TABLE_ENTRY_T*
            load_order_next() const noexcept
        {
            return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T*>(
                InLoadOrderLinks.Flink);
        }
    };

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
        unsigned long           Signature;
        IMAGE_FILE_HEADER       FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    };

 } 

// I'll keep working on this until i can import functions like a pro. And I plan on adding more modularity
int main() {
    const char* func = "LoadLibraryA";

    // Retrieve pointer to PEB
    const WinDecls::PEB_T* pebPtr = reinterpret_cast<const WinDecls::PEB_T*>(__readfsdword(0x30));
    // Retrieve pointer to LDR_DATA
    const WinDecls::PEB_LDR_DATA_T* Ldr = pebPtr->Ldr;
    // Retrieve pointer to first module of list (PEB-Walk.exe)
    const WinDecls::LDR_DATA_TABLE_ENTRY_T* kernel32Module = reinterpret_cast<const WinDecls::LDR_DATA_TABLE_ENTRY_T*>(Ldr->InLoadOrderModuleList.Flink);
    // Walk the list until kernel32.dll
    kernel32Module = kernel32Module->load_order_next()->load_order_next();
  
    // Retrieve the base address of the module
    const char* base = kernel32Module->DllBase;
// Uncomment to print the address of PEB and the current module being iterated, and vice versa
#define PRINT_PEB
#if defined(PRINT_PEB)
    printf("[+] PEB @: %p\n", pebPtr);
    wprintf(L"  [+] Module: %s @ %p\n", kernel32Module->BaseDllName.Buffer, base);
#endif
    // Retrieve a pointer to the NT_HEADERS
    const WinDecls::IMAGE_NT_HEADERS* ntHeaders = 
        reinterpret_cast<const WinDecls::IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<const WinDecls::IMAGE_DOS_HEADER*>(base)->e_lfanew);

    // Retrieve a pointer to the first entry in DataDirectory[] list (EXPORT_DIRECTORY RVA)
    const auto dataDir = ntHeaders->OptionalHeader.DataDirectory[0];
    
    // Retrieve a pointer to the actual address of the EXPORT_DIRECTORY
    const WinDecls::IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<const WinDecls::IMAGE_EXPORT_DIRECTORY*>(base + dataDir.VirtualAddress);
    // Retrieve the number of entries in the symbol table (both the strings and RVA symbol table)
    unsigned long NumberOfNames = exportDir->NumberOfNames;
   
// Uncomment to print the NumberOfNames variable (Number of strings on symbol table), and vice versa
//#define PRINT_NOFNAMES
#if defined(PRINT_NOFNAMES)
    printf("    [+] Number of names: %d\n", NumberOfNames);
#endif
    // Iterate over the the table
    for (size_t index = NumberOfNames; index > 0; index--) {
        // Retrieve a pointer to an entry in the string table @ index
        // RVAOfStringInFile     = (base + exportDir->AddressOfNames[index])
        // PointerToStringInFile =  base + RVAOfStringInFile
        const char* name = reinterpret_cast<const char*>(base +
            reinterpret_cast<const unsigned long*>(
                base + exportDir->AddressOfNames)[index]);

// Uncomment to print the string table containing the functions names, and vice versa
#define PRINT_STRINGS
#if defined(PRINT_STRINGS)
        printf("      [+] [%d] = %s\n", index, name);
#endif
        // Lazy checking if we found LoadLibraryA
        if ( ( strcmp(func, name) == 0 ) ) {
            // Retrieve the RVA Table
            const auto* const AddrTable = reinterpret_cast<const unsigned long*> (base + exportDir->AddressOfFunctions);
            // Retrieve the Ordinal Table
            const auto* const OrdTable = reinterpret_cast<const unsigned short*>(base + exportDir->AddressOfNameOrdinals);

            // Retrieve the function pointer
            const int (*pLoadLibrary)(const char *) = reinterpret_cast<const int(*)(const char*)>(base + AddrTable[OrdTable[index]]);
            // Call the function with argument "user32.dll"
            pLoadLibrary("user32.dll");
            
            break;
        }

    }

    return 0;
}
