//#include "lazy_importer.hpp"
#include <string.h>
#include <stdio.h>
#include <intrin.h>

#define NOEXCEPT
#if !defined(NOEXCEPT)
#define NOEXCEPT
#else
#define NOEXCEPT noexcept
#endif

//namespace blau {
    namespace win {

        struct LIST_ENTRY_T {
            const char* Flink;
            const char* Blink;
        };

        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            wchar_t* Buffer;
        };

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

            __forceinline const LDR_DATA_TABLE_ENTRY_T*
                load_order_next() const noexcept
            {
                return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T*>(
                    InLoadOrderLinks.Flink);
            }
        };

        struct IMAGE_DOS_HEADER { // DOS .EXE header
            unsigned short e_magic; // Magic number
            unsigned short e_cblp; // Bytes on last page of file
            unsigned short e_cp; // Pages in file
            unsigned short e_crlc; // Relocations
            unsigned short e_cparhdr; // Size of header in paragraphs
            unsigned short e_minalloc; // Minimum extra paragraphs needed
            unsigned short e_maxalloc; // Maximum extra paragraphs needed
            unsigned short e_ss; // Initial (relative) SS value
            unsigned short e_sp; // Initial SP value
            unsigned short e_csum; // Checksum
            unsigned short e_ip; // Initial IP value
            unsigned short e_cs; // Initial (relative) CS value
            unsigned short e_lfarlc; // File address of relocation table
            unsigned short e_ovno; // Overlay number
            unsigned short e_res[4]; // Reserved words
            unsigned short e_oemid; // OEM identifier (for e_oeminfo)
            unsigned short e_oeminfo; // OEM information; e_oemid specific
            unsigned short e_res2[10]; // Reserved words
            long           e_lfanew; // File address of new exe header
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
            unsigned long  AddressOfFunctions; // RVA from base of image
            unsigned long  AddressOfNames; // RVA from base of image
            unsigned long  AddressOfNameOrdinals; // RVA from base of image
        };

        struct IMAGE_DATA_DIRECTORY {
            unsigned long VirtualAddress;
            unsigned long Size;
        };

        struct IMAGE_OPTIONAL_HEADER64 {
            unsigned short       Magic;
            unsigned char        MajorLinkerVersion;
            unsigned char        MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long long   ImageBase;
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
            unsigned long long   SizeOfStackReserve;
            unsigned long long   SizeOfStackCommit;
            unsigned long long   SizeOfHeapReserve;
            unsigned long long   SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[16];
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
#ifdef _WIN64
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
            IMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
        };

    } // namespace win
//}



int main() {
    const char* func = "LoadLibraryA";
    const win::PEB_T* pebPtr = reinterpret_cast<const win::PEB_T*>(__readfsdword(0x30));
    const win::PEB_LDR_DATA_T* Ldr = pebPtr->Ldr;
    const win::LDR_DATA_TABLE_ENTRY_T* kernel32Module = reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T*>(pebPtr->Ldr->InLoadOrderModuleList.Flink);
    kernel32Module = kernel32Module->load_order_next()->load_order_next();
    

    

    printf("[+] PEB @: %p\n", pebPtr);

    wprintf(L"  [+] Module: %s @ %p\n", kernel32Module->BaseDllName.Buffer, kernel32Module->DllBase);

    /*wprintf(L"\n\nENTER exits...\n");
    getc(stdin);*/
    return 0;
}