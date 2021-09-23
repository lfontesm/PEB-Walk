#pragma once

#ifndef WIN_DECL_
#define WIN_DECL_

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
        wchar_t* Buffer;
    };

    struct PEB_LDR_DATA_T {
        unsigned long Length;
        unsigned long Initialized;
        const char* SsHandle;
        LIST_ENTRY_T  InLoadOrderModuleList;
    };

    struct PEB_T {
        bool 	InheritedAddressSpace;
        bool 	ReadImageFileExecOptions;
        bool 	BeingDebugged;
        bool 	SpareBool;
        unsigned long 	Mutant;
        unsigned long 	ImageBaseAddress;
        PEB_LDR_DATA_T* Ldr;
        unsigned long 	ProcessParameters;
        unsigned long 	SubSystemData;
        unsigned long 	ProcessHeap;
        unsigned long 	FastPebLock;
        unsigned long 	FastPebLockRoutine;
        unsigned long 	FastPebUnlockRoutine;
        unsigned long 	EnvironmentUpdateCount;
        unsigned long 	KernelCallbackTable;
        unsigned long 	Reserved[2];
    };
    

    /*struct PEB_T {
        unsigned char   Reserved1[2];
        unsigned char   BeingDebugged;
        unsigned char   Reserved2[1];
        const char* Reserved3[2];
        PEB_LDR_DATA_T* Ldr;
    };*/

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

    struct IMAGE_SECTION_HEADER {
        char Name[8];
        union {
            unsigned long PhysicalAddress;
            unsigned long VirtualSize;
        } Misc;
        unsigned long VirtualAddress;
        unsigned long SizeOfRawData;
        unsigned long PointerToRawData;
        unsigned long PointerToRelocations;
        unsigned long PointerToLinenumbers;
        unsigned short NumberOfRelocations;
        unsigned short NumberOfLinenumbers;
        unsigned long Characteristics;
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

    struct SECURITY_ATTRIBUTES {
        unsigned long nLength;
        void* lpSecurityDescriptor;
        bool bInheritHandle;
    };

    struct STARTUPINFOA {
        unsigned long cb;
        char *lpReserved;
        char *lpDesktop;
        char *lpTitle;
        unsigned long dwX;
        unsigned long dwY;
        unsigned long dwXSize;
        unsigned long dwYSize;
        unsigned long dwXCountChars;
        unsigned long dwYCountChars;
        unsigned long dwFillAttribute;
        unsigned long dwFlags;
        unsigned short wShowWindow;
        unsigned short cbReserved2;
        unsigned char *lpReserved2;
        void *hStdInput;
        void *hStdOutput;
        void *hStdError;
    };

    struct PROCESS_INFORMATION {
        void *hProcess;
        void *hThread;
        unsigned long dwProcessId;
        unsigned long dwThreadId;
    };

    struct PROCESS_BASIC_INFORMATION {
        void* Reserved1;
        PEB_T* Peb;
        void* Reserved2[2];
        unsigned long* UniquePID;
        void* Resrved3;
    };

    //unsigned int SIZE_OF_80387_REGISTERS = 80;
    struct FLOATING_SAVE_AREA {
        unsigned long   ControlWord;
        unsigned long   StatusWord;
        unsigned long   TagWord;
        unsigned long   ErrorOffset;
        unsigned long   ErrorSelector;
        unsigned long   DataOffset;
        unsigned long   DataSelector;
        char    RegisterArea[80];
        unsigned long   Spare0;
    };

    //unsigned int MAXIMUM_SUPPORTED_EXTENSION = 512;

    struct CONTEXT {
        //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

        unsigned long ContextFlags;

        //
        // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
        // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
        // included in CONTEXT_FULL.
        //

        unsigned long   Dr0;
        unsigned long   Dr1;
        unsigned long   Dr2;
        unsigned long   Dr3;
        unsigned long   Dr6;
        unsigned long   Dr7;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
        //

        FLOATING_SAVE_AREA FloatSave;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_SEGMENTS.
        //

        unsigned long   SegGs;
        unsigned long   SegFs;
        unsigned long   SegEs;
        unsigned long   SegDs;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_INTEGER.
        //

        unsigned long   Edi;
        unsigned long   Esi;
        unsigned long   Ebx;
        unsigned long   Edx;
        unsigned long   Ecx;
        unsigned long   Eax;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_CONTROL.
        //

        unsigned long   Ebp;
        unsigned long   Eip;
        unsigned long   SegCs;              // MUST BE SANITIZED
        unsigned long   EFlags;             // MUST BE SANITIZED
        unsigned long   Esp;
        unsigned long   SegSs;

        //
        // This section is specified/returned if the ContextFlags word
        // contains the flag CONTEXT_EXTENDED_REGISTERS.
        // The format and contexts are processor specific
        //

        char    ExtendedRegisters[512];
    };

    /*unsigned long CREATE_SUSPENDED = 0x00000004;
    unsigned long DETACHED_PROCESS = 0x00000008;
    unsigned long STARF_USESHOWWINDOW = 0x00000001;
    unsigned long SW_SHOW = 5;*/
}

#endif // !WIN_DECL_