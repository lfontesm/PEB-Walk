#pragma once
#ifndef _MY_DEFS
#define _MY_DEFS

// Definition of UNICODE_STRING per Miscrosoft Documentation
// Alternatively, you can import it's containing library
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// My definition of LDR_DATA_TABLE_ENTRY, but only the important fields
// Alternatively, you can import it's containing library
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitialiationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// My definition of PEB_LDR_DATA, but only the important fields
// Alternatively, you can import it's containing library
typedef struct _PEB_LDR_DATA {
    PVOID dontCare;
    PVOID dontCare2;
    PVOID dontCare3;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// My definition of PEB, but only the important fields
// Alternatively, you can import it's containing library
typedef struct _PEB {
    PVOID dontCare;
    PVOID dontCare2;
    PVOID dontCare3;
    PEB_LDR_DATA* Ldr;
} PEB, * PPEB;

#endif // !_MY_DEFS
