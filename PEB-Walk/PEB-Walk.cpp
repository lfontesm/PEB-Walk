// PEB-Walk.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

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

typedef struct _PEB_LDR_DATA {
    PVOID dontCare;
    PVOID dontCare2;
    PVOID dontCare3;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    PVOID dontCare;
    PVOID dontCare2;
    PVOID dontCare3;
    PEB_LDR_DATA* Ldr;
} PEB, * PPEB;

int main(int argc, char **argv){
    void *_pebPtr = NULL;
    PEB *pebPtr;

    __asm {
        mov eax, fs: [0x30]
        mov _pebPtr, eax
    };

    pebPtr = (PEB*)_pebPtr;

    std::cout << "PEB:         " << pebPtr << std::endl;
    
    PLIST_ENTRY link;
    PLDR_DATA_TABLE_ENTRY ldrMod;

    for (link = pebPtr->Ldr->InLoadOrderModuleList.Flink->Flink;
        link != pebPtr->Ldr->InLoadOrderModuleList.Flink;
        link = link->Flink) {

        ldrMod = (PLDR_DATA_TABLE_ENTRY)link;

        if (wcscmp(L"KERNEL32.DLL", ldrMod->BaseDllName.Buffer) == 0) {
            std::cout << "AAAAAAAA " << std::endl;
        }
        //std::cout << ldrMod->FullDllName.Buffer << std::endl;

        //break;

        wprintf(L"module %-17s base@ %10p\n",
            ldrMod->BaseDllName.Buffer,
            ldrMod->DllBase);
    }

    /*while (true)
    {

    }*/

    return 0;
}
