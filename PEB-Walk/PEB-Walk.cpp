// PEB-Walk.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <winternl.h>
#include <iostream>

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

    for (link = pebPtr->Ldr->InMemoryOrderModuleList.Flink->Flink;
        link != pebPtr->Ldr->InMemoryOrderModuleList.Flink;
        link = link->Flink) {

        ldrMod = (PLDR_DATA_TABLE_ENTRY)link;

        if (wcscmp(L"KERNEL32.DLL", ldrMod->FullDllName.Buffer) == 0) {
            std::cout << "AAAAAAAA " << std::endl;
        }
        //std::cout << ldrMod->FullDllName.Buffer << std::endl;

        //break;

        wprintf(L"module %-17s base@ %10p\n",
            ldrMod->FullDllName.Buffer,
            ldrMod->DllBase);
    }

    /*while (true)
    {

    }*/

    return 0;
}
