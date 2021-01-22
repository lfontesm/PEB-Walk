// PEB-Walk.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>
#include "..\mydefs.h"

int main(int argc, char **argv){
    void *_pebPtr = NULL;
    PEB *pebPtr;

    // Inline assembly to get the VA of the PEB
    __asm {
        mov eax, fs: [0x30]
        mov _pebPtr, eax
    };

    // Typecast to a PEB type
    pebPtr = (PEB*)_pebPtr;

    // Print the address for reasons
    std::cout << "PEB:         " << pebPtr << std::endl;
    
    // Defining the iterator
    PLIST_ENTRY link;
    // Defining the content of InLoadOrderModuleList
    PLDR_DATA_TABLE_ENTRY ldrMod;

    // Iterate over the list of modules
    for (link = pebPtr->Ldr->InLoadOrderModuleList.Flink->Flink;
        link != pebPtr->Ldr->InLoadOrderModuleList.Flink;
        link = link->Flink) {

        // Typecast to a list entry, e.g, a module
        ldrMod = (PLDR_DATA_TABLE_ENTRY)link;

        // Still deciding on what to do with this
        if (ldrMod->BaseDllName.Buffer && wcscmp(L"KERNEL32.DLL", ldrMod->BaseDllName.Buffer) == 0) {
            std::cout << "AAAAAAAA " << std::endl;
        }

        // Print the module name and it's base address
        wprintf(L"module %-17s base@ %10p\n",
            ldrMod->BaseDllName.Buffer,
            ldrMod->DllBase);
    }

    // For debugging
    /*while (true)
    {

    }*/

    return 0;
}
