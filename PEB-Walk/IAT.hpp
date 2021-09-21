#pragma once

#ifndef IAT_H_
#define IAT_H_

#include "WinDecl.hpp"

// Function pointer var with it's signature (refer to https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya and so on)
typedef const void* (__stdcall* LoadLibrary_t)(const char*);
typedef int(__stdcall* MessageBox_t)(void*, const char*, const char*, unsigned int);
typedef void* (__stdcall* VirtualAlloc_t)(void*, size_t, unsigned long, unsigned long);
typedef bool(__stdcall* VirtualProtect_t)(void*, size_t, unsigned long, unsigned long*);
typedef bool(__stdcall* CreateProcessA_t)(const char*, char*, WinDecls::SECURITY_ATTRIBUTES*, WinDecls::SECURITY_ATTRIBUTES*, bool, unsigned long, void*, const char*, WinDecls::STARTUPINFOA*, WinDecls::PROCESS_INFORMATION*);
typedef char* (__stdcall* GetProcAddress_t)(void*, const char*);
typedef void* (__stdcall* GetModuleHandleA_t)(const char*);
typedef unsigned long(__stdcall* ZwUnmapViewOfSection_t)(void*, void*);
typedef unsigned long(__stdcall* NtQueryInformationProcess_t)(void*, unsigned int, WinDecls::PROCESS_BASIC_INFORMATION*, unsigned long, unsigned long*);
typedef bool(__stdcall* ReadProcessMemory_t)(void*, const void*, void*, unsigned int, unsigned int*);
typedef void* (__stdcall* CreateFileA_t)(const char*, unsigned long, unsigned long, WinDecls::SECURITY_ATTRIBUTES*, unsigned long, unsigned long, void*);
typedef unsigned long(__stdcall* GetFileSize_t)(void*, unsigned long*);
typedef bool(__stdcall* ReadFile_t)(void*, void*, unsigned long, unsigned long*, void*);
typedef void* (__stdcall* HeapAlloc_t)(void*, unsigned long, unsigned int);
typedef void* (__stdcall* GetProcessHeap_t)(void);
typedef void* (__stdcall* VirtualAllocEx_t)(void*, void*, unsigned int, unsigned long, unsigned long);
typedef bool(__stdcall* WriteProcessMemory_t)(void*, void*, const void*, unsigned int, unsigned int);
//typedef bool(__stdcall* GetThreadContext_t)(void *, )

// Definition of a data structure akin to an Import Address Table
extern LoadLibrary_t pLoadLibrary;
extern MessageBox_t  pMessageBox;
extern VirtualAlloc_t pVirtualAlloc;
extern VirtualProtect_t pVirtualProtect;
extern CreateProcessA_t pCreateProcessA;
extern GetProcAddress_t pGetProcAddress;
extern GetModuleHandleA_t pGetModuleHandle;
extern ZwUnmapViewOfSection_t pZwUnmapViewOfSection;
extern NtQueryInformationProcess_t pNtQueryInformationProcess;
extern ReadProcessMemory_t pReadProcessMemory;
extern CreateFileA_t pCreateFileA;
extern GetFileSize_t pGetFileSize;
extern ReadFile_t pReadFile;


#endif // !IAT_H_


