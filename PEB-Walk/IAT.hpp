#pragma once

#ifndef IAT_H_
#define IAT_H_

#include "WinDecl.hpp"

// Function pointer var with it's signature (refer to https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya and so on)
typedef const void* (*LoadLibrary_t)(const char*);
typedef int (*MessageBox_t)(void*, const char*, const char*, unsigned int);
typedef void* (*VirtualAlloc_t)(void*, size_t, unsigned long, unsigned long);
typedef bool (*VirtualProtect_t)(void*, size_t, unsigned long, unsigned long*);
typedef bool (*CreateProcessA_t)(const char*, char*, WinDecls::SECURITY_ATTRIBUTES*, WinDecls::SECURITY_ATTRIBUTES*, bool, unsigned long, void*, const char*, WinDecls::STARTUPINFOA*, WinDecls::PROCESS_INFORMATION*);

// Definition of a data structure akin to an Import Address Table
typedef struct {
	LoadLibrary_t pLoadLibrary;
	MessageBox_t  pMessageBox;
	VirtualAlloc_t pVirtualAlloc;
	VirtualProtect_t pVirtualProtect;
	CreateProcessA_t pCreateProcessA;
} IAT_t;

#endif // !IAT_H_


