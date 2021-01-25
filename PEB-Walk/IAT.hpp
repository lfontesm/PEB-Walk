#pragma once

#ifndef IAT_H_
#define IAT_H_

// Function pointer var with it's signature (refer to https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya and so on)
// I'm thinking about storing these in a different file
typedef const void* (*LoadLibrary_t)(const char*);
typedef int (*MessageBox_t)(void*, const char*, const char*, unsigned int);
typedef void* (*VirtualAlloc_t)(void*, size_t, unsigned long, unsigned long);
typedef bool (*VirtualProtect_t)(void*, size_t, unsigned long, unsigned long*);

// Definition of a data structure akin to an Import Address Table
typedef struct {
	LoadLibrary_t pLoadLibrary;
	MessageBox_t  pMessageBox;
	VirtualAlloc_t pVirtualAlloc;
	VirtualProtect_t pVirtualProtect;
} IAT_t;

#endif // !IAT_H_


