#ifndef MODULE_ITERATOR_
#define MODULE_ITERATOR_

#include "WinDecl.hpp" // File with Windows internal definitions

// Simple Class to iterate over the modules on the PEB to add extra modularity
class ModuleIterator {
private:
	// Pointer do the module structure, e.g, an entry on the InLoadOrderModuleList
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* modulePtr;
	// Base of the module on memory
	const char* base;

public:
	ModuleIterator(const WinDecls::LDR_DATA_TABLE_ENTRY_T* _modptr);
	// Retrieves pointer to next module
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* next();
	// Retrieve base addr
	const char* get_base() const;
	// Retrieve ptr do module
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* get_modPtr() const;
	// Retrieve ptr to module name
	const wchar_t* get_modName() const;
};

#endif // !MODULE_ITERATOR_
