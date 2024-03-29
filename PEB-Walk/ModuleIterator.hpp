#include "WinDecl.hpp" // File with Windows internal definitions
#ifndef MODULE_ITERATOR_
#define MODULE_ITERATOR_


// Simple Class to iterate over the modules on the PEB to add extra modularity
class ModuleIterator {
private:
	// Pointer do the module structure, e.g, an entry on the InLoadOrderModuleList
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* modulePtr;
	// Pointer to LDR_DATA. Needed to reset the iterator
	const WinDecls::PEB_LDR_DATA_T* Ldr;
	// Base of the module on memory
	const char* base;

public:
	ModuleIterator(const WinDecls::LDR_DATA_TABLE_ENTRY_T* _modptr, const WinDecls::PEB_LDR_DATA_T* _ldr);
	// Retrieves pointer to next module
	void next();
	// Retrieve base addr
	const char* get_base() const;
	// Retrieve ptr do module
	const WinDecls::LDR_DATA_TABLE_ENTRY_T* get_modPtr() const;
	// Retrieve ptr to module name
	const wchar_t* get_modName() const;
	// Reset the iterator
	void reset();	
};

#endif // !MODULE_ITERATOR_
