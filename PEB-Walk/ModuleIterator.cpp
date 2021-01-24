#include "ModuleIterator.hpp"

// Check ModuleIterator.hpp
ModuleIterator::ModuleIterator(const WinDecls::LDR_DATA_TABLE_ENTRY_T* _modptr) : modulePtr(_modptr) {
	base = modulePtr->DllBase;
}

const WinDecls::LDR_DATA_TABLE_ENTRY_T*  ModuleIterator::next() {
	return modulePtr->load_order_next();
}

const char* ModuleIterator::get_base() const {
	return base;
}

const WinDecls::LDR_DATA_TABLE_ENTRY_T* ModuleIterator::get_modPtr() const {
	return modulePtr;
}

const wchar_t* ModuleIterator::get_modName() const {
	return modulePtr->BaseDllName.Buffer;
}