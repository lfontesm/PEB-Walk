#include "ModuleIterator.hpp"

// Check ModuleIterator.hpp
ModuleIterator::ModuleIterator(const WinDecls::LDR_DATA_TABLE_ENTRY_T* _modptr, const WinDecls::PEB_LDR_DATA_T* _ldr) : modulePtr(_modptr), Ldr(_ldr) {
	base = modulePtr->DllBase;
}

void  ModuleIterator::next() {
	modulePtr =  modulePtr->load_order_next();
	base      =  modulePtr->DllBase;
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

void ModuleIterator::reset() {
	modulePtr = (const WinDecls::LDR_DATA_TABLE_ENTRY_T*)Ldr->InLoadOrderModuleList.Flink;
	base      = modulePtr->DllBase;
}