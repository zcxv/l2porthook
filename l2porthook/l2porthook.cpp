#include "stdafx.h"

bool writeProcMem(LPVOID fAddr, PBYTE raw, SIZE_T size);

HookedFunction::HookedFunction(LPCWSTR dll, LPCSTR func, LPVOID addr) {
	this->dll = dll;
	this->func = func;
	this->addr = addr;
	this->hooked = false;

	this->fAddr = (LPVOID) GetProcAddress(GetModuleHandle(dll), func);
	if(!ReadProcessMemory(GetCurrentProcess(), this->fAddr, this->saved, 6, 0)) {
		::crash(L"failed read process memory");
	}
	DWORD nearAddr = ((DWORD) this->addr) - ((DWORD) this->fAddr) - 5;
	this->jump[0] = 0xe9;
	memcpy(&(this->jump[1]), &nearAddr, 4);
	this->jump[5] = 0xc3;
}

HookedFunction::~HookedFunction() {
	this->unhook();
}

bool HookedFunction::hook() {
	if(this->hooked) {
		return false;
	}
	this->hooked = true;

	return writeProcMem(this->fAddr, this->jump, 6);
}

bool HookedFunction::unhook() {
	if(!this->hooked) {
		return false;
	}
	this->hooked = false;

	return writeProcMem(this->fAddr, this->saved, 6);
}

bool writeProcMem(LPVOID fAddr, PBYTE raw, SIZE_T size) {
	DWORD oldProtect;
	if(!VirtualProtect(fAddr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		return false;
	}
	
	if(!WriteProcessMemory(GetCurrentProcess(), fAddr, raw, size, 0)) {
		return false;
	}

	if(!VirtualProtect(fAddr, size, oldProtect, &oldProtect)) {
		return false;
	}

	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return true;
}