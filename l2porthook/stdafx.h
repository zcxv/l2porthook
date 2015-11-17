#ifndef ___STDAFX_H
#define ___STDAFX_H

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define CATCH_PORT 2106
#define NEW_PORT 2107

#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

#include <signal.h>

class HookedFunction {
private:
	LPCWSTR dll;
	LPCSTR func;
	LPVOID addr;
	LPVOID fAddr;

	bool hooked;

	BYTE saved[6]; //original func six bytes for unhook
	BYTE jump[6]; //jump near instruction set

	void setHooked(bool hooked) {
		this->hooked = hooked;
	}

public:
	HookedFunction(LPCWSTR dll, LPCSTR func, LPVOID addr);
	~HookedFunction();

	bool hook();
	bool unhook();

	PBYTE getSaved() {
		return saved;
	}

	bool isHooked() {
		return hooked;
	}
};

void crash(LPCWSTR msg);

extern "C" __declspec(dllexport) void l2porthook_export();

#endif