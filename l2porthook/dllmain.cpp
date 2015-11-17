#include "stdafx.h"

int __stdcall nConnect(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
);

HookedFunction* hFunc;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hFunc = new HookedFunction(L"ws2_32.dll", "connect", &nConnect);
		if(!hFunc->hook()) {
			crash(L"failed hook connect func");
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		hFunc->unhook();
		delete hFunc;
		break;
	}
	return TRUE;
}

int __stdcall nConnect(_In_ SOCKET sock, _In_ const struct sockaddr *name, _In_ int namelen) {
	if(!hFunc->unhook()) {
		crash(L"failed unhook");
	}

	struct sockaddr_in* addr = (struct sockaddr_in*) name;
	
	if(::ntohs(addr->sin_port) == CATCH_PORT) {
		addr->sin_port = ::htons(NEW_PORT);
	}

	int ret = ::connect(sock, name, namelen);

	if(!hFunc->hook()) {
		crash(L"failed hook");
	}

	return ret;
}

void crash(LPCWSTR msg) {
	::MessageBox(NULL, msg, NULL, MB_OK | MB_ICONERROR);
	::raise(SIGSEGV);
}

__declspec(dllexport) void l2porthook_export() {
}