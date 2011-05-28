// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "disasm.h"

//#pragma comment(lib, "msvcrt.lib")

////////////////////////////////////////////////////////

using namespace disasm;

extern "C"
{
	class	__declspec(dllexport) DISASM;
			__declspec(dllexport) LPDISASM CreateDisasm(){ return new _disasm; }
			__declspec(dllexport) void DestroyDisasm( LPDISASM ptr){ delete ptr; }
}

////////////////////////////////////////////////////////

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

