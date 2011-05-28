#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace std;

#include "disasm.h"
using namespace disasm;

#define DEBUG			1
#define HEX_BYTES_TO_SHOW	5
#define BYTES_TO_DISASM		256

#if DEBUG == 1
	#define DLLPATH "Debug\\disasm.dll"
#else
	#define DLLPATH "Release\\disasm.dll"
#endif


int main( int argc, char **argv)
{
	char *defApp = "C:\\Windows\\System32\\calc.exe";

	if( argc < 2)
		argv[2] = defApp;

	HMODULE hMod = LoadLibraryA( DLLPATH);
	if( hMod == NULL || GetLastError() )
	{
		printf( "[!] Error while LoadLibraryA: %d", GetLastError() );
		return 0;
	}

	printf( "Deassembling:\t'%s'\n", argv[2] );

	typedef LPDISASM (*fnCreateDisasm)();
	typedef void (*fnDestroyDisasm)(LPDISASM);

	fnCreateDisasm CreateDisasm = 
		(fnCreateDisasm)GetProcAddress( hMod, "CreateDisasm");
	fnDestroyDisasm DestroyDisasm = 
		(fnDestroyDisasm)GetProcAddress(hMod, "DestroyDisasm");

	if( CreateDisasm == NULL || DestroyDisasm == NULL 
			|| GetLastError() )
	{
		printf( "[!] Error while GetProcAddress'es: %d", 
				GetLastError() );
		return 0;
	}

	LPDISASM Disasm = CreateDisasm();
	
	printf( "DISASM interface has been successfully loaded at 0x%08X", 
			(DWORD)Disasm );
	printf( "> Disasm.Load( \"%s\" );\n", argv[2]);
	
	if( !Disasm->Load( argv[2] ) )
	{
		printf( "[!] Disasm->Load returned err #%d.", 
				Disasm->peFile.GetError() );
		return 0;
	}

	DWORD lpBuff = Disasm->peFile.RVA2RAW(Disasm->peFile.GetEP());
	
	int nSize = BYTES_TO_DISASM * sizeof(LPDISM);
	LPDISM lpDisasm = (LPDISM)malloc( nSize );
	memset( (void*)lpDisasm, 0, nSize);

	unsigned uRet = Disasm->DisasmBytes( (void*)lpBuff, 
					lpDisasm, BYTES_TO_DISASM);

	printf( "> Disasm->DisasmBytes( %X, lpDisasm, %d ) returned %d.\n",
			lpBuff, BYTES_TO_DISASM, uRet );

	char szTmp[ 64] = "";
	char szHexs[ HEX_BYTES_TO_SHOW * 3 + 1] = "";
	char szLine[ 512] = "";
//	for( unsigned u = 0; u < uRet; u++)
//	{
//		for( unsigned u1 = 0; u1 < 
//	}

	printf( "> END of program. ");

	DestroyDisasm( Disasm);
	free( lpDisasm);

	return 0;
}
