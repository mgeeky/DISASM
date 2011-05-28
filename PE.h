#pragma once


///////////////////////////////////////////////////////////////////////////////////////
///////////////////		PREPROCESSOR		///////////////////////////////////////////

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////


// Sizes of structures

#define		IMAGE_SIZEOF_IMPORT_DESCRIPTOR	20
#define		IMAGE_SIZEOF_THUNK_DATA			4
#define		IMAGE_SIZEOF_IMPORT_BY_NAME		3
#define		IMAGE_SIZEOF_DOS_HEADER			64
#define		IMAGE_SIZEOF_DOS_STUB			64
#define		IMAGE_SIZEOF_OPTIONAL_HEADER	224
#define		IMAGE_SIZEOF_SECTION_HEADER		40
#define		IMAGE_SIZEOF_EXPORT_DIRECTORY	40


// Errors

#define		ERROR_FILE_IS_COMPRESSED		0x80001		// File is probably compressed
#define		ERROR_IAT_UNACCESSIBLE			0x80002		// IAT is unaccessible
#define		ERROR_INVALID_MAGIC				0x80003		// DOS_HEADER.eMagic is not "MZ"
#define		ERROR_INVALID_SIGNATURE			0x80004		// NT_HEADERS.Signature is not "PE"
#define		ERROR_HEAP_CORRUPTED			0x80005		// Error while allocating memory at the Heap
#define		ERROR_WRITTEN_LESS_THAN_SHOULD	0x80006		// Written less bytes than should write
#define		ERROR_READ_LESS_THAN_SHOULD		0x80007		// Read less bytes than should read
#define		ERROR_WRITE_LESS_THAN_SHOULD	0x80008		// Write less bytes than should write



///////////////////////////////////////////////////////////////////////////////////////
///////////////////		DECLARATIONS		///////////////////////////////////////////

class IMPORTED_FUNCTION
{
public:
	IMPORTED_FUNCTION(){ memset( (void*)szFunction, 0, sizeof( szFunction)); }

	unsigned	uImpDescriptorIndex;		// Index of section header (index in vector)
	union{
		char	szFunction[ 65];
		DWORD	dwOrdinal;
	};

	DWORD		dwPtrValue;					// Value of pointer to this thunk
	DWORD		dwHint;						// Hint
	DWORD		dwThunkRAW;					// RAW address of this Thunk in file (not of value)
	DWORD		dwThunkRVA;					// RVA address of this Thunk in file (not of value)
};

//.........

class __IMAGE_IMPORT_DESCRIPTOR {
public:
	IMAGE_IMPORT_DESCRIPTOR		d;
	char						szName[ 32];
	vector< IMPORTED_FUNCTION>	vImports;
};


////////////////////////////////		MAIN CLASS		///////////////////////////////////////////////
class PE
{

	DWORD								dwLastError;
	BOOL								bIsIATFilled;

public:
	// Public variables

	char								szFileName[ MAX_PATH + 65];
	BY_HANDLE_FILE_INFORMATION			bhFileInformation;

	DWORD								dwSizeOfFile;
	DWORD								dwSignature;					// Should be "PE"
	DWORD								dwOEP;
	DWORD								dwNumberOfImports;				// Number of imported functions

	IMAGE_DOS_HEADER					imgDosHdr;
	IMAGE_FILE_HEADER					imgFileHdr;
	IMAGE_OPTIONAL_HEADER				imgOptionalHdr;
	IMAGE_SECTION_HEADER				*pSectionHdrs;

	LPVOID								lpDOSStub;						// DOS STUB
	DWORD								dwSizeOfDOSStub;

	vector< char*>						vSectionsNames;
	vector< IMPORTED_FUNCTION>			vImports;
	vector< __IMAGE_IMPORT_DESCRIPTOR>	vImportDescriptors;
	
	LPBYTE								lpMapOfFile;

private:
	HANDLE								hFileHandle;
	HANDLE								hMapOfFile;
	bool								bIsFileMapped;


	//////////////////////////////		MEMBER METHODS		////////////////////////////////////////////


public:	//==========================================

										// Constructor
	PE( )
	{ 
		lpDOSStub		= NULL;
		pSectionHdrs	= NULL;
		bIsFileMapped	= false;
		bIsIATFilled	= false;
		memset( szFileName, 0, sizeof( szFileName));
		dwLastError = dwSizeOfFile = dwSignature = dwOEP = dwNumberOfImports = 0;		
	}

	PE( const char *_szFileName )
	{ 
		lpDOSStub		= NULL;
		pSectionHdrs	= NULL;
		bIsIATFilled	= false;
		bIsFileMapped	= false;
		memset( szFileName, 0, sizeof( szFileName));
		dwLastError = dwSizeOfFile = dwSignature = dwOEP = dwNumberOfImports = 0;
		LoadFile( _szFileName) ;		
	}

										// Destructor
	~PE()
	{
		if( bIsFileMapped ){
			UnmapViewOfFile( lpMapOfFile);
			CloseHandle( hMapOfFile);
		}
		CloseHandle( hFileHandle);
		if( lpDOSStub != NULL)	free( lpDOSStub);
		if( pSectionHdrs != NULL)free( (void*)pSectionHdrs);
	}


	// Address / offset conversions

	DWORD	RVA2RAW	(	DWORD dwRVA );
	DWORD	RAW2RVA	(	DWORD dwRAW );
	DWORD	VA2RVA	(	DWORD dwVA  ){	return dwVA - GetIB();	}
	DWORD	RVA2VA	(	DWORD dwRVA ){	return dwRVA + GetIB();	}


	// Getting info

	DWORD					GetEP	(	)			{ return imgOptionalHdr.AddressOfEntryPoint;	}
	DWORD					GetIB	(	)			{ return imgOptionalHdr.ImageBase;				}
	DWORD					GetSectionsCount( )		{ return imgFileHdr.NumberOfSections;			}
	IMAGE_SECTION_HEADER*	GetSection( unsigned u ){ return &pSectionHdrs[ u];						}
	IMAGE_SECTION_HEADER*	GetLastSection( )		{ return &pSectionHdrs[ GetSectionsCount( )];	}


	// Checking errors

	DWORD	GetError( )								{ return dwLastError;	}
	bool	operator!()								{ return ((this->GetError() != 0)? true : false); }
	void	SetError	( DWORD dwErrCode )			{ SetLastError( dwErrCode); dwLastError = dwErrCode; }


	// Insert bytes to a file (by overwriting existing)

	BOOL	Patch( LPCVOID lpData, DWORD dwSize, LONG lOffset, DWORD dwMethod = FILE_BEGIN );
	BOOL	InsertShellcode( const char *szFileWithShellcode, const char *szSectionName = "extra");

	BOOL	LoadFile( const char *szFileName );
	LPBYTE	MapFile();

	BOOL	FillIAT( );				// Function fills IAT in mapped memory (with GetProcAddr addresses)
	

private:	//==========================================

	BOOL	_OpenFile()
	{
		if( hFileHandle != (HANDLE)0xCCCCCCCC && hFileHandle != (HANDLE)-1 ) return TRUE;

		/* Open the file */
		hFileHandle = CreateFileA(	szFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 
									NULL, OPEN_EXISTING, 0, NULL );
		if( hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError() ){
			SetError( GetLastError() );
			return FALSE;
		}
		return TRUE;
	}

	// I/O
	BOOL	ReadBytes ( LPVOID, DWORD dwSize, DWORD dwOffset = 0, DWORD dwMethod = FILE_CURRENT);
	BOOL	WriteBytes ( LPVOID, DWORD dwSize, DWORD dwOffset = 0, DWORD dwMethod = FILE_CURRENT);

	BOOL	ParseIAT( );			// Function parses IAT

	// Shellcode injecting functions

	IMAGE_SECTION_HEADER
			CreateSection(	DWORD dwSizeOfSection, DWORD dwDesiredAccess, 
							const char *szNameOfSection);
	BOOL	BuildImage(		IMAGE_SECTION_HEADER *pNewSectHdr, DWORD dwSizeOfShellcode );
	void	AppendShellcode( const char *szFileWithShellcode, DWORD dwSizeOfShellcode, 
							IMAGE_SECTION_HEADER *imgNewSection );


};

///////////////////////////////////////////////////////////////////////////////////////

