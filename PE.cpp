#include "stdafx.h"
#include "PE.h"

#pragma warning( disable: 4309)
#pragma warning( disable: 4996)

#define		SET_ERROR	SetError( GetLastError() )


///////////////////////////////////////////////////////////////////////////////////////
BOOL PE::LoadFile( const char *_szFileName)
{
	bIsFileMapped = false;
	strcpy_s( szFileName, sizeof(szFileName), _szFileName);
	
	if( !_OpenFile()) return FALSE;

	GetFileInformationByHandle( hFileHandle, &bhFileInformation);
	dwSizeOfFile = bhFileInformation.nFileSizeLow + bhFileInformation.nFileSizeHigh;

	if( !ReadBytes( (LPVOID)&imgDosHdr, sizeof(IMAGE_DOS_HEADER) ) )
		return FALSE;

	if( IMAGE_DOS_SIGNATURE != imgDosHdr.e_magic || GetLastError() ){
		SetError( ERROR_INVALID_MAGIC );
		return FALSE;
	}

	// Retrieving DOS STUB
	DWORD dwActualPos = SetFilePointer( hFileHandle, 0, NULL, FILE_CURRENT );
	dwSizeOfDOSStub = imgDosHdr.e_lfanew - dwActualPos;

	lpDOSStub = malloc( dwSizeOfDOSStub );
	if( lpDOSStub == NULL){
		SetError( ERROR_HEAP_CORRUPTED);
		return FALSE;
	}

	if( !ReadBytes(lpDOSStub, dwSizeOfDOSStub ) )
		return FALSE;

	if( !ReadBytes(	(LPVOID)&dwSignature, sizeof( dwSignature), 
					imgDosHdr.e_lfanew, FILE_BEGIN) )
			return FALSE;

	SetFilePointer( hFileHandle, imgDosHdr.e_lfanew + sizeof( dwSignature), NULL, FILE_BEGIN);

	if( !ReadBytes( (LPVOID)&imgFileHdr, IMAGE_SIZEOF_FILE_HEADER )) return FALSE;
	if( !ReadBytes( (LPVOID)&imgOptionalHdr, sizeof(IMAGE_OPTIONAL_HEADER32))) return FALSE;

	DWORD dwSectionCount = imgFileHdr.NumberOfSections;
	pSectionHdrs = (IMAGE_SECTION_HEADER*) malloc( IMAGE_SIZEOF_SECTION_HEADER * dwSectionCount + 1);
	if( pSectionHdrs == NULL){
		SetError( ERROR_HEAP_CORRUPTED);
		return FALSE;
	}

	memset( (void*)pSectionHdrs, 0, IMAGE_SIZEOF_SECTION_HEADER * dwSectionCount + 1);

	DWORD dwRead;
	for(unsigned i = 0; i < dwSectionCount; i++)
		ReadFile( hFileHandle, (LPVOID)&pSectionHdrs[ i], IMAGE_SIZEOF_SECTION_HEADER, &dwRead, NULL );

	dwOEP = GetEP();
	ParseIAT();

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////

DWORD PE::RVA2RAW ( DWORD dwRVA )
{
	DWORD dwSections = GetSectionsCount();
	DWORD dwRAW = 0;

	if( dwRVA > this->GetIB() )
		dwRVA -=  this->GetIB();

	for( unsigned i = 0; i < dwSections; i++)
	{
		if( dwRVA >= pSectionHdrs[i].VirtualAddress && 
			dwRVA < (	pSectionHdrs[i].VirtualAddress
					+	pSectionHdrs[i].Misc.VirtualSize) ){
			dwRAW = dwRVA - pSectionHdrs[i].VirtualAddress 
							+ pSectionHdrs[i].PointerToRawData;
			break;
		}
	}
	return dwRAW;
}



///////////////////////////////////////////////////////////////////////////////////////

DWORD PE::RAW2RVA ( DWORD dwRAW )
{
	DWORD dwRVA = -1;
	int i = 0;

	if( dwRAW > this->GetIB() )
		dwRAW -=  this->GetIB();

	while( i < imgFileHdr.NumberOfSections )
	{
		if(pSectionHdrs[ i].PointerToRawData <= dwRAW && 
			(pSectionHdrs[ i].PointerToRawData
			+ pSectionHdrs[ i].SizeOfRawData) > dwRAW )
		{
			dwRVA = dwRAW + pSectionHdrs[ i].VirtualAddress 
					- pSectionHdrs[ i].PointerToRawData;
		}
		i++;
	}
	return dwRVA;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function rebuilds IAT by computing and rewriting each routine address

BOOL PE::ParseIAT( )
{
	// Computing virtual address of Import Address Table
	IMAGE_NT_HEADERS		*imgNTHdr = (IMAGE_NT_HEADERS*)malloc( sizeof(IMAGE_NT_HEADERS));
	IMAGE_DATA_DIRECTORY	*pIddIAT = (IMAGE_DATA_DIRECTORY*)
											&(imgOptionalHdr.DataDirectory[1]);

	memset( (void*)imgNTHdr, 0, sizeof( IMAGE_NT_HEADERS));
	imgNTHdr->Signature		=	dwSignature;
	imgNTHdr->FileHeader	=	imgFileHdr;
	imgNTHdr->OptionalHeader=	imgOptionalHdr;

	if( pIddIAT->VirtualAddress == 0 ) {
		SetError( ERROR_IAT_UNACCESSIBLE);
		free( (void*)imgNTHdr);
		return FALSE;
	}

	//HANDLE	hFile;
	DWORD	dwIAT = RVA2RAW( pIddIAT->VirtualAddress);
	
	MapFile();
	LPVOID lpBuffer = lpMapOfFile;

	char szSectionName[ 64] = "";

	for(unsigned i = 0; i < imgFileHdr.NumberOfSections; i++)
	{
		strcpy_s( (char*)szSectionName, sizeof(szSectionName)-1, (const char*)pSectionHdrs[i].Name);
		vSectionsNames.push_back( szSectionName);

		//for( int m = 8; m > 0; m--)
		//	if( !isalnum( vSectionsNames[ i][ m]) ) 
		//		vSectionsNames[ i][ m] = '\0';
	}


	IMAGE_IMPORT_DESCRIPTOR	*iidTmp = (IMAGE_IMPORT_DESCRIPTOR*)( DWORD(lpBuffer) + dwIAT);
	IMAGE_THUNK_DATA		*itdTmp, *itdTmp2;
	IMAGE_IMPORT_BY_NAME	*iibnTmp;
	unsigned				u = 0, b = 0, c = 0, f = 0;

	// This loop iterates on import descriptors
	while( true )
	{
		if( iidTmp->FirstThunk == 0 && iidTmp->OriginalFirstThunk == 0 && iidTmp->Name == 0 )
			break;

		__IMAGE_IMPORT_DESCRIPTOR *iid = (__IMAGE_IMPORT_DESCRIPTOR*)malloc( 
										sizeof(__IMAGE_IMPORT_DESCRIPTOR)+1);

		memset( (void*)iid, 0, sizeof( __IMAGE_IMPORT_DESCRIPTOR)+1);
		memcpy( (void*)iid, (const void*)iidTmp, sizeof( IMAGE_IMPORT_DESCRIPTOR));

		strcpy_s( iid->szName, sizeof( iid->szName), 
					(const char*)(DWORD(lpBuffer) + RVA2RAW(iidTmp->Name)) );

		vImportDescriptors.push_back( *iid );

		b = 0;

		// time to iterate on its imports
		while( true )
		{
			IMPORTED_FUNCTION	impFunc;
			memset( &impFunc, 0, sizeof( impFunc));

			impFunc.uImpDescriptorIndex = u;

			itdTmp	= (IMAGE_THUNK_DATA*)(DWORD(lpBuffer) + RVA2RAW(iidTmp->OriginalFirstThunk)
						+ b*sizeof( IMAGE_THUNK_DATA) );
			itdTmp2	= (IMAGE_THUNK_DATA*)(DWORD(lpBuffer) + RVA2RAW(iidTmp->FirstThunk)
						+ b*sizeof( IMAGE_THUNK_DATA));
			
			if( iidTmp->OriginalFirstThunk == 0) itdTmp = itdTmp2;
			if( itdTmp->u1.Function == 0 && itdTmp->u1.Ordinal == 0) break;
			if( itdTmp->u1.Function > (DWORD(lpBuffer) + this->dwSizeOfFile)) break;

			iibnTmp = (IMAGE_IMPORT_BY_NAME*)(DWORD(lpBuffer) + RVA2RAW(itdTmp->u1.Function));
			if( iibnTmp->Name == 0 && !(itdTmp->u1.Ordinal & IMAGE_ORDINAL_FLAG) ) break;
			if(!( *(const char*)iibnTmp->Name >= 0x30 && *(const char*)iibnTmp->Name <= 0x7A) )
				break;

			// Rewriting (but firstly getting) address of procedure
			if( (itdTmp->u1.Ordinal & IMAGE_ORDINAL_FLAG) )
				impFunc.dwOrdinal = DWORD(itdTmp->u1.Ordinal & IMAGE_ORDINAL_FLAG);
			else {
				strcpy_s(impFunc.szFunction, sizeof(impFunc.szFunction)-1, 
						(const char*)iibnTmp->Name);
			}
			
			impFunc.dwHint			= iibnTmp->Hint;
			impFunc.dwPtrValue		= itdTmp2->u1.Function;
			impFunc.dwThunkRAW		= (DWORD( itdTmp2) - DWORD(lpMapOfFile) ) + GetIB();
			impFunc.dwThunkRVA		= (RAW2RVA(DWORD( itdTmp2) - DWORD(lpMapOfFile)) + GetIB());

			vImports.push_back( impFunc);
			vImportDescriptors[ u].vImports.push_back( impFunc);

			b++;
			c++;
		}

		// Aiming next import descriptor structure
		u++;
		iidTmp = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD(lpBuffer) 
				+ dwIAT + (u * sizeof(IMAGE_IMPORT_DESCRIPTOR)));

		free( (void*)iid);
	}

	free( (void*)imgNTHdr);
	dwNumberOfImports = c;

	if( u == 0 || c < 2){
		SetError( ERROR_IAT_UNACCESSIBLE);
		return FALSE;
	}

	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// Function fills whole IAT in memory

BOOL PE::FillIAT( )
{

	HMODULE	hModule;
	void	*ptrFunc = NULL;
	DWORD	dwAddr = 0;
	int		i = 0;

	for( unsigned u = 0; u < vImportDescriptors.size(); u++)
	{
		char *pChar = vImportDescriptors[ u].szName;
		hModule = LoadLibraryA( pChar);
	
		for( unsigned n = 0; n < vImportDescriptors[ u].vImports.size(); n++)
		{
			dwAddr = (DWORD)GetProcAddress(hModule, vImportDescriptors[ u].vImports[ n].szFunction);
			vImportDescriptors[ u].vImports[ n].dwPtrValue = dwAddr;
			vImports[ i++].dwPtrValue = dwAddr;

			char szAddr[ 4] = {						// Big Endian to Little Endian conversion
				char(dwAddr & 0xFF),
				char((dwAddr & 0xFF00) / 0x100),
				char((dwAddr & 0xFF0000) / 0x10000),
				char((dwAddr & 0xFF000000) / 0x1000000)
			};

//			WriteBytes( (LPVOID)szAddr, 4, vImportDescriptors[ u].d.FirstThunk + n * sizeof( DWORD), 0);
			DWORD *dwAddr = (DWORD*)((DWORD(lpMapOfFile)+vImportDescriptors[ u].d.FirstThunk 
							+ n * sizeof( DWORD) ));
			*((BYTE*) dwAddr ) = (BYTE)szAddr[0];
			*((BYTE*) DWORD(dwAddr)+1 ) = (BYTE)szAddr[1];
			*((BYTE*) DWORD(dwAddr)+2 ) = (BYTE)szAddr[2];
			*((BYTE*) DWORD(dwAddr)+3 ) = (BYTE)szAddr[3];
		}

		FreeLibrary( hModule);
	}

	bIsIATFilled	= true;
	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function inserts data to file (by overwriting existing data)

BOOL PE::Patch( LPCVOID lpData, DWORD dwSize, 
				  LONG lOffset, DWORD dwMethod )
{
	HANDLE hFile;

	hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, 
						NULL, OPEN_EXISTING, 0, NULL );
	if( hFile == INVALID_HANDLE_VALUE || ::GetLastError() ){
		SET_ERROR;
		return FALSE;
	}

	DWORD nOffset = 0;
    if ((nOffset = 
		SetFilePointer(	hFile, lOffset, NULL, dwMethod)) == 0xFFFFFFFF || ::GetLastError() ){
		SET_ERROR;
        return FALSE;
	}

	DWORD dwWritten;
	WriteFile( hFile, lpData, dwSize, &dwWritten, NULL);
	if( dwWritten != dwSize){
		SetError( ERROR_WRITTEN_LESS_THAN_SHOULD);
		return FALSE;
	}

	CloseHandle( hFile);
	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// Function appends new section to the file.

IMAGE_SECTION_HEADER 
PE::CreateSection(	DWORD dwSizeOfSection, DWORD dwDesiredAccess, const char *szNameOfSection)
{
	IMAGE_SECTION_HEADER	ish;
	DWORD					dwFileAlignment = 0,
							dwNewVirtualAddress = 0, 
							dwSectionAlignment = 0;
	
	memset( (void*)&ish, 0, sizeof( ish));
	
	dwFileAlignment			= 	imgOptionalHdr.FileAlignment;
	dwSectionAlignment		=	imgOptionalHdr.SectionAlignment;
	//dwNewVirtualAddress 	=	(GetLastSection()->SizeOfRawData / dwSectionAlignment + 1)
	//							* dwSectionAlignment + g_iLastSectHdr->VirtualAddress;
	dwNewVirtualAddress     =   (GetLastSection()->SizeOfRawData / dwSectionAlignment + 1)
								* dwSectionAlignment + GetLastSection()->VirtualAddress;
	
	memcpy( ish.Name, 			szNameOfSection, IMAGE_SIZEOF_SHORT_NAME);
	ish.Misc.VirtualSize	=	dwSizeOfSection;
	ish.VirtualAddress		=	dwNewVirtualAddress;
	ish.SizeOfRawData		=	( dwSizeOfSection / dwFileAlignment + 1) * dwFileAlignment;
	ish.PointerToRawData	=	GetLastSection()->PointerToRawData + GetLastSection()->SizeOfRawData;
	ish.Characteristics		=	dwDesiredAccess;
	
	imgFileHdr.NumberOfSections ++;

	imgOptionalHdr.AddressOfEntryPoint = dwNewVirtualAddress;

	return ish;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function builds an image (writes data into exe file)

BOOL PE::BuildImage( IMAGE_SECTION_HEADER *pNewSectHdr, DWORD dwSizeOfShellcode )
{
	DWORD	dwAddrOfFileHdr = 0;
	HANDLE	hFile;
	DWORD	dwRead;

	hFile = CreateFileA(szFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 
						NULL, OPEN_EXISTING, 0, NULL );
	if( hFile == INVALID_HANDLE_VALUE || ::GetLastError() ){
		SET_ERROR;
		return FALSE;
	}
	
	DWORD dwNewSizeOfFile = dwSizeOfFile +  sizeof( IMAGE_SECTION_HEADER) + dwSizeOfShellcode + 32;
	
	LPVOID lpData	= (char*)malloc( dwNewSizeOfFile + 8 );
	memset( lpData, 0, dwNewSizeOfFile+8);
	
	ReadFile( hFile, lpData, dwSizeOfFile, &dwRead, NULL);
	if( hFile == INVALID_HANDLE_VALUE || ::GetLastError()  ){
		SetError( ERROR_INVALID_SIGNATURE );
		return FALSE;
	}
	
	DWORD dwTmp1 = imgDosHdr.e_lfanew + 4 + sizeof( IMAGE_FILE_HEADER) 
				+ sizeof( IMAGE_OPTIONAL_HEADER ) 
				+	( (imgFileHdr.NumberOfSections-1) * sizeof( IMAGE_SECTION_HEADER) ) ;
	DWORD dwTmp2 = dwNewSizeOfFile - (dwTmp1 + sizeof( IMAGE_SECTION_HEADER) );

	WriteFile( hFile, (LPCVOID)&imgDosHdr, sizeof( imgDosHdr), NULL, NULL);
	WriteFile( hFile, (LPCVOID)lpDOSStub, dwSizeOfDOSStub, NULL, NULL);
	WriteFile( hFile, (LPCVOID)&dwSignature, sizeof( dwSignature), NULL, NULL);
	WriteFile( hFile, (LPCVOID)&imgFileHdr, sizeof( imgFileHdr), NULL, NULL);
	WriteFile( hFile, (LPCVOID)&imgOptionalHdr, sizeof(imgOptionalHdr), NULL, NULL);
	
	for( unsigned i = 0; i < GetSectionsCount()-1; i++)
		WriteFile( hFile, (LPCVOID)&pSectionHdrs[ i], IMAGE_SIZEOF_SECTION_HEADER, NULL, NULL);

	DWORD dwOffset = SetFilePointer( hFile, 0, NULL, FILE_CURRENT);

	WriteFile( hFile, pNewSectHdr, IMAGE_SIZEOF_SECTION_HEADER, NULL, NULL);
	WriteFile( hFile, (LPCVOID)(DWORD(lpData)+dwOffset), dwSizeOfFile - dwOffset, NULL, NULL);

	CloseHandle( hFile);
	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function prepares additional shellcode and loads specified shellcode from the file.

void PE::AppendShellcode( const char *szFileWithShellcode, DWORD dwSizeOfShellcode, 
					  IMAGE_SECTION_HEADER *imgNewSection )
{			
	DWORD dwRelocatedEP = dwOEP + GetIB();
	
	char dwJmpOEP[4] = {
        char(dwRelocatedEP & 0xFF),
        char((dwRelocatedEP & 0xFF00) / 0x100),
        char((dwRelocatedEP & 0xFF0000) / 0x10000),
        char((dwRelocatedEP & 0xFF000000) / 0x1000000)
	};

	char szAdditionalShellcode [32] = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
		0x90, 0xB8, dwJmpOEP[0], dwJmpOEP[1], dwJmpOEP[2], dwJmpOEP[3], 0xFF, 0xE0
	}; /* 32 bytes */
	
	/* Upper shellcode does:
	 *
	 *      B8(dwRelocatedEP)	mov eax, dwRelocatedEP
	 *      FFE0				jmp eax
	**/
	
	FILE 	*pFile 	= fopen( szFileWithShellcode, "rb");

	DWORD	dwTmp 	= dwSizeOfShellcode + sizeof( szAdditionalShellcode);
	char 	*pBuf	= (char*) malloc( dwTmp);
	memset( pBuf, 0, dwTmp);
	
	fread( pBuf, 1, dwSizeOfShellcode, pFile);
	memcpy( (void*)(pBuf+dwSizeOfShellcode), (const void*)szAdditionalShellcode, 
			sizeof( szAdditionalShellcode));
	
	DWORD dwOffset = imgNewSection->PointerToRawData;
	
	dwTmp = imgOptionalHdr.SizeOfImage;
	dwTmp += dwSizeOfShellcode + sizeof( szAdditionalShellcode) + 1;
	dwTmp = ( dwTmp / imgOptionalHdr.SectionAlignment + 1)
			* imgOptionalHdr.SectionAlignment;
			
	imgOptionalHdr.SizeOfImage = dwTmp;

	fseek( pFile, RVA2RAW(imgNewSection->VirtualAddress), FILE_BEGIN);
	fwrite( (const void*)pBuf, 1, dwSizeOfShellcode + sizeof( szAdditionalShellcode), pFile);

	free( pBuf);
}


///////////////////////////////////////////////////////////////////////////////////////

BOOL PE::InsertShellcode( const char *szFileWithShellcode, const char *szSectionName )
{

	FILE 	*pFile 	= fopen( szFileWithShellcode, "rb");
	if( pFile == NULL){
		SetError( 2);
		return 0;
	}

	DWORD	dwSizeOfShellcode = fseek( pFile, 0, FILE_END);
	fclose( pFile);

	IMAGE_SECTION_HEADER ish = 
		CreateSection( dwSizeOfShellcode + 32, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | 
						IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, szSectionName );
	if( !BuildImage( &ish, dwSizeOfShellcode ))
		return FALSE;

	AppendShellcode( szFileWithShellcode, dwSizeOfShellcode, &ish);

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////

BOOL PE::ReadBytes ( LPVOID lpBuffer, DWORD dwSize, DWORD dwOffset, DWORD dwMethod )
{
	DWORD	dwRead = 0;
	DWORD	dwLastOffs = 0;

	if( dwOffset != 0 ){
		dwLastOffs = SetFilePointer( hFileHandle, dwOffset, NULL, dwMethod) ;
		if( dwLastOffs == 0xFFFFFFFF || ::GetLastError() ){
			SET_ERROR;
			CloseHandle( hFileHandle);
			return FALSE;
		}
	}

	ReadFile( hFileHandle, lpBuffer, dwSize, &dwRead, NULL);

	if( hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError() ){
		SET_ERROR;
		return FALSE;
	}else if( dwSize != dwRead ){
		SetError( ERROR_READ_LESS_THAN_SHOULD );
		CloseHandle( hFileHandle);
		return FALSE;
	}

	if( dwOffset != 0 )
		if(SetFilePointer( hFileHandle, dwLastOffs, NULL, FILE_BEGIN)
			== 0xFFFFFFFF || ::GetLastError()){
			SET_ERROR;
			CloseHandle( hFileHandle);
			return FALSE;
		}

	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////

BOOL PE::WriteBytes ( LPVOID lpBuffer, DWORD dwSize, DWORD dwOffset, DWORD dwMethod )
{
	DWORD	dwWritten = 0;
	DWORD	dwLastOffs = 0;

	if( dwOffset != 0 ){
		dwLastOffs = SetFilePointer( hFileHandle, dwOffset, NULL, dwMethod) ;
		if( dwLastOffs == 0xFFFFFFFF || ::GetLastError() ){
			SET_ERROR;
			CloseHandle( hFileHandle);
			return FALSE;
		}
	}

	WriteFile( hFileHandle, lpBuffer, dwSize, &dwWritten, NULL);

	if( hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError() ){
		SET_ERROR;
		return FALSE;
	}else if( dwSize != dwWritten ){
		SetError( ERROR_WRITE_LESS_THAN_SHOULD );
		CloseHandle( hFileHandle);
		return FALSE;
	}

	if( dwOffset != 0 )
		if(SetFilePointer( hFileHandle, dwLastOffs, NULL, FILE_BEGIN)
			== 0xFFFFFFFF || ::GetLastError()){
			SET_ERROR;
			CloseHandle( hFileHandle);
			return FALSE;
		}

	return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////

LPBYTE	PE::MapFile()
{
	if( bIsFileMapped) return lpMapOfFile;
	if( hFileHandle == (HANDLE)-1 || hFileHandle == (HANDLE)0xCCCCCCCC )
		_OpenFile();

	hMapOfFile = CreateFileMappingA( hFileHandle, NULL, PAGE_READWRITE|SEC_COMMIT, 
									bhFileInformation.nFileSizeHigh, 
									bhFileInformation.nFileSizeLow, NULL );
	if( hMapOfFile == NULL || ::GetLastError() )
	{
		SET_ERROR;
		return NULL;
	}

	lpMapOfFile = (LPBYTE)MapViewOfFile( hMapOfFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if( lpMapOfFile == NULL || ::GetLastError() )
	{
		SET_ERROR;
		return NULL;
	}

	bIsFileMapped = true;
	return (LPBYTE)lpMapOfFile;
}


///////////////////////////////////////////////////////////////////////////////////////
