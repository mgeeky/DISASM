#ifndef __DISASM_H_
#define __DISASM_H_

#include <windef.h>
#include <iostream>
#include <string>
#include <vector>
#include "PE.h"

using namespace std;


namespace disasm
{

	///		M A C R O D E F I N I T I O N S
	#define	MAX_INSTRUCTION_NAME_LENGTH	16


	#define __GET_UNIT16( x)		(BYTE)((x) - (unsigned(floor(double(x) / 0x10)) * 0x10))
	#define GET_UNIT( x)			__GET_UNIT16(x)

	#define __GET_BASE16( x)		(BYTE)(floor(double((x) / 0x10)))
	#define GET_BASE( x)			__GET_BASE16( x)

	#define GET_SIZE( x)			((__GET_BASE16( x)) * 8)

	#define GET_REGISTER_SIZE( x)	(	((((x) & 0xF0) == 0xB0)? SIZE_BYTE : \
										((((x) & 0xF0) == 0xC0)? SIZE_WORD : SIZE_DWORD )))

	#define __GET_IMM( type, x, y)	(type)*((type*)(DWORD(x)+(y)))

	#define IS_NEGATIVE_BYTE( x)	(((x) & 80)? 1 : 0)			// Checks wheter most-significant
	#define IS_NEGATIVE( x)			IS_NEGATIVE_BYTE(x)			// bit is set (SIGN bit)
	#define IS_NEGATIVE_WORD( x)	(((x) & 8000)? 1 : 0)
	#define IS_NEGATIVE_DWORD( x)	(((x) & 80000000)? 1 : 0)

	////////####################################################################################

	///		D E F I N I T I O N S
	struct	_i386Instruction;
	struct	_i386ModRM;
	struct	_i386Opcode;
	struct	_i386Prefixes;
	struct	_i386SIB;
	struct	_Analysis;
	struct	_XRef;
	struct	_DISM;

	typedef	_i386Instruction	INSTRUCTION, *LPINSTRUCTION, *PINSTRUCTION, 
								I385INSTRUCTION, *LPI385INSTRUCTION, *PI385INSTRUCTION,
								i386Instruction, *lpi386Instruction, *pi386Instruction;
	typedef	_i386Opcode			OPCODE, *LPOPCODE, *POPCODE, 
								I385OPCODE, *LPI385OPCODE, *PI385OPCODE,
								i386Opcode, *lpi386Opcode, *pi386Opcode;


	////////####################################################################################
	
	///		D I S A S S E M B L E R		S T R U C T .    D E F I N I T I O N S
	
		/////////	ModR/M		////////////
		///		Specifises instruction register or chooses instruction from group.
		///
		///	Mod:	0 - [REG]				( disp == displacement)
		///			1 - [REG + disp8 ]
		///			2 - [REG + disp32]
		///			3 -  REG
		///			|  0 |  1 |  2 |  3 |  4     |  5        |  6 |  7 |
		///	Reg/Op:	| EAX| ECX| EDX| EBX| ESP    | EBP       | ESI| EDI|
		///	R/M:	| EAX| ECX| EDX| EBX| SIB/ESP| disp32/EBP| ESI| EDI|
		///
		struct	_i386ModRM {
			unsigned int	RM		: 3;		// R/M
			unsigned int	RegOp	: 3;		// Reg/Op
			unsigned int	Mod		: 2;		// Mod
		};

		/////////	SIB			////////////
		///		Specifies Scale-Index-Base addressing (using while array calculations).
		///												Using:		Base + Index * Scale
		///	Scale:	0 - 2^0 = 1
		///			1 - 2^1 = 2
		///			2 - 2^2 = 4
		///			3 - 2^3 = 8
		///			|  0 |  1 |  2 |  3 |  4   |  5               |  6 |  7 |
		///	Index:	| EAX| ECX| EDX| EBX| none | EBP              | ESI| EDI|
		/// Base:	| EAX| ECX| EDX| EBX| ESP  | Mod=0 -> disp32  | ESI| EDI|
		///									   | Mod=1 or 2 -> EBP|
		struct	_i386SIB {
			unsigned int	Base	: 3;
			unsigned int	Index	: 3;
			unsigned int	Scale	: 2;
		};

		struct	_i386Prefixes					// Intel Manual Vol. 2A, chapt. 2.1.1, pg. 33
		{
			BYTE	bCode;
			BYTE	bGroup;
			char	*szName;
		};

		// ################		NECCESSARY DEFINITIONS		######################

		// Parameter types - DO NOT CHANGE THIS VALUES ! They are all precisely choosen.

		#define NONE		0x00	// There is no valid parameters/data/byte/code etc.	

		// 8bit operands
		#define R_M8		0x10	// A byte general-purpose register, or a byte from memory.	
		#define R8			0x11	// One of the byte general-purpose registers.
		#define IMM8		0x12	// An immediate byte value. 
		#define M8			0x13	// A byte operand in memory,  pointed to by the DS:(E)SI or ES:(E)DI.  
		#define MOFFS8		0x14	// A simple memory variable (memory offset) of type byte,
									//		word, or doubleword used by some variants of the MOV instruction. 
									//		No ModR/M byte is used in the instruction. 
		#define REL8		0x15	// // A relative address within the same code segment as the instruction assembled.


		// 16bit operands
		
		#define R_M16		0x20	// A word general-purpose register, or a word memory operand.
		#define R16			0x21	// One of the word general-purpose registers.
		#define IMM16		0x22	// An immediate word value. 
		#define M16			0x23	// A word operand in memory, pointed to by the DS:(E)SI or ES:(E)DI
		#define MOFFS16		0x24
		#define REL16		0x25	// A relative address within the same code segment as the instruction assembled.
		#define SREG		0x26	// A segment register. ( ES=0, CS=1, SS=2, DS=3, FS=4, and GS=5 )


		// 32bit operands

		#define R_M32		0x40	// A doubleword general-purpose register, or a doubleword memory operand. 
		#define R32			0x41	// One of the doubleword general-purpose registers.
		#define IMM32		0x42	// An immediate double word value. 
		#define M32			0x43	// A doubleword operand in memory, pointed to by the DS:(E)SI or ES:(E)DI
		#define MOFFS32		0x44
		#define REL32		0x45	// // A relative address within the same code segment as the instruction assembled.

		#define M16_32		0x50	// A memory operand containing a far pointer composed of two numbers.
		#define M32_32		0x51	// A memory operand consisting of data item pairs whose
		#define PTR16_16	0x52	// A far pointer, typically in a code segment different 
									// from that of the instruction. 
		#define PTR16_32	0x53


		// Some egzotic parameter types

		#define M			0x60	// A 16- or 32-bit operand in memory.
		#define MM			0x61	// An MMX register. The 64-bit MMX registers are: MM0 through MM7
		#define M64			0x62
		#define MM_M64		0x63	// An MMX register or a 64-bit memory operand. 

		#define ST_0_		0x70	// The top element of the FPU register stack.
		#define ST_I_		0x71	// The i th element from the top of the FPU register stack. (i=0 through 7)

		#define IMM8_		IMM8
		#define IMM16_		IMM16
		#define IMM32_		IMM32
		#define MM_M64O		MM_M64
		#define M16_32O		M16_32
		#define M32_32O		M32_32
		#define ST			ST_0_	// The top element of the FPU register stack.

		// FPU specific parameter Types..
		#define M14_28BYTE	NONE
		#define M2BYTE		NONE
		#define M94_108BYTE	NONE
		#define M32REAL		NONE
		#define M64REAL		NONE
		#define M80REAL		NONE
		#define M16INT		NONE
		#define M32INT		NONE
		#define M64INT		NONE
		#define M80BCD		NONE


		// Segments

		#define ES			0
		#define CS			1
		#define SS			2
		#define DS			3
		#define FS			4	
		#define GS			5 


		// Registers

		#define AL			0xB0	// 8-bit registers
		#define CL			0xB1								//    rb     rw     rd
		#define DL			0xB2								// ----------------------
		#define BL			0xB3								//	AL = 0 AX = 0 EAX = 0
		#define AH			0xB4								//	CL = 1 CX = 1 ECX = 1
		#define CH			0xB5								//	DL = 2 DX = 2 EDX = 2
		#define DH			0xB6								//	BL = 3 BX = 3 EBX = 3
		#define BH			0xB7								//	AH = 4 SP = 4 ESP = 4
		
		#define AX			0xC0	// 16-bit registers			||	CH = 5 BP = 5 EBP = 5
		#define CX			0xC1								//	DH = 6 SI = 6 ESI = 6
		#define DX			0xC2								//	BH = 7 DI = 7 EDI = 7
		#define BX			0xC3
		#define SP			0xC4
		#define BP			0xC5
		#define SI			0xC6
		#define DI			0xC7
		#define IP			0xC8
		
		#define EAX			0xD0	// 32-bit registers
		#define ECX			0xD1
		#define EDX			0xD2
		#define EBX			0xD3
		#define ESP			0xD4
		#define EBP			0xD5
		#define ESI			0xD6
		#define EDI			0xD7
		#define EIP			0xD8

		#define DR0			0xE0	// Debug registers
		#define DR1			0xE1
		#define DR2			0xE2
		#define DR3			0xE3
		#define DR6			0xE6
		#define DR7			0xE7

		#define CR0			0xF0	// Control Registers
		#define CR2			0xF2
		#define CR3			0xF3
		#define CR4			0xF4	// This register must be last in registers defintions.
									// Procedure DISASM::IsRegister depends on value from this definition.

		// CString representation of registers

		#define _AL			"AL"	// 8-bit registers
		#define _CL			"CL"
		#define _DL			"DL"
		#define _BL			"BL"
		#define _AH			"AH"
		#define _CH			"CH"
		#define _DH			"DH"
		#define _BH			"BH"

		#define _AX			"AX"	// 16-bit registers
		#define _CX			"CX"
		#define _DX			"DX"
		#define _BX			"BX"
	#ifdef _SP
		#undef _SP					// definitions collision (with xlocinfo.h )
	#endif
		#define _SP			"SP"
		#define _BP			"BP"
		#define _SI			"SI"
	#ifdef _DI
		#undef _DI					// definitions collision (with xlocinfo.h )
	#endif
		#define _DI			"DI"
		#define _IP			"IP"

		#define _EAX		"EAX"	// 32-bit registers
		#define _ECX		"ECX"
		#define _EDX		"EDX"
		#define _EBX		"EBX"
		#define _ESP		"ESP"
		#define _EBP		"EBP"
		#define _ESI		"ESI"
		#define _EDI		"EDI"
		#define _EIP		"EIP"

		#define _DR0		"DR0"	// Debug registers
		#define _DR1		"DR1"
		#define _DR2		"DR2"
		#define _DR3		"DR3"
		#define _DR6		"DR6"
		#define _DR7		"DR7"
		#define _CR0		"CR0"	// Control Registers
		#define _CR2		"CR2"
		#define _CR3		"CR3"
		#define _CR4		"CR4"

		#define _CS			"CS"	// Segment Registers
		#define _DS			"DS"
		#define _ES			"ES"
		#define _SS			"SS"
		#define _GS			"GS"
		#define _FS			"FS"

		#define	_UNKNOWN	"??"
		#define NOT_IMPLEMENTED_YET	""

		// Other definitions
		#define SIZE_BYTE	8		// Sizes
		#define SIZE_WORD	16
		#define SIZE_DWORD	32

		#define JMP_BYTE	50		// Relative jump flags
		#define JMP_WORD	51
		#define JMP_DWORD	52
		#define JMP_FAR		53

		// ################		NECCESSARY DEFINITIONS		######################

		struct	_i386Opcode
		{
			BYTE				bCode[ 3];			// Opcode
			BYTE				bData;				// This can be: 
													//	- Digit of group ( /0 - /7)
													//	- 16 (0x10) when there is ModR/M specifier
													//	- 0x50 when this is an REG-dependent instruction
													//	- 0xFF - when nothing
			BYTE				bImmSize;			// Immediate size ( 8, 16, 32 )
			unsigned short		uArgC;				// Number of parameters (arguments) for opcode
			unsigned short		uArgs[ 3];			// Arguments (as a constant). Max. 3 arguments
			char				*szName;			// Instruction name (mnemonic) - max 16. len.
		};	

		///////////////////////////////////////////////////////

		#define _ONE( x)	{ x, 0x00, 0x00}
		#define _TWO( x, y)	{ x, y, 0x00 }

		///////////////////////////////////////////////////////
		// Structure describes each instruction precisely, 
		// by dissassembling whole instruction (opcode)
		struct	_i386Instruction
		{
			BYTE			cInstrBytes[ 16];	// Whole instruction's bytes.
			BYTE			NumOfBytes;			// Number of bytes assigned to this instruction
			_i386Prefixes	*Prefixes[ 4];		// Prefixes (0 - 4)
			BYTE			NumOfPrefixes;		// Number of set prefixes
			_i386Opcode		*Opcode;				// Opcode (size: 0-3)
			BYTE			bIsModRM;			// Is ModR/M byte used? (0 - false, 1 - true)
			union{
				struct							// s - special informations (further)
				{
					_i386ModRM		ModRM;				// ModR/M (0 or 1)
					_i386SIB		SIB;				// SIB (0 or 1)
				} s;
				WORD		wNOP;				// Used to set values in ModRM and SIB from struct s
			};
		};

		

		//**//**//**//**//**//**//**//**//**//**//**//**//**//**//**//**//**//**//**//**//
		//////////////////////////////////////////////////////////////////////////////////
		/////
		/////	Static disassembly analysis control structures
		/////

		#define ANALYSE_CALLING_IMPORTS		0x80000000			// PE impotrs calling analysis
		#define ANALYSE_IMPORTS_IN_PARAMS	0x40000000			// Checks if parameters handle
																// addresses to the Imports (of IAT)
		#define ANALYSE_EVERYTHING			0xFFFFFFFF
		#define ANALYSE_ALL					ANALYSE_EVERYTHING

		#define XREF_TYPE_CALL				0x80000000			// XRef by call
		#define XREF_TYPE_JUMP				0x40000000			// XRef by uncoditional call
		#define XREF_TYPE_CJUMP				0x20000000			// XRef by conditional call
		#define XREF_TYPE_MEM_REF			0x1000000			// XRef by memory reference
		
		struct _XRef
		{
			DWORD		dwSrcAddr;					// Source address of XRef -> From
			DWORD		dwDstAddr;					// Destination address of XRef -> To
			_DISM		*Instruction;				// Pointer to disassembled instruction
			DWORD		dwType;						// Type of XRef. Possible groups of types:
													//		Jumps, Conditional Jumps, Calls, Empty (none)
			DWORD		dwProcedureAddr;			// Address of procedure that owns this instruction
		};

		struct _Analysis
		{
			_XRef		ThisXRef;					// Possible instruction FROM XRef (if CALL, JUMP etc)
			vector<_XRef> vXRefsTo;					// Vector containg all XRefs to this instr.
			bool		bIsReferencing;				// Sygnalize if this instruction is referencing another
			unsigned	uNumOfXRefsTo;				// Number of objects in above array
			bool		bIsReferenced;				// Sygnalize if this instruction has been already 
													// referenced by another instruction
		};


		///////////////////////////////////////////////////////
		// This structure contains clearly dissassembled instruction in
		// sweet CString type :)
		// Additional members like "Instruction" included only for correcting purposes.
		typedef struct	_DISM
		{
			char				szPrefixes[4][6];		// Instuction's prefixes
			char				*szInstruction;			// Instruction name
			char				szParameters[ 3][ 16];	// Instruction's parameters
			DWORD				dwParameters[ 3];		//
			_i386Instruction	Instruction;			// Instruction's internal structure
			_Analysis			Analysis;				// Instruction's analysis
			DWORD				dwInstrAddress;			// Address of an instruction
			DWORD				dwRelativeAddr;			// Relative address of the instruction.
														//	Relative to start of the buffer from which
														//	it has been taken, at disassemble time.
			char				szAdditional[ 256];		// Additional informations, like comments
		} DISM, *PDISM, **PPDISM, *LPDISM;

	////////####################################################################################
	////////####################################################################################


	///		D I S A S M	     C L A S S
	typedef class _disasm
	{
		
		static _i386Prefixes	st_globalPrefixes[ 13];
		static _i386Opcode		st_globalOpcodes[ 622];
		static BYTE				st_globalJumpCodes1[20];
		static BYTE				st_globalJumpCodes2[16][2];

	public:

		// Options

		bool				optUseDecimal;		// If set, all Immediate values will be represented as
												// decimal values instead of hexadecimal
		bool				optAutoAnalyse;		// If set, automatically analysing process will be
												// performed after DisasmBytes(...) routine
		DWORD				optAutoAnalysisFlags;// Flags used by AutoAnalysis

		// Vars

		DWORD				dwLastError;		// Last operation error value
		PE					peFile;				// PE object of this file (of mine PE analysing lib)
		char				*szFileName;		// Name of file that is being processed

		//===========================================

		_disasm								( void){ __DefaultOptions(); }
		_disasm								( char *_szFileName )
		{	
			__DefaultOptions();
			_disasm::Load( _szFileName);		
		}
		~_disasm							( void)
		{
			fclose( pFile);
			peFile.~PE();
		}

		DWORD	GetError					(){ return dwLastError;	}
		DWORD	SetError					( DWORD dwErr )
		{ 
			DWORD dTmp = dwLastError; 
			dwLastError = dwErr; 
			return dTmp; 
		}

		// Overloaded operator ! - used in error checking switches:  ... if( !Disasm ){ ...success... }
		bool	operator!					(){ return (dwLastError == 0)? true : false; }

		
		/*
			Loads file to process. This procedure uses mine PE library, which is useful
			in analysing valid PE files. 
		*/
		bool	Load						( char *szFileName );

		/*
			Disassembles buffer filled with bytes and prepares array of 
			DISM structure objects. 

			@_lpBuffer - address of buffer containing bytes to disassemble
			@lpDisasm - address of DISM structures array
			@uNumOfBytes - number of bytes to process (set 0 if you need to use uNumOfInstr param )
			@uNumOfInstr - number of instructions to disassemble

			#returns - number of disassembled instructions
		*/
		unsigned	DisasmBytes				(	LPVOID _lpBuffer, LPDISM lpDisasm, 
												unsigned long uNumOfBytes,
												unsigned long uNumOfInstr = 0 );

		/*
			Analyses disassembled instructions. Corrects relative jumps,
			performs CALLs recognition, generates additional comments, 
			names local variables / procedure parameters ( EBP-XX, EBP+XX),
			performs (when specified by flag) code CrossReferences (XREF).
			This is active, dynamic analysis of already statically analysed 
			instructions.
			
			@lpDisasm - address of structure that contains instructions to analyse
			@uNumOfInstr - number of instructions to analyse (or -1 to process them all)
			@dwFlags - analysing switches
		*/
		void	AnalyseDisasm				(	LPDISM	lpDisasm, unsigned long uNumOfInstr, DWORD dwFlags );


	private:

		FILE								*pFile;

		_i386Prefixes						*pPrefixes;
		_i386Opcode							*pOpcodes;
		unsigned							uPrefixes;
		unsigned							uOpcodes;
		LPVOID								lpWorkBuffer;

		//=======================

		// Private routine used to parse rest of cut from buffer instruction.
		// It prepares pDism structure, gathers all needed immediates, values or params
		// to correctly process an instruction.
		void			__PrepareDism		(	_i386Opcode *pOpc, LPVOID _lpBuffer, PDISM pDism,
												bool bRegDependent = false );

		// Private routine used to disassemble bytes as ordinary data bytes.
		// Returns number of added instructions to an pDism array.
		unsigned		__DisassembleAsData	(	LPVOID lpBuffer, PDISM lpDism, unsigned uNumOfBytes, 
												DWORD dwRel, bool bForceBytes = false );

		// Performs private, local and static analysis on each instruction passed as
		// an argument. Checks some basic signs.
		void			_StaticInstrAnalysis( LPDISM lpInstruction, LPDISM lpWholeSet,
												unsigned nSetCapacity );
		void			_StaticAfterAnalysis ( LPDISM lpDisasm, unsigned nSetCapacity );

		
		void			__DefaultOptions	()
		{
			optUseDecimal			= false;
			optAutoAnalyse			= true;
			optAutoAnalysisFlags	= ANALYSE_EVERYTHING;
		}


		void			_InitializeGlobals	( );

		bool			IsPrefix			( BYTE bCode )
		{
			for( unsigned u = 0; u < uPrefixes; u++)
				if( bCode == pPrefixes[ u].bCode ) return true;
			return false;
		}

		_i386Prefixes*	GetPrefix			( BYTE bCode )
		{	
			for( unsigned u = 0; u < uPrefixes; u++)
				if( bCode == pPrefixes[ u].bCode ) return &pPrefixes[ u];
			return NULL;
		}

		_i386Opcode*	GetOpcode			( BYTE bCode1, BYTE bCode2 = 0 );
		_i386Opcode*	GetOpcodeEx			( LPBYTE lpBuffer );
		unsigned		GetInstrBytesQuanity( LPVOID _lpBuffer );
		inline unsigned	GetOpcodeBytesNumber( _i386Opcode *pOpc)
		{
			if( pOpc == NULL) 
				return 0;
			return ((pOpc->bCode[ 2] != 0)? 3 : ((pOpc->bCode[ 1] != 0)? 2 : 1) );
		}

		const char*		GetRegister			( unsigned uIndex, short sSize );
		const char*		GetRegister			( unsigned uRegister );
		inline bool		IsEscape			( BYTE bCode )
		{
			return ( bCode == 0x0F || ( bCode >= 0xD8 && bCode <= 0xDF) )? 
				true : false;
		}

		inline bool		IsModRM				( LPBYTE lpBuffer )
		{
			return (GetOpcodeEx( lpBuffer)->bData <= 0x10)? 
				true : false;
		}
		
		inline bool		IsModRM				( _i386Opcode *pOpc)
		{
			return	((pOpc->bData >= 0 && pOpc->bData <= 7) || pOpc->bData == 0x10)? 
				true : false;
		}

		inline bool		IsRegister			( unsigned short uArg )
		{
			return	((uArg >= AL ) && (uArg <= CR4 ))? 
				true:false;
		}
		
		bool			IsMoffsParamType	( _i386Opcode* pOpc)
		{
			if(			pOpc->uArgs[0] == MOFFS8	|| 
						pOpc->uArgs[0] == MOFFS16	|| 
						pOpc->uArgs[0] == MOFFS32)
					return true;
			else if(	pOpc->uArgs[1] == MOFFS8	|| 
						pOpc->uArgs[1] == MOFFS16	|| 
						pOpc->uArgs[1] == MOFFS32)
					return true;
			else if(	pOpc->uArgs[2] == MOFFS8	|| 
						pOpc->uArgs[2] == MOFFS16	|| 
						pOpc->uArgs[2] == MOFFS32	)
					return true;
			else	return false;
		}

		// This procedure checks if instruction is using register as one of its parameters.
		// For example: instructions A0 (mov AL, moffs8*), A1 (mov AX, moffs16*), A1 (mov EAX, moffs32* )
		bool			IsUsingRegister		( _i386Opcode *pOpc )
		{
			if( IsRegister( pOpc->uArgs[0] )	|| 
				IsRegister( pOpc->uArgs[1] )	|| 
				IsRegister( pOpc->uArgs[2] )	)
					return true;
			else	return false;
		}

		// Checks wheter instruction is register-dependent. I.e: 50+rd (PUSH r32)
		inline bool		IsRegDependent		( BYTE bCode1, BYTE bCode2 = 0)
		{
			if(  bCode1 == 0x0F && ( bCode2 >= 0xC8 && bCode2 <= 0xCF)
			||	(bCode1 >= 0x40 && bCode1 <= 0x5F ) 
			||  (bCode1 >= 0x90 && bCode1 <= 0x97 )
			||	(bCode1 >= 0xB0 && bCode1 <= 0xC0 ) ) 
					return true;
			else	return false;		
		}

		// These functions compute relative alignment of value. For example,
		// when CALL opcode have parameter - RELATIVE address (REL8/REL16/REL32)
		// then this address might be treaten as bytes to jump forward, or backward.
		// Below procedures computes this relative address by determining wheter it
		// points forward or backward.
		
		bool			CheckIfValueIsRelative		( DWORD dw)
		{
			if( (dw & 0xFFFF0000) == (DWORD(lpWorkBuffer) & 0xFFFF0000) )
					return true;
			else	return false;
		}

		inline BYTE		byteComputeAlignment		( BYTE b1)
		{
			if( IS_NEGATIVE( b1) )	return 0xFF-b1+1;
			else					return b1;
		}
		inline WORD		wordComputeAlignment		( WORD w1)
		{
			if( IS_NEGATIVE( w1) )	return 0xFFFF-w1+1;
			else					return w1;
		}
		inline DWORD	dwordComputeAlignment		( DWORD dw1)
		{
			if( IS_NEGATIVE( dw1) ) return 0xFFFFFFFF-dw1+1;
			else					return dw1;
		}

		////////////////////////// ANALYSE FUNCTIONS ///////////////////////////
		IMPORTED_FUNCTION *CheckIfCallToImport		( DWORD dwRel, bool bIsRelative = false );	
																	// Checks wheter address points to
																	// app's IAT, and extracts function
																	// that belongs to this index of IAT.
																	// Useful in analysing CALLs to Imports
		bool			IsJump						( _i386Opcode *pOpc);
		bool			IsConditionalJump			( _i386Opcode *pOpc)
		{
			if( !IsJump( pOpc) ) return false;
			if( pOpc->bCode[ 0] == 0xEB || pOpc->bCode[ 0] == 0xE9 ||
				pOpc->bCode[ 0] == 0xEA || 
				( pOpc->bCode[ 0] == 0xFF && pOpc->bData == 4) ||
				( pOpc->bCode[ 0] == 0xFF && pOpc->bData == 0x10) )
				return true;
			else return false;
		}

	public:
		bool			IsCall						( _i386Opcode *pOpc)
		{
			if( pOpc->bCode[ 0] == 0x9A || pOpc->bCode[ 0] == 0xE8 || 
				(pOpc->bCode[ 0] == 0xFF && pOpc->bData == 2 ) || 
				(pOpc->bCode[ 0] == 0xFF && pOpc->bData == 2 ) )
				return true;
			else return false;
		}
		inline bool		IsAPICall					( PDISM pDism )
		{
			if( NULL != CheckIfCallToImport(pDism->dwParameters[0] ) )
					return true;
			else	return false;
		}



	
	} DISASM, *PDISASM, *LPDISASM ;


	////////####################################################################################
	////////####################################################################################

}	// namespace disasm;

#endif

