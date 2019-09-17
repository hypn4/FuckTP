#pragma once

#include "Imports.h"
#include "NativeStructs.h"

// Module type
typedef enum _ModType
{
	mt_mod32,       // 64 bit module
	mt_mod64,       // 32 bit module
	mt_default,     // type is deduced from target process
	mt_unknown      // Failed to detect type
} ModType;

// Image name resolve flags
typedef enum _ResolveFlags
{
	KApiShemaOnly = 1,
	KSkipSxS = 2,
	KFullPath = 4,
} ResolveFlags;

/// <summary>
/// User-mode memory region
/// </summary>
typedef struct _USER_CONTEXT
{
	UCHAR code[0x1000];             // Code buffer
	union
	{
		UNICODE_STRING ustr;
		UNICODE_STRING32 ustr32;
	};
	wchar_t buffer[0x400];          // Buffer for unicode string


									// Activation context data
	union
	{
		ACTCTXW actx;
		ACTCTXW32 actx32;
	};
	HANDLE hCTX;
	ULONG hCookie;

	PVOID ptr;                      // Tmp data
	union
	{
		NTSTATUS status;            // Last execution status
		PVOID retVal;               // Function return value
		ULONG retVal32;             // Function return value
	};

	//UCHAR tlsBuf[0x100];
} USER_CONTEXT, *PUSER_CONTEXT;

/// <summary>
/// Manual map context
/// </summary>
typedef struct _MMAP_CONTEXT
{
	PEPROCESS pProcess;     // Target process
	PVOID pWorkerBuf;       // Worker thread code buffer
	HANDLE hWorker;         // Worker thread handle
	PETHREAD pWorker;       // Worker thread object
	LIST_ENTRY modules;     // Manual module list
	PUSER_CONTEXT userMem;  // Tmp buffer in user space
	HANDLE hSync;           // APC sync handle
	PKEVENT pSync;          // APC sync object
	PVOID pSetEvent;        // ZwSetEvent address
	PVOID pLoadImage;       // LdrLoadDll address
	BOOLEAN tlsInitialized; // Static TLS was initialized
} MMAP_CONTEXT, *PMMAP_CONTEXT;

PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord);

#ifdef WINXP
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	ULONG AllocationProtect;
	SIZE_T RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

#endif