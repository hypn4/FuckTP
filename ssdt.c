#include <ntifs.h>
#include "Private.h"
#include "Utils.h"
#include "main.h"
#include <Ntstrsafe.h>

#ifndef AMD64

extern PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

#endif

BOOLEAN WriteKernelMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy);
ULONG GetNativeFunctionIndex(const char *lpFunctionName);
NTSTATUS BBInitDynamicData(IN OUT PDYNAMIC_DATA pData);
NTSTATUS CreateMyDbgkDebugObjectType(void);
NTSTATUS RestoreDbgkDebugObjectType(void);

#pragma alloc_text(PAGE, GetNativeFunctionIndex)
#pragma alloc_text(PAGE, GetKernelBase)
#pragma alloc_text(PAGE, GetSSDTBase)
#pragma alloc_text(PAGE, GetSSDTEntry)
#pragma alloc_text(PAGE, CreateMyDbgkDebugObjectType)
#pragma alloc_text(PAGE, RestoreDbgkDebugObjectType)
#pragma alloc_text(INIT, BBInitDynamicData)

DYNAMIC_DATA dynData = {0};
PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;

ULONG GetNativeFunctionIndex(const char *lpFunctionName)
{
	HANDLE hSection, hFile;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS32 ntHeader;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	ULONG* arrayOfFunctionAddresses;
	ULONG* arrayOfFunctionNames;
	USHORT* arrayOfFunctionOrdinals;
	ULONG x;
	PUCHAR functionAddress = NULL;
	char* functionName = NULL;
	PVOID BaseAddress = NULL;
	SIZE_T Size = 0;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	ULONG uIndex = 0;
	UNICODE_STRING pDllName;

#ifdef AMD64
	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\SysWOW64\\ntdll.dll");
#else
	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\System32\\ntdll.dll");
#endif

	InitializeObjectAttributes(&oa, &pDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (NT_SUCCESS(status))
	{
		oa.ObjectName = 0;
		status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_READONLY, 0x01000000, hFile);
		if (NT_SUCCESS(status))
		{
			BaseAddress = NULL;

			status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &Size, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);
			if (NT_SUCCESS(status))
			{
				dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
				ntHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + dosHeader->e_lfanew);

				pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)BaseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				arrayOfFunctionAddresses = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfFunctions);
				arrayOfFunctionNames = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfNames);
				arrayOfFunctionOrdinals = (USHORT*)((PUCHAR)BaseAddress + pExportTable->AddressOfNameOrdinals);
				
				for (x = 0; x < pExportTable->NumberOfFunctions; x++)
				{
					functionName = (char*)((unsigned char*)BaseAddress + arrayOfFunctionNames[x]);
					functionAddress = ((unsigned char*)BaseAddress + arrayOfFunctionAddresses[arrayOfFunctionOrdinals[x]]);
					if (!_stricmp(functionName, lpFunctionName))
					{
						uIndex = *(USHORT *)(functionAddress + 1);
						break;
					}
				}

				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
			}

			ZwClose(hSection);
		}
		ZwClose(hFile);
	}

	return uIndex;
}

/// <summary>
/// Get ntoskrnl base address
/// </summary>
/// <param name="pSize">Size of module</param>
/// <returns>Found address, NULL if not found</returns>
PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;
	ULONG i;

	// Already found
	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		DPRINT("BlackBone: %s: Invalid SystemModuleInformation size\n", __FUNCTION__);
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, BB_POOL_TAG);
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					*pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, BB_POOL_TAG);

	return g_KernelBase;
}

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ULONG_PTR i, j;
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}


PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase()
{
#ifdef AMD64
	PIMAGE_NT_HEADERS pHdr;
	PIMAGE_SECTION_HEADER pFirstSec;
	PIMAGE_SECTION_HEADER pSec;
	PUCHAR ntosBase;

	ntosBase = GetKernelBase(NULL);

	// Already found
	if (g_SSDT != NULL)
		return g_SSDT;

	if (!ntosBase)
		return NULL;

	pHdr = RtlImageNtHeader(ntosBase);
	pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		// Non-paged, non-discardable, readable sections
		// Probably still not fool-proof enough...
		if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)pSec->Name != 'TINI') &&
			(*(PULONG)pSec->Name != 'EGAP'))
		{
			PVOID pFound = NULL;

			// KiSystemServiceRepeat pattern
			UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
			NTSTATUS status = BBSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
			if (NT_SUCCESS(status))
			{
				g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
				//DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n", __FUNCTION__, g_SSDT );
				return g_SSDT;
			}
		}
	}
	return NULL;
#else
	return KeServiceDescriptorTable;
#endif
}


/// <summary>
/// Gets the SSDT entry address by index.
/// </summary>
/// <param name="index">Service index</param>
/// <returns>Found service address, NULL if not found</returns>
PVOID GetSSDTEntry(IN ULONG index)
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();
	if (!pSSDT)
		return NULL;

	// Index range check
	if (index > pSSDT->NumberOfServices)
		return NULL;

#ifdef AMD64
	return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
#else
	return (PVOID)pSSDT->ServiceTableBase[index];
#endif
}

NTSTATUS BBInitDynamicData(IN OUT PDYNAMIC_DATA pData)
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	PVOID fnExGetPreviousMode = NULL;
	PVOID pFoundPattern = NULL;
	UCHAR PreviousModePattern[] = "\x00\x00\xC3";

	if (pData == NULL)
		return STATUS_INVALID_ADDRESS;

	RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));

	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

	if (status == STATUS_SUCCESS)
	{
		ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;

		DPRINT(
			"OS version %d.%d.%d.%d\n",
			verInfo.dwMajorVersion,
			verInfo.dwMinorVersion,
			verInfo.dwBuildNumber,
			verInfo.wServicePackMajor
		);

		switch (ver_short)
		{
		case WINVER_VISTA:
#ifdef AMD64
			pData->Protection = 0x36C;  // Bitfield, bit index - 0xB
#else
			pData->Protection = 0x43C;  // Bitfield, bit index - 0xB
#endif
			// Windows 7
			// Windows 7 SP1
		case WINVER_7:
		case WINVER_7_SP1:
#ifdef AMD64
			pData->Protection = 0x43C;  // Bitfield, bit index - 0xB
#else
			pData->Protection = 0x26C;  // Bitfield, bit index - 0xB
#endif
			break;

			// Windows 8
		case WINVER_8:
#ifdef AMD64
			pData->Protection = 0x648;
#else
			pData->Protection = 0x2D4;
#endif
			break;

			// Windows 8.1
		case WINVER_81:
			pData->Protection = 0x67A;
			break;

			// Windows 10, build 10586
		case WINVER_10:
			pData->Protection = 0x6B2;
			break;

		default:
			break;
		}

		pData->OsVer = (WinVer)ver_short;
		pData->NtReadIndex = GetNativeFunctionIndex("NtReadVirtualMemory");
		pData->NtWriteIndex = GetNativeFunctionIndex("NtWriteVirtualMemory");
		pData->NtProtectIndex = GetNativeFunctionIndex("NtProtectVirtualMemory");
		pData->NtQueryIndex = GetNativeFunctionIndex("NtQueryVirtualMemory");
		pData->NtCreateThdExIndex = GetNativeFunctionIndex("NtCreateThreadEx");
		pData->NtDebugActiveProcessIndex = GetNativeFunctionIndex("NtDebugActiveProcess");

		fnExGetPreviousMode = ExGetPreviousMode;

		if (NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
		{
			pData->PrevMode = *(DWORD *)((PUCHAR)pFoundPattern - 2);
		}

		DPRINT(
			"Dynamic search status: SSDT - %s\n",
			GetSSDTBase() != NULL ? "SUCCESS" : "FAIL"
		);

		return status;
	}

	return status;
}

//Pass TP

PVOID MyDbgkDebugObjectType = NULL;

NTSTATUS CreateMyDbgkDebugObjectType(void)
{
	NTSTATUS status;
	UNICODE_STRING ObjectTypeName;

	union
	{
		OBJECT_TYPE_INITIALIZER_VISTA vista;
		OBJECT_TYPE_INITIALIZER_WIN7 win7;
		OBJECT_TYPE_INITIALIZER_WIN8 win8;
	}ObjectTypeInitializer;

	union 
	{
		OBJECT_TYPE_VISTA *vista;
		OBJECT_TYPE_WIN7 *win7;
		OBJECT_TYPE_WIN8 *win8;
	}DbgkDebugObjectType;

	PVOID fnNtDebugActiveProcess = NULL;
	PVOID pFoundPattern = NULL;
#ifdef AMD64
	UCHAR DebugObjectTypePattern[] = "\xE9\x2A\x2A\x2A\x2A\x4C\x8B\x05";
#else
	UCHAR DebugObjectTypePattern[] = "\x50\xFF\x2A\x2A\xFF\x35\x2A\x2A\x2A\x2A\x6A\x02";
#endif

	if (MyDbgkDebugObjectType)
	{
		goto end;
	}

	//Search Pattern...
	if (!dynData.DbgkDebugObjectType)
	{
		int offset;

		if (!dynData.NtDebugActiveProcessIndex)
			return STATUS_NOT_FOUND;

		fnNtDebugActiveProcess = GetSSDTEntry(dynData.NtDebugActiveProcessIndex);
		if (!fnNtDebugActiveProcess)
			return STATUS_NOT_FOUND;
		if (!NT_SUCCESS(BBSearchPattern(DebugObjectTypePattern, 0x2A, sizeof(DebugObjectTypePattern) - 1, fnNtDebugActiveProcess, 0x200, &pFoundPattern)))
			return STATUS_NOT_FOUND;

		//有符号
#ifdef AMD64
		offset = *(int *)((PUCHAR)pFoundPattern + 8);
		dynData.pDbgkDebugObjectType = (PVOID)((PUCHAR)pFoundPattern + 12 + offset);
#else
		dynData.pDbgkDebugObjectType = *(PVOID *)((PUCHAR)pFoundPattern + 6);
#endif
		dynData.DbgkDebugObjectType = *(PVOID *)dynData.pDbgkDebugObjectType;
	}

	RtlInitUnicodeString(&ObjectTypeName, L"MyDebugObject");

	if (dynData.OsVer >= WINVER_VISTA && dynData.OsVer < WINVER_7)
	{
		DbgkDebugObjectType.vista = dynData.DbgkDebugObjectType;

		if (RtlCompareUnicodeString(&DbgkDebugObjectType.vista->Name, &ObjectTypeName, FALSE) == 0)
		{
			KdPrint(("已经替换为MyDebugObject.\n"));
			return STATUS_ALREADY_WIN32;
		}

		RtlCopyMemory(&ObjectTypeInitializer.vista, &DbgkDebugObjectType.vista->TypeInfo, sizeof(ObjectTypeInitializer.vista));
		if (DbgkDebugObjectType.vista->TypeInfo.ValidAccessMask == 0)
		{
			ObjectTypeInitializer.vista.GenericMapping.GenericRead = 0x00020001;
			ObjectTypeInitializer.vista.GenericMapping.GenericWrite = 0x00020002;
			ObjectTypeInitializer.vista.GenericMapping.GenericExecute = 0x00120000;
			ObjectTypeInitializer.vista.GenericMapping.GenericAll = 0x001f000f;
			ObjectTypeInitializer.vista.ValidAccessMask = 0x001f000f;
		}

		status = ObCreateObjectType(&ObjectTypeName, &ObjectTypeInitializer.vista, (PSECURITY_DESCRIPTOR)NULL, &MyDbgkDebugObjectType);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ObCreateObjectType status = %X\n", status));
			return status;
		}
	}
	else if (dynData.OsVer >= WINVER_7 && dynData.OsVer < WINVER_8)
	{
		DbgkDebugObjectType.win7 = dynData.DbgkDebugObjectType;

		if (RtlCompareUnicodeString(&DbgkDebugObjectType.win7->Name, &ObjectTypeName, FALSE) == 0)
		{
			KdPrint(("已经替换为MyDebugObject.\n"));
			return STATUS_ALREADY_WIN32;
		}

		RtlCopyMemory(&ObjectTypeInitializer.win7, &DbgkDebugObjectType.win7->TypeInfo, sizeof(ObjectTypeInitializer.win7));
		if (DbgkDebugObjectType.win7->TypeInfo.ValidAccessMask == 0)
		{
			ObjectTypeInitializer.win7.GenericMapping.GenericRead = 0x00020001;
			ObjectTypeInitializer.win7.GenericMapping.GenericWrite = 0x00020002;
			ObjectTypeInitializer.win7.GenericMapping.GenericExecute = 0x00120000;
			ObjectTypeInitializer.win7.GenericMapping.GenericAll = 0x001f000f;
			ObjectTypeInitializer.win7.ValidAccessMask = 0x001f000f;
		}

		status = ObCreateObjectType(&ObjectTypeName, &ObjectTypeInitializer.win7, (PSECURITY_DESCRIPTOR)NULL, &MyDbgkDebugObjectType);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ObCreateObjectType status = %X\n", status));
			return status;
		}
	}
	else if (dynData.OsVer >= WINVER_8 && dynData.OsVer <= WINVER_10)
	{
		DbgkDebugObjectType.win8 = dynData.DbgkDebugObjectType;

		if (RtlCompareUnicodeString(&DbgkDebugObjectType.win8->Name, &ObjectTypeName, FALSE) == 0)
		{
			KdPrint(("已经替换为MyDebugObject.\n"));
			return STATUS_ALREADY_WIN32;
		}

		RtlCopyMemory(&ObjectTypeInitializer.win8, &DbgkDebugObjectType.win8->TypeInfo, sizeof(ObjectTypeInitializer.win8));
		if (DbgkDebugObjectType.win8->TypeInfo.ValidAccessMask == 0)
		{
			ObjectTypeInitializer.win8.GenericMapping.GenericRead = 0x00020001;
			ObjectTypeInitializer.win8.GenericMapping.GenericWrite = 0x00020002;
			ObjectTypeInitializer.win8.GenericMapping.GenericExecute = 0x00120000;
			ObjectTypeInitializer.win8.GenericMapping.GenericAll = 0x001f000f;
			ObjectTypeInitializer.win8.ValidAccessMask = 0x001f000f;
		}

		status = ObCreateObjectType(&ObjectTypeName, &ObjectTypeInitializer.win8, (PSECURITY_DESCRIPTOR)NULL, &MyDbgkDebugObjectType);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ObCreateObjectType status = %X\n", status));
			return status;
		}
	}
	else
	{
		KdPrint(("Unsupport OS version!\n"));
		return STATUS_UNSUCCESSFUL;
	}

end:

	if(!WriteKernelMemory(dynData.pDbgkDebugObjectType, &MyDbgkDebugObjectType, sizeof(PVOID)))
	{
		KdPrint(("WriteKernelMemory failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RestoreDbgkDebugObjectType(void)
{
	if (!MyDbgkDebugObjectType)
		return STATUS_UNSUCCESSFUL;

	if (!WriteKernelMemory(dynData.pDbgkDebugObjectType, &dynData.DbgkDebugObjectType, sizeof(PVOID)))
	{
		KdPrint(("WriteKernelMemory failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}