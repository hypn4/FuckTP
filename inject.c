#include <ntifs.h>
#include "private.h"
#include "inject.h"
#include "utils.h"
#include "main.h"
#include <Ntstrsafe.h>

typedef PVOID(*fnPsGetProcessPeb)(PEPROCESS Process);
typedef PVOID(*fnPsGetProcessWow64Process)(PEPROCESS Process);
typedef NTSTATUS(*fnNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(*fnNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS(*fnNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS(*fnNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(*fnNtCreateThreadEx)(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);

extern fnPsGetProcessPeb PsGetProcessPeb;
extern fnPsGetProcessWow64Process PsGetProcessWow64Process;

typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	UCHAR original_code[8];
	PVOID hook_func;
	union
	{
		UNICODE_STRING path;
		UNICODE_STRING32 path32;
	};

	wchar_t buffer[488];
	PVOID module;
} INJECT_BUFFER, *PINJECT_BUFFER;

extern DYNAMIC_DATA dynData;

static PVOID PsNtDllBase = NULL;
static PVOID fnLdrLoadDll = NULL;
static PVOID fnProtectVirtualMemory = NULL;
static PVOID fnHookFunc = NULL;

#ifdef AMD64
static PVOID PsNtDllBase64 = NULL;
static PVOID fnLdrLoadDll64 = NULL;
static PVOID fnProtectVirtualMemory64 = NULL;
static PVOID fnHookFunc64 = NULL;
#endif

#ifdef WINXP
typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
#endif

PINJECT_BUFFER GetInlineHookCode(IN HANDLE hProcess, IN PUNICODE_STRING pDllPath);
PINJECT_BUFFER GetInlineHookCode64(IN HANDLE hProcess, IN PUNICODE_STRING pDllPath);

PINJECT_BUFFER GetThreadInjectCode(IN HANDLE hProcess, IN PVOID NtDllBase, IN PVOID LdrLoadDll, IN PUNICODE_STRING pDllPath);
PINJECT_BUFFER GetThreadInjectCode64(IN HANDLE hProcess, IN PVOID NtDllBase, IN PVOID LdrLoadDll, IN PUNICODE_STRING pDllPath);

PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64);

#pragma alloc_text(PAGE, GetInlineHookCode)
#pragma alloc_text(PAGE, GetInlineHookCode64)
#pragma alloc_text(PAGE, GetThreadInjectCode)
#pragma alloc_text(PAGE, GetThreadInjectCode64)
#pragma alloc_text(PAGE, BBGetUserModule)
#pragma alloc_text(PAGE, BBGetModuleExport)

NTSTATUS NTAPI NewNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtQueryVirtualMemory pfnNtQueryVirtualMemory;

	if (dynData.NtQueryIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtQueryVirtualMemory = (fnNtQueryVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtQueryIndex);
	if (pfnNtQueryVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtReadVirtualMemory pfnNtReadVirtualMemory;

	if (dynData.NtReadIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtReadVirtualMemory = (fnNtReadVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtReadIndex);
	if (pfnNtReadVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtWriteVirtualMemory pfnNtWriteVirtualMemory;

	if (dynData.NtWriteIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtWriteVirtualMemory = (fnNtWriteVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtWriteIndex);
	if (pfnNtWriteVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtProtectVirtualMemory pfnNtProtectVirtualMemory;

	if (dynData.NtProtectIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtProtectVirtualMemory = (fnNtProtectVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtProtectIndex);
	if (pfnNtProtectVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI ZwCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	fnNtCreateThreadEx pfnNtCreateThreadEx;

	if (dynData.NtCreateThdExIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtCreateThreadEx = (fnNtCreateThreadEx)(ULONG_PTR)GetSSDTEntry(dynData.NtCreateThdExIndex);
	if (pfnNtCreateThreadEx)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtCreateThreadEx(
			hThread, DesiredAccess, ObjectAttributes,
			ProcessHandle, lpStartAddress, lpParameter,
			Flags, StackZeroBits, SizeOfStackCommit,
			SizeOfStackReserve, AttributeList
		);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

PVOID AllocateInjectMemory(IN HANDLE ProcessHandle, IN PVOID DesiredAddress, IN SIZE_T DesiredSize)
{
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T AllocateSize = DesiredSize;

	if ((ULONG_PTR)DesiredAddress >= 0x70000000 && (ULONG_PTR)DesiredAddress < 0x80000000)
		DesiredAddress = (PVOID)0x70000000;

	while (1)
	{
		if (!NT_SUCCESS(NewNtQueryVirtualMemory(ProcessHandle, DesiredAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)))
			return NULL;

		if (DesiredAddress != mbi.AllocationBase)
		{
			DesiredAddress = mbi.AllocationBase;
		}
		else
		{
			DesiredAddress = (PVOID)((ULONG_PTR)mbi.AllocationBase - 0x10000);
		}

		if (mbi.State == MEM_FREE)
		{
			if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
			{
				if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
				{
					return mbi.BaseAddress;
				}
			}
		}
	}
	return NULL;
}

const UCHAR HookCode[] =
{
	//为防止某些人乱加特征检测以致影响正常软件工作，故隐去关键代码
};

PINJECT_BUFFER GetInlineHookCode(IN HANDLE ProcessHandle, IN PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = {0};

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)PsNtDllBase, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		status = NewNtReadVirtualMemory(ProcessHandle, fnHookFunc, Buffer.original_code, sizeof(Buffer.original_code), NULL);
		if (NT_SUCCESS(status))
		{
			// Fill data
			Buffer.path32.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			Buffer.path32.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			Buffer.path32.Buffer = (ULONG)pBuffer->buffer;
			Buffer.hook_func = fnHookFunc;
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path32.Length);
			memcpy(Buffer.code, HookCode, sizeof(HookCode));

			// Fill code
			*(DWORD*)((PUCHAR)Buffer.code + 7) = (DWORD)&pBuffer->hook_func;
			*(DWORD*)((PUCHAR)Buffer.code + 38) = (DWORD)((DWORD)fnProtectVirtualMemory - ((DWORD)pBuffer + 42));
			*(DWORD*)((PUCHAR)Buffer.code + 44) = (DWORD)&pBuffer->hook_func;
			*(DWORD*)((PUCHAR)Buffer.code + 49) = (DWORD)pBuffer->original_code;
			*(DWORD*)((PUCHAR)Buffer.code + 56) = (DWORD)pBuffer->original_code + 4;
			*(DWORD*)((PUCHAR)Buffer.code + 81) = (DWORD)((DWORD)fnProtectVirtualMemory - ((DWORD)pBuffer + 85));
			*(DWORD*)((PUCHAR)Buffer.code + 86) = (DWORD)&pBuffer->module;
			*(DWORD*)((PUCHAR)Buffer.code + 91) = (DWORD)&pBuffer->path32;
			*(DWORD*)((PUCHAR)Buffer.code + 100) = (DWORD)((DWORD)fnLdrLoadDll - ((DWORD)pBuffer + 104));
			*(DWORD*)((PUCHAR)Buffer.code + 108) = (DWORD)((DWORD)fnHookFunc - ((DWORD)pBuffer + 112));

			// Copy all
			NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

			return pBuffer;
		}
		else
		{
			DPRINT("%s: Failed to read original code %X\n", __FUNCTION__, status);
		}
	}
	else
	{
		DPRINT("%s: Failed to allocate memory\n", __FUNCTION__);
	}

	return NULL;
}

const UCHAR ThrdCode[] =
{
	//为防止某些人乱加特征检测以致影响正常软件工作，故隐去关键代码
};

PINJECT_BUFFER GetThreadInjectCode(IN HANDLE ProcessHandle, IN PVOID NtDllBase, IN PVOID LdrLoadDll, IN PUNICODE_STRING pDllPath)
{
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)NtDllBase, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		// Fill data
		Buffer.path32.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
		Buffer.path32.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
		Buffer.path32.Buffer = (ULONG)pBuffer->buffer;
		memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path32.Length);
		memcpy(Buffer.code, HookCode, sizeof(HookCode));

		// Fill code
		*(DWORD*)((PUCHAR)Buffer.code + 1) = (DWORD)&pBuffer->module;
		*(DWORD*)((PUCHAR)Buffer.code + 6) = (DWORD)&pBuffer->path32;
		*(DWORD*)((PUCHAR)Buffer.code + 15) = (DWORD)((DWORD)LdrLoadDll - ((DWORD)pBuffer + 19));

		// Copy all
		NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

		return pBuffer;
	}
	else
	{
		DPRINT("%s: Failed to allocate memory\n", __FUNCTION__);
	}

	return NULL;
}

#ifdef AMD64

const UCHAR HookCode64[] = {
	//为防止某些人乱加特征检测以致影响正常软件工作，故隐去关键代码
};

PINJECT_BUFFER GetInlineHookCode64(IN HANDLE ProcessHandle, IN PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)PsNtDllBase64, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		status = NewNtReadVirtualMemory(ProcessHandle, fnHookFunc64, Buffer.original_code, sizeof(Buffer.original_code), NULL);
		if (NT_SUCCESS(status))
		{
			// Fill data
			Buffer.path.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			Buffer.path.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			Buffer.path.Buffer = (PWCH)pBuffer->buffer;
			Buffer.hook_func = fnHookFunc64;
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path.Length);
			memcpy(Buffer.code, HookCode64, sizeof(HookCode64));

			// Fill code
			*(ULONG*)((PUCHAR)Buffer.code + 16) = (ULONG)((ULONGLONG)&pBuffer->hook_func - ((ULONGLONG)pBuffer + 20));
			*(ULONG*)((PUCHAR)Buffer.code + 65) = (ULONG)((ULONGLONG)fnProtectVirtualMemory64 - ((ULONGLONG)pBuffer + 69));
			*(ULONG*)((PUCHAR)Buffer.code + 71) = (ULONG)((ULONGLONG)pBuffer->original_code - ((ULONGLONG)pBuffer + 75));
			*(ULONG*)((PUCHAR)Buffer.code + 83) = (ULONG)((ULONGLONG)&pBuffer->hook_func - ((ULONGLONG)pBuffer + 87));
			*(ULONG*)((PUCHAR)Buffer.code + 96) = (ULONG)((ULONGLONG)(pBuffer->original_code + 4) - ((ULONGLONG)pBuffer + 100));
			*(ULONG*)((PUCHAR)Buffer.code + 124) = (ULONG)((ULONGLONG)fnProtectVirtualMemory64 - ((ULONGLONG)pBuffer + 128));
			*(ULONG*)((PUCHAR)Buffer.code + 131) = (ULONG)((ULONGLONG)&pBuffer->module - ((ULONGLONG)pBuffer + 135));
			*(ULONG*)((PUCHAR)Buffer.code + 140) = (ULONG)((ULONGLONG)&pBuffer->path - ((ULONGLONG)pBuffer + 144));
			*(ULONG*)((PUCHAR)Buffer.code + 147) = (ULONG)((ULONGLONG)fnLdrLoadDll64 - ((ULONGLONG)pBuffer + 151));
			*(ULONG*)((PUCHAR)Buffer.code + 165) = (ULONG)((ULONGLONG)fnHookFunc64 - ((ULONGLONG)pBuffer + 169));

			//Write all
			NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

			return pBuffer;
		}
		else
		{
			DPRINT("%s: Failed to read original code %X\n", __FUNCTION__, status);
		}
	}
	else
	{
		DPRINT("%s: Failed to allocate memory\n", __FUNCTION__);
	}
	return NULL;
}

const UCHAR ThrdCode64[] =
{
	//为防止某些人乱加特征检测以致影响正常软件工作，故隐去关键代码
};

PINJECT_BUFFER GetThreadInjectCode64(IN HANDLE ProcessHandle, IN PVOID NtDllBase, IN PVOID LdrLoadDll, IN PUNICODE_STRING pDllPath)
{
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, NtDllBase, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		// Fill data
		Buffer.path.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
		Buffer.path.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
		Buffer.path.Buffer = (PWCH)pBuffer->buffer;
		memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path.Length);
		memcpy(Buffer.code, ThrdCode64, sizeof(ThrdCode64));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)Buffer.code + 12) = (ULONGLONG)&pBuffer->module;
		*(ULONGLONG*)((PUCHAR)Buffer.code + 22) = (ULONGLONG)&pBuffer->path;
		*(ULONGLONG*)((PUCHAR)Buffer.code + 32) = (ULONGLONG)LdrLoadDll;

		// Copy all
		NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

		return pBuffer;
	}
	else
	{
		DPRINT("%s: Failed to allocate memory\n", __FUNCTION__);
	}

	return NULL;
}

#endif

PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
{
	INT i;

	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.
#ifdef AMD64
		if (isWow64 && PsGetProcessWow64Process != NULL)
		{
			PLIST_ENTRY32 pListEntry;
			PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
			if (pPeb32 == NULL)
			{
				DPRINT("%s: No PEB present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Wait for loader a bit
			for (i = 0; !pPeb32->Ldr && i < 10; i++)
			{
				DPRINT("%s: Loader not intialiezd, waiting\n", __FUNCTION__);
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb32->Ldr)
			{
				DPRINT("%s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
				pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
				pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
			{
				UNICODE_STRING ustr;
				PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

				if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
					return (PVOID)pEntry->DllBase;
			}
		}
		// Native process
		else
		{
#endif
			PLIST_ENTRY pListEntry;
			PPEB pPeb = PsGetProcessPeb(pProcess);
			if (!pPeb)
			{
				DPRINT("%s: No PEB present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Wait for loader a bit
			for (i = 0; !pPeb->Ldr && i < 10; i++)
			{
				DPRINT("%s: Loader not intialiezd, waiting\n", __FUNCTION__);
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb->Ldr)
			{
				DPRINT("%s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
				pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
				pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
					return pEntry->DllBase;
			}
#ifdef AMD64
		}
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("%s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	return NULL;
}

PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;
	PUSHORT pAddressOfOrds;
	PULONG  pAddressOfNames;
	PULONG  pAddressOfFuncs;
	ULONG i;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// Find by index
		if ((ULONG_PTR)name_ord <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
			return NULL;

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

			// Check forwarded export
			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
			{
				return NULL;
			}

			break;
		}
	}

	return (PVOID)pAddress;
}

NTSTATUS InjectByHook(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;

	if (!PsNtDllBase)
		PsNtDllBase = ImageBase;

	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
		if (NT_SUCCESS(status))
		{
			status = STATUS_UNSUCCESSFUL;

			if (!fnLdrLoadDll || !fnHookFunc || !fnProtectVirtualMemory)
			{
				KAPC_STATE kApc;
				KeStackAttachProcess(Process, &kApc);
				fnProtectVirtualMemory = BBGetModuleExport(ImageBase, "ZwProtectVirtualMemory");
				fnLdrLoadDll = BBGetModuleExport(ImageBase, "LdrLoadDll");
				fnHookFunc = BBGetModuleExport(ImageBase, "ZwTestAlert");
				KeUnstackDetachProcess(&kApc);
			}

			if (fnLdrLoadDll && fnHookFunc && fnProtectVirtualMemory)
			{
				PINJECT_BUFFER pBuffer = GetInlineHookCode(ProcessHandle, pDllPath);
				if (pBuffer)
				{
					UCHAR trampo[] = { 0xE9, 0, 0, 0, 0 };
					ULONG OldProtect = 0;
					PVOID ProtectAddress = fnHookFunc;
					SIZE_T ProtectSize = sizeof(trampo);

					*(DWORD *)(trampo + 1) = (DWORD)((DWORD)pBuffer->code - ((DWORD)fnHookFunc + 5));

					status = NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
					if (NT_SUCCESS(status))
					{
						NewNtWriteVirtualMemory(ProcessHandle, fnHookFunc, trampo, sizeof(trampo), &ReturnLength);
						NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
					}
				}
			}

			ZwClose(ProcessHandle);
		}

		ObDereferenceObject(Process);
	}

	return status;
}

NTSTATUS InjectCreateThread(HANDLE ProcessId, PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	PVOID pNtDllBase;
	PVOID pfnLdrLoadDll;

	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
		if (NT_SUCCESS(status))
		{
			//Do not inject x64 process
			status = STATUS_UNSUCCESSFUL;
#ifdef AMD64
			if (PsGetProcessWow64Process(Process) != NULL)
			{
#endif
				pNtDllBase = PsNtDllBase;
				pfnLdrLoadDll = fnLdrLoadDll;

				if (!pfnLdrLoadDll)
				{
					UNICODE_STRING NtdllName;
					KAPC_STATE kApc;

					KeStackAttachProcess(Process, &kApc);
					RtlInitUnicodeString(&NtdllName, L"ntdll.dll");
#ifdef AMD64
					pNtDllBase = BBGetUserModule(Process, &NtdllName, TRUE);
#else
					pNtDllBase = BBGetUserModule(Process, &NtdllName, FALSE);
#endif
					if (pNtDllBase)
					{
						pfnLdrLoadDll = BBGetModuleExport(pNtDllBase, "LdrLoadDll");
					}
					KeUnstackDetachProcess(&kApc);
				}

				if (pfnLdrLoadDll)
				{
					PINJECT_BUFFER pBuffer = GetThreadInjectCode(ProcessHandle, pNtDllBase, pfnLdrLoadDll, pDllPath);
					if (pBuffer)
					{
						HANDLE hThread = NULL;
						OBJECT_ATTRIBUTES ob = { 0 };

						InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

						status = ZwCreateThreadEx(
							&hThread, THREAD_ALL_ACCESS, &ob,
							ProcessHandle, pBuffer->code, NULL,
							THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
							0, 0x1000, 0x100000, NULL);

						if (hThread)
							ZwClose(hThread);
					}
				}
#ifdef AMD64
			}
#endif
			ZwClose(ProcessHandle);
		}
		ObDereferenceObject(Process);
	}

	return status;
}

#ifdef AMD64

NTSTATUS InjectByHook64(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;

	if (!PsNtDllBase64)
		PsNtDllBase64 = ImageBase;

	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		//Do not inject WOW64 process
		status = STATUS_UNSUCCESSFUL;
		if (PsGetProcessWow64Process(Process) == NULL)
		{
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
			if (NT_SUCCESS(status))
			{
				KAPC_STATE kApc;

				if (!fnLdrLoadDll64 || !fnHookFunc64 || !fnProtectVirtualMemory64)
				{
					KeStackAttachProcess(Process, &kApc);
					fnProtectVirtualMemory64 = BBGetModuleExport(ImageBase, "ZwProtectVirtualMemory");
					fnLdrLoadDll64 = BBGetModuleExport(ImageBase, "LdrLoadDll");
					fnHookFunc64 = BBGetModuleExport(ImageBase, "ZwTestAlert");
					KeUnstackDetachProcess(&kApc);
				}

				status = STATUS_UNSUCCESSFUL;

				if (fnLdrLoadDll64 && fnHookFunc64 && fnProtectVirtualMemory64)
				{
					PINJECT_BUFFER pBuffer = GetInlineHookCode64(ProcessHandle, pDllPath);
					if (pBuffer)
					{
						UCHAR trampo[] = { 0xE9, 0, 0, 0, 0 };
						ULONG OldProtect = 0;
						PVOID ProtectAddress = fnHookFunc64;
						SIZE_T ProtectSize = sizeof(trampo);

						*(DWORD *)(trampo + 1) = (DWORD)((ULONG_PTR)pBuffer->code - ((ULONG_PTR)fnHookFunc64 + 5));

						status = NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
						if (NT_SUCCESS(status))
						{
							NewNtWriteVirtualMemory(ProcessHandle, fnHookFunc64, trampo, sizeof(trampo), &ReturnLength);
							NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
						}
					}
				}

				ZwClose(ProcessHandle);
			}
		}
		ObDereferenceObject(Process);
	}

	return status;
}

NTSTATUS InjectCreateThread64(HANDLE ProcessId, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	PVOID pNtDllBase64;
	PVOID pfnLdrLoadDll64;

	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		//Do not inject WOW64 process
		status = STATUS_UNSUCCESSFUL;
		if (PsGetProcessWow64Process(Process) == NULL)
		{
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
			if (NT_SUCCESS(status))
			{
				pNtDllBase64 = PsNtDllBase64;
				pfnLdrLoadDll64 = fnLdrLoadDll64;

				if (!pfnLdrLoadDll64)
				{
					UNICODE_STRING NtdllName;
					KAPC_STATE kApc;

					KeStackAttachProcess(Process, &kApc);
					RtlInitUnicodeString(&NtdllName, L"ntdll.dll");
					pNtDllBase64 = BBGetUserModule(Process, &NtdllName, FALSE);
					if (pNtDllBase64)
					{
						pfnLdrLoadDll64 = BBGetModuleExport(pNtDllBase64, "LdrLoadDll");
					}
					KeUnstackDetachProcess(&kApc);
				}

				if (pfnLdrLoadDll64)
				{
					PINJECT_BUFFER pBuffer = GetThreadInjectCode64(ProcessHandle, pNtDllBase64, pfnLdrLoadDll64, pDllPath);
					if (pBuffer)
					{
						HANDLE hThread = NULL;
						OBJECT_ATTRIBUTES ob = { 0 };

						InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

						status = ZwCreateThreadEx(
							&hThread, THREAD_ALL_ACCESS, &ob,
							ProcessHandle, pBuffer, NULL,
							THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
							0, 0x1000, 0x100000, NULL);

						if (hThread)
							ZwClose(hThread);
					}					
				}
				ZwClose(ProcessHandle);
			}			
		}
		ObDereferenceObject(Process);
	}

	return status;
}

#endif

NTSTATUS BBSetProtection(IN PSET_PROC_PROTECTION pProtection)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pProtection->PID, &pProcess);
	if (NT_SUCCESS(status))
	{
		if (dynData.Protection != 0)
		{
			// Win7
			if (dynData.OsVer == WINVER_VISTA || dynData.OsVer == WINVER_7 || dynData.OsVer == WINVER_7_SP1)
			{
				if (pProtection->enableState)
					*(PULONG)((PUCHAR)pProcess + dynData.Protection) |= 1 << 0xB;
				else
					*(PULONG)((PUCHAR)pProcess + dynData.Protection) &= ~(1 << 0xB);
			}
			// Win8
			else if (dynData.OsVer == WINVER_8)
			{
				*((PUCHAR)pProcess + dynData.Protection) = pProtection->enableState;
			}
			// Win8.1
			else if (dynData.OsVer >= WINVER_81)
			{
				PS_PROTECTION protBuf = { 0 };

				if (pProtection->enableState == FALSE)
				{
					protBuf.Level = 0;
				}
				else
				{
					protBuf.Flags.Signer = PsProtectedSignerWinTcb;
					protBuf.Flags.Type = PsProtectedTypeProtected;
				}

				*((PUCHAR)pProcess + dynData.Protection) = protBuf.Level;
			}
			else
				status = STATUS_NOT_SUPPORTED;
		}
		else
		{
			DPRINT("%s: Invalid protection flag offset\n", __FUNCTION__);
			status = STATUS_INVALID_ADDRESS;
		}
	}
	else
		DPRINT("%s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}