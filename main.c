#include <ntddk.h>
#include <ntddkbd.h>
#include <ntddmou.h>
#include <ntstrsafe.h>
#include "kernel.h"
#include "main.h"

fnPsGetProcessPeb PsGetProcessPeb = NULL;
#ifdef AMD64
fnPsGetProcessWow64Process PsGetProcessWow64Process = NULL;
#endif

DRV_INJECT_DLL m_GlobalInjectDll = {0};
CHAR m_GlobalInjectTarget[64] = { 0 };
UNICODE_STRING m_GlobalInjectDllPath32 = { 0 };

#ifdef AMD64
UNICODE_STRING m_GlobalInjectDllPath64 = { 0 };
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString);
NTSTATUS InjectByHook(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath);
NTSTATUS InjectByHook64(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath);
NTSTATUS BBInitDynamicData(IN OUT PDYNAMIC_DATA pData);
NTSTATUS InjectCreateThread(HANDLE ProcessId, PUNICODE_STRING pDllPath);
NTSTATUS InjectCreateThread64(HANDLE ProcessId, PUNICODE_STRING pDllPath);
NTSTATUS CreateMyDbgkDebugObjectType(void);
NTSTATUS RestoreDbgkDebugObjectType(void);
NTSTATUS BBSetProtection(IN PSET_PROC_PROTECTION pProtection);
VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo);

extern DYNAMIC_DATA dynData;

#pragma alloc_text(INIT, DriverEntry) 

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;

	//Unregister routine
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);

	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo)
{
	PEPROCESS Process;

	if (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4)
		return;

	if (!FullImageName || !FullImageName->Length)
		return;

	if (pImageInfo->SystemModeImage)
		return;

	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		ObDereferenceObject(Process);
		PCHAR ProcessName = PsGetProcessImageFileName(Process);
		if (ProcessName && !_stricmp(ProcessName, m_GlobalInjectTarget))
		{
			//ntdll.dll
			if (0 == _wcsnicmp(FullImageName->Buffer, L"\\SystemRoot\\System32\\ntdll.dll", 30))
			{
	#ifdef AMD64
				if (m_GlobalInjectDllPath64.Length != 0)
					InjectByHook64(ProcessId, pImageInfo->ImageBase, &m_GlobalInjectDllPath64);
	#else
				if (m_GlobalInjectDllPath32.Length != 0)
					InjectByHook(ProcessId, pImageInfo->ImageBase, &m_GlobalInjectDllPath32);
	#endif
				return;
			}

	#ifdef AMD64
			if (0 == _wcsnicmp(FullImageName->Buffer, L"\\SystemRoot\\SysWOW64\\ntdll.dll", 30))
			{
				if (m_GlobalInjectDllPath32.Length != 0)
					InjectByHook(ProcessId, pImageInfo->ImageBase, &m_GlobalInjectDllPath32);
				return;
			}
	#endif
		}
	}
}

BOOLEAN ReadKernelMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pSourceAddress, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pDestination, pSafeAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

BOOLEAN WriteKernelMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pDestination, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pSafeAddress, pSourceAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

NTSTATUS TerminateProcessById(HANDLE ProcessId)
{
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(Process, 0, NULL, PROCESS_ALL_ACCESS, 0, KernelMode, &ProcessHandle);
		if (NT_SUCCESS(status))
		{
			status = ZwTerminateProcess(ProcessHandle, 0);
		}
	}
	if (Process)
	{
		ObDereferenceObject(Process);
		Process = NULL;
	}
	if (ProcessHandle)
		ZwClose(ProcessHandle);

	return status;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	PVOID pIUserBuffer;
	ULONG uInSize;
	ULONG uOutSize;

	UNREFERENCED_PARAMETER(pDevObj);
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	pIUserBuffer = pIrp->UserBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	switch (uIoControlCode)
	{
	case IOCTL_GLOBAL_INJECT_DLL_CONTROL:
	{
		if (pIoBuffer == NULL || uInSize < sizeof(DRV_INJECT_DLL))
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		memcpy(&m_GlobalInjectDll, pIoBuffer, sizeof(DRV_INJECT_DLL));

		RtlInitUnicodeString(&m_GlobalInjectDllPath32, m_GlobalInjectDll.Dll32Path);
#ifdef AMD64
		RtlInitUnicodeString(&m_GlobalInjectDllPath64, m_GlobalInjectDll.Dll64Path);
#endif
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_INJECT_DLL_CONTROL:
	{
		HANDLE ProcessId;
		if (pIoBuffer == NULL || uInSize < sizeof(UINT32))
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		ProcessId = (HANDLE)*(UINT32 *)pIoBuffer;

		status = InjectCreateThread(ProcessId, &m_GlobalInjectDllPath32);
#ifdef AMD64
		if (!NT_SUCCESS(status))
		{
			status = InjectCreateThread64(ProcessId, &m_GlobalInjectDllPath64);
		}
#endif
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_PROTECT_PROCESS_CONTROL:
	{
		if (pIoBuffer == NULL || uInSize < sizeof(SET_PROC_PROTECTION))
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		status = BBSetProtection(pIoBuffer);

		break;
	}
	case IOCTL_CREATE_DEBUGOBJECTTYPE_CONTROL:
	{
		status = CreateMyDbgkDebugObjectType();

		break;
	}
	case IOCTL_INJECT_TARGET_CONTROL:
	{
		if (pIoBuffer == NULL || uInSize < sizeof(char)*64)
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		strncpy(m_GlobalInjectTarget, pIoBuffer, 64);
		m_GlobalInjectTarget[63] = 0;

		status = STATUS_SUCCESS;

		break;
	}
	}
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	UNICODE_STRING routineName;
	PDEVICE_OBJECT pDevObj;

	UNREFERENCED_PARAMETER(pRegistryString);

	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	//Init Blackbone module
	BBInitDynamicData(&dynData);

	RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
	PsGetProcessPeb = (fnPsGetProcessPeb)MmGetSystemRoutineAddress(&routineName);
#ifdef AMD64
	RtlInitUnicodeString(&routineName, L"PsGetProcessWow64Process");
	PsGetProcessWow64Process = (fnPsGetProcessWow64Process)MmGetSystemRoutineAddress(&routineName);
#endif

	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	if(!NT_SUCCESS(PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback)))
	{
		DbgPrint("Couldn't Install LoadImage Notify\n");
	}

	return STATUS_SUCCESS;
}