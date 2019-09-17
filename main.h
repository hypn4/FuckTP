#define dprintf				DbgPrint

#ifdef AMD64

#define	DEVICE_NAME			L"\\Device\\FuckTP"
#define LINK_NAME			L"\\DosDevices\\FuckTP"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\FuckTP"

#else

#define	DEVICE_NAME			L"\\Device\\FuckTP"
#define LINK_NAME			L"\\DosDevices\\FuckTP"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\FuckTP"

#endif

#define IOCTL_GLOBAL_INJECT_DLL_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_DLL_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROCESS_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x102, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_DEBUGOBJECTTYPE_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x103, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESTORE_DEBUGOBJECTTYPE_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x104, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_TARGET_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x105, METHOD_BUFFERED, FILE_ANY_ACCESS)
/// <summary>
/// Input for IOCTL_GLOBAL_INJECT_DLL
/// </summary>
typedef struct _DRV_INJECT_DLL
{
	WCHAR		Dll32Path[488];
	WCHAR		Dll64Path[488];
} DRV_INJECT_DLL, *PDRV_INJECT_DLL;

typedef struct _SET_PROC_PROTECTION
{
	ULONG   PID;            // Process ID
	BOOLEAN enableState;    // TRUE to enable, FALSE to disable
} SET_PROC_PROTECTION, *PSET_PROC_PROTECTION;

typedef enum _WinVer
{
	WINVER_XP = 0x0510,
	WINVER_XP_SP1 = 0x0511,
	WINVER_XP_SP2 = 0x0512,
	WINVER_XP_SP3 = 0x0513,
	WINVER_VISTA = 0x0600,
	WINVER_7 = 0x0610,
	WINVER_7_SP1 = 0x0611,
	WINVER_8 = 0x0620,
	WINVER_81 = 0x0630,
	WINVER_10 = 0x0A00,
} WinVer;

/// <summary>
/// OS-dependent stuff
/// </summary>
typedef struct _DYNAMIC_DATA
{
	WinVer OsVer;
	ULONG Protection;       // EPROCESS::Protection
	ULONG PrevMode;         // KTHREAD::PreviousMode
	ULONG NtQueryIndex;   // NtQueryVirtualMemory SSDT index
	ULONG NtProtectIndex;   // NtProtectVirtualMemory SSDT index
	ULONG NtWriteIndex;     // NtWriteVirtualMemory SSDT index
	ULONG NtReadIndex;      // NtReadVirtualMemory SSDT index	
	ULONG NtCreateThdExIndex; // NtCreateThreadEx SSDT index	
	ULONG NtDebugActiveProcessIndex;
	PVOID pDbgkDebugObjectType;
	PVOID DbgkDebugObjectType;
} DYNAMIC_DATA, *PDYNAMIC_DATA;