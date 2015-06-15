#include <ntddk.h>
#include <ntimage.h>

#define		DEVICE_NAME		L"\\Device\\SSDTHook"
#define		LINK_NAME		L"\\DosDevices\\SSDTHook"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase;
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)( (PUCHAR)_function + 1 )]
#define SDT  SYSTEMSERVICE
#define KSDT KeServiceDescriptorTable

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemNotImplemented1,
    SystemProcessesAndThreadsInformation,
    SystemCallCounts,
    SystemConfigurationInformation,
    SystemProcessorTimes,
    SystemGlobalFlag,
    SystemNotImplemented2,
    SystemModuleInformation,
    SystemLockInformation,
    SystemNotImplemented3,
    SystemNotImplemented4,
    SystemNotImplemented5,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPagefileInformation,
    SystemInstructionEmulationCounts,
    SystemInvalidInfoClass1,
    SystemCacheInformation,
    SystemPoolTagInformation,
    SystemProcessorStatistics,
    SystemDpcInformation,
    SystemNotImplemented6,
    SystemLoadImage,
    SystemUnloadImage,
    SystemTimeAdjustment,
    SystemNotImplemented7,
    SystemNotImplemented8,
    SystemNotImplemented9,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemLoadAndCallImage,
    SystemPrioritySeparation,
    SystemNotImplemented10,
    SystemNotImplemented11,
    SystemInvalidInfoClass2,
    SystemInvalidInfoClass3,
    SystemTimeZoneInformation,
    SystemLookasideInformation,
    SystemSetTimeSlipEvent,
    SystemCreateSession,
    SystemDeleteSession,
    SystemInvalidInfoClass4,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS;

PDEVICE_OBJECT g_pDeviceObject;

UNICODE_STRING g_RegPath;

VOID DriverUnload(struct _DRIVER_OBJECT *pDriverObject);

void Hook(void);
void Unhook(void);

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL );

NTSTATUS NtQuerySystemInformation(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL );

NTSTATUS FakeNtQuerySystemInformation(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL );

typedef NTSTATUS (*fn_NtQuerySystemInformation)(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL );

static fn_NtQuerySystemInformation GenuineNtQuerySystemInformation;

NTSTATUS FakeNtQuerySystemInformation(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength OPTIONAL )
{
    NTSTATUS ns;

	DbgPrint("FakeNtQuerySystemInformation called %d\n", SystemInformationClass);

    ns = GenuineNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    return ns;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNICODE_STRING 		uDeviceName = {0};
	UNICODE_STRING 		uLinkName = {0};
	NTSTATUS 			ntStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT		pDeviceObject = NULL;

	int i = 0;

	DbgPrint("Driver load begin.\n");

	pDriverObject->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	ntStatus = IoCreateDevice(
		pDriverObject,
		0,							// extension device allocated byte number
		&uDeviceName,				// device name 
		FILE_DEVICE_UNKNOWN, 
		0,							// no special characteristics
		TRUE,						// we can open many handles in same time
		&pDeviceObject);		    // [OUT] ptr to the created object

	if ( !NT_SUCCESS(ntStatus) )
	{
		DbgPrint("IoCreateDevice failed: %x\n",ntStatus);
		return ntStatus;
	}

	pDeviceObject-> Flags |= DO_BUFFERED_IO;

	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);

	if( !NT_SUCCESS(ntStatus) )
	{
		DbgPrint("IoCreateSymbolicLink failed: %x\n",ntStatus);
		IoDeleteDevice(pDeviceObject);
		return ntStatus;
	}

	Hook();


	return STATUS_SUCCESS;
}

VOID DriverUnload(struct _DRIVER_OBJECT *pDriverObject)
{

	UNICODE_STRING uLinkName = {0};

	Unhook();

	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&uLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	return;
}

void Hook(void)
{
    //获取未导出的服务函数索引号
    HANDLE    hFile;
    PCHAR    pDllFile;
    ULONG  ulSize;
    ULONG  ulByteReaded;

    __asm
    {
        push    eax
        mov        eax, CR0
        and        eax, 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }

    GenuineNtQuerySystemInformation = 
		(fn_NtQuerySystemInformation) InterlockedExchange((PLONG) &SDT(ZwQuerySystemInformation), (LONG)FakeNtQuerySystemInformation);

    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
    return ;
}

void Unhook(void)
{
    __asm
    {
        push    eax
        mov        eax, CR0
        and        eax, 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }

    InterlockedExchange( (PLONG) &SDT(ZwQuerySystemInformation),  (LONG) GenuineNtQuerySystemInformation);

    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
}
