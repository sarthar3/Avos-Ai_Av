/*
 * AVOS AI - Minifilter File System Driver
 * Ring 0 - File Read/Write/Execute Hook → IPC Notification to CSO
 *
 * Build Requirements:
 *   - Windows Driver Kit (WDK)
 *   - Visual Studio 2022
 *   - Enable test signing: bcdedit /set testsigning on
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

// ─── Constants ───────────────────────────────────────────────────────────────
#define AVOS_FILTER_NAME    L"AvosMinifilter"
#define AVOS_PIPE_NAME      L"\\Device\\NamedPipe\\AvosCSO"
#define AVOS_ALTITUDE       L"385010"
#define AVOS_TAG            'SNTL'
#define MAX_PATH_LENGTH         1024
#define IPC_BUFFER_SIZE         4096

// ─── Structures ──────────────────────────────────────────────────────────────
typedef struct _AVOS_STREAM_CONTEXT {
    BOOLEAN ScannedAndClean;
    BOOLEAN IsExecutable;
    LONG    ScanCount;
} AVOS_STREAM_CONTEXT, *PAVOS_STREAM_CONTEXT;

typedef struct _IPC_FILE_EVENT {
    ULONG  EventType;      // 1=Create, 2=Write, 3=Delete, 4=Execute
    ULONG  ProcessId;
    WCHAR  FilePath[MAX_PATH_LENGTH];
    ULONG  FileSize;
    UCHAR  Reserved[32];
} IPC_FILE_EVENT, *PIPC_FILE_EVENT;

// EventType values
#define EVENT_FILE_CREATE   1
#define EVENT_FILE_WRITE    2
#define EVENT_FILE_DELETE   3
#define EVENT_FILE_EXECUTE  4

// ─── Globals ─────────────────────────────────────────────────────────────────
PFLT_FILTER g_FilterHandle = NULL;
HANDLE      g_PipeHandle   = NULL;
FAST_MUTEX  g_PipeMutex;

// ─── Forward Declarations ────────────────────────────────────────────────────
DRIVER_UNLOAD AvosDriverUnload;
FLT_PREOP_CALLBACK_STATUS AvosPreCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS AvosPreWrite(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS AvosPreSetInfo(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
NTSTATUS AvosInstanceSetup(PCFLT_RELATED_OBJECTS, FLT_INSTANCE_SETUP_FLAGS, DEVICE_TYPE, FLT_FILESYSTEM_TYPE);
NTSTATUS AvosUnload(FLT_FILTER_UNLOAD_FLAGS);
NTSTATUS AvosConnectPipe(VOID);
NTSTATUS AvosSendIpcEvent(PIPC_FILE_EVENT Event);
VOID     AvosGetFilePath(PFLT_CALLBACK_DATA Data, PWCHAR Buffer, ULONG BufferLen);

// ─── Filter Registration ─────────────────────────────────────────────────────
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        AvosPreCreate,
        NULL
    },
    {
        IRP_MJ_WRITE,
        0,
        AvosPreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        AvosPreSetInfo,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistrations[] = {
    { FLT_STREAM_CONTEXT, 0, NULL, sizeof(AVOS_STREAM_CONTEXT), AVOS_TAG },
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistrations,
    Callbacks,
    AvosUnload,
    AvosInstanceSetup,
    NULL,   // InstanceQueryTeardown
    NULL,   // InstanceTeardownStart
    NULL,   // InstanceTeardownComplete
    NULL, NULL, NULL
};

// ─── DriverEntry ─────────────────────────────────────────────────────────────
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AVOS] Minifilter loading...\n");

    ExInitializeFastMutex(&g_PipeMutex);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AVOS] FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }

    // Connect IPC pipe to CSO (Ring 3)
    status = AvosConnectPipe();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AVOS] IPC pipe connection failed (CSO may not be running): 0x%X\n", status);
        // Continue without IPC — will retry on each event
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AVOS] FltStartFiltering failed: 0x%X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    DbgPrint("[AVOS] Minifilter loaded successfully.\n");
    return STATUS_SUCCESS;
}

// ─── Unload ──────────────────────────────────────────────────────────────────
NTSTATUS AvosUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("[AVOS] Minifilter unloading...\n");

    if (g_PipeHandle) {
        ZwClose(g_PipeHandle);
        g_PipeHandle = NULL;
    }

    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
    }

    return STATUS_SUCCESS;
}

// ─── Instance Setup ──────────────────────────────────────────────────────────
NTSTATUS AvosInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    if (VolumeFilesystemType == FLT_FSTYPE_RAW) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

// ─── Pre-Create Callback (File Open/Execute) ─────────────────────────────────
FLT_PREOP_CALLBACK_STATUS AvosPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only flag execute-intent opens
    ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (desiredAccess & GENERIC_EXECUTE || desiredAccess & FILE_EXECUTE) {
        IPC_FILE_EVENT evt = {0};
        evt.EventType = EVENT_FILE_EXECUTE;
        evt.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        AvosGetFilePath(Data, evt.FilePath, MAX_PATH_LENGTH);
        AvosSendIpcEvent(&evt);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ─── Pre-Write Callback ──────────────────────────────────────────────────────
FLT_PREOP_CALLBACK_STATUS AvosPreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    IPC_FILE_EVENT evt = {0};
    evt.EventType = EVENT_FILE_WRITE;
    evt.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt.FileSize  = (ULONG)Data->Iopb->Parameters.Write.Length;
    AvosGetFilePath(Data, evt.FilePath, MAX_PATH_LENGTH);
    AvosSendIpcEvent(&evt);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ─── Pre-SetInformation Callback (Delete) ────────────────────────────────────
FLT_PREOP_CALLBACK_STATUS AvosPreSetInfo(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        IPC_FILE_EVENT evt = {0};
        evt.EventType = EVENT_FILE_DELETE;
        evt.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        AvosGetFilePath(Data, evt.FilePath, MAX_PATH_LENGTH);
        AvosSendIpcEvent(&evt);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
VOID AvosGetFilePath(PFLT_CALLBACK_DATA Data, PWCHAR Buffer, ULONG BufferLen)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        ULONG copyLen = min(nameInfo->Name.Length / sizeof(WCHAR), BufferLen - 1);
        RtlCopyMemory(Buffer, nameInfo->Name.Buffer, copyLen * sizeof(WCHAR));
        Buffer[copyLen] = L'\0';
        FltReleaseFileNameInformation(nameInfo);
    }
}

NTSTATUS AvosConnectPipe(VOID)
{
    UNICODE_STRING pipeName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;

    RtlInitUnicodeString(&pipeName, AVOS_PIPE_NAME);
    InitializeObjectAttributes(&objAttr, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwCreateFile(
        &g_PipeHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
}

NTSTATUS AvosSendIpcEvent(PIPC_FILE_EVENT Event)
{
    if (!g_PipeHandle) {
        NTSTATUS st = AvosConnectPipe();
        if (!NT_SUCCESS(st)) return st;
    }

    IO_STATUS_BLOCK ioStatus;
    ExAcquireFastMutex(&g_PipeMutex);
    NTSTATUS status = ZwWriteFile(
        g_PipeHandle,
        NULL, NULL, NULL,
        &ioStatus,
        Event,
        sizeof(IPC_FILE_EVENT),
        NULL, NULL);
    ExReleaseFastMutex(&g_PipeMutex);

    if (!NT_SUCCESS(status)) {
        // Pipe broken — close and retry next time
        ZwClose(g_PipeHandle);
        g_PipeHandle = NULL;
    }

    return status;
}
