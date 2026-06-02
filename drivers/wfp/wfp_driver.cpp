/*
 * AVOS AI - WFP (Windows Filtering Platform) Firewall Driver
 * Stateful packet filtering + application-level blocking
 * Sends events to CSO via Named Pipe IPC
 */

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <mstcpip.h>

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "uuid.lib")

#define AVOS_WFP_TAG        'SWFP'
#define AVOS_PIPE_NAME      L"\\Device\\NamedPipe\\AvosCSO"
#define MAX_BLOCKED_APPS        256
#define IPC_NET_BUFFER_SIZE     1024

// ─── Callout GUIDs ───────────────────────────────────────────────────────────
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(AVOS_CALLOUT_GUID,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// ─── Structures ──────────────────────────────────────────────────────────────
typedef struct _NET_EVENT {
    ULONG  EventType;    // 1=Connect, 2=Block
    ULONG  ProcessId;
    UINT32 LocalAddr;
    UINT32 RemoteAddr;
    UINT16 RemotePort;
    UINT8  Protocol;     // IPPROTO_TCP=6, IPPROTO_UDP=17
    WCHAR  AppPath[512];
} NET_EVENT, *PNET_EVENT;

typedef struct _BLOCKED_APP {
    WCHAR Path[512];
    BOOLEAN Active;
} BLOCKED_APP;

#define NET_EVENT_CONNECT   1
#define NET_EVENT_BLOCK     2

// ─── Globals ─────────────────────────────────────────────────────────────────
static HANDLE  g_EngineHandle   = NULL;
static UINT32  g_CalloutId      = 0;
static UINT32  g_FilterId       = 0;
static HANDLE  g_PipeHandle     = NULL;
static FAST_MUTEX g_PipeMutex;

// Blocked application list (runtime blocklist)
static BLOCKED_APP g_BlockedApps[MAX_BLOCKED_APPS] = {0};
static ULONG g_BlockedAppCount = 0;
static KSPIN_LOCK g_BlockListLock;

// ─── Forward Declarations ────────────────────────────────────────────────────
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     AvosWfpUnload;
NTSTATUS AvosWfpRegisterCallout(VOID);
NTSTATUS AvosWfpAddFilter(VOID);
VOID     AvosWfpClassify(const FWPS_INCOMING_VALUES*, const FWPS_INCOMING_METADATA_VALUES*,
                              VOID*, const VOID*, const FWPS_FILTER*, UINT64, FWPS_CLASSIFY_OUT*);
NTSTATUS AvosWfpNotify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, const FWPS_FILTER*);
VOID     AvosWfpFlowDelete(UINT16, UINT32, UINT64);
BOOLEAN  AvosIsAppBlocked(UINT32 ProcessId);
NTSTATUS AvosSendNetEvent(PNET_EVENT Event);
NTSTATUS AvosConnectPipe(VOID);

// ─── DriverEntry ─────────────────────────────────────────────────────────────
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AVOS-WFP] Loading WFP Firewall Driver...\n");

    DriverObject->DriverUnload = AvosWfpUnload;

    ExInitializeFastMutex(&g_PipeMutex);
    KeInitializeSpinLock(&g_BlockListLock);

    // Open WFP engine
    FWPM_SESSION session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AVOS-WFP] FwpmEngineOpen failed: 0x%X\n", status);
        return status;
    }

    // Register callout
    status = AvosWfpRegisterCallout();
    if (!NT_SUCCESS(status)) return status;

    // Add filter
    status = AvosWfpAddFilter();
    if (!NT_SUCCESS(status)) return status;

    // Connect IPC
    AvosConnectPipe();

    DbgPrint("[AVOS-WFP] WFP Firewall Driver loaded.\n");
    return STATUS_SUCCESS;
}

// ─── Unload ──────────────────────────────────────────────────────────────────
VOID AvosWfpUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[AVOS-WFP] Unloading WFP driver...\n");

    if (g_FilterId)  FwpmFilterDeleteById(g_EngineHandle, g_FilterId);
    if (g_CalloutId) FwpsCalloutUnregisterById(g_CalloutId);
    if (g_EngineHandle) FwpmEngineClose(g_EngineHandle);
    if (g_PipeHandle)   ZwClose(g_PipeHandle);
}

// ─── Register Callout ────────────────────────────────────────────────────────
NTSTATUS AvosWfpRegisterCallout(VOID)
{
    FWPS_CALLOUT callout = {0};
    callout.calloutKey         = AVOS_CALLOUT_GUID;
    callout.classifyFn         = AvosWfpClassify;
    callout.notifyFn           = AvosWfpNotify;
    callout.flowDeleteFn       = AvosWfpFlowDelete;

    NTSTATUS status = FwpsCalloutRegister(NULL, &callout, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AVOS-WFP] FwpsCalloutRegister failed: 0x%X\n", status);
        return status;
    }

    FWPM_CALLOUT fwpmCallout = {0};
    fwpmCallout.calloutKey        = AVOS_CALLOUT_GUID;
    fwpmCallout.displayData.name  = L"AvosWFP";
    fwpmCallout.displayData.description = L"AVOS AI WFP Callout";
    fwpmCallout.applicableLayer   = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    return FwpmCalloutAdd(g_EngineHandle, &fwpmCallout, NULL, NULL);
}

// ─── Add Filter ──────────────────────────────────────────────────────────────
NTSTATUS AvosWfpAddFilter(VOID)
{
    FWPM_FILTER filter = {0};
    filter.displayData.name  = L"AvosFilter";
    filter.layerKey          = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type       = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = AVOS_CALLOUT_GUID;
    filter.weight.type       = FWP_EMPTY;

    return FwpmFilterAdd(g_EngineHandle, &filter, NULL, &g_FilterId);
}

// ─── Classify Function (Packet Inspection) ───────────────────────────────────
VOID AvosWfpClassify(
    const FWPS_INCOMING_VALUES       *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    VOID                             *layerData,
    const VOID                       *classifyContext,
    const FWPS_FILTER                *filter,
    UINT64                            flowContext,
    FWPS_CLASSIFY_OUT                *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Default: permit
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;

    UINT32 processId   = (UINT32)(ULONG_PTR)inMetaValues->processId;
    UINT32 remoteAddr  = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort  = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8  protocol    = (UINT8)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    // Check if app is blocked
    if (AvosIsAppBlocked(processId)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;

        // Notify CSO
        NET_EVENT evt = {0};
        evt.EventType  = NET_EVENT_BLOCK;
        evt.ProcessId  = processId;
        evt.RemoteAddr = remoteAddr;
        evt.RemotePort = remotePort;
        evt.Protocol   = protocol;
        AvosSendNetEvent(&evt);
    } else {
        // Log connection
        NET_EVENT evt = {0};
        evt.EventType  = NET_EVENT_CONNECT;
        evt.ProcessId  = processId;
        evt.RemoteAddr = remoteAddr;
        evt.RemotePort = remotePort;
        evt.Protocol   = protocol;
        AvosSendNetEvent(&evt);
    }
}

NTSTATUS AvosWfpNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, const FWPS_FILTER* filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

VOID AvosWfpFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
BOOLEAN AvosIsAppBlocked(UINT32 ProcessId)
{
    // TODO: Look up process path and compare against g_BlockedApps
    // This would use ZwQueryInformationProcess to get image path
    UNREFERENCED_PARAMETER(ProcessId);
    return FALSE;
}

NTSTATUS AvosConnectPipe(VOID)
{
    UNICODE_STRING pipeName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;

    RtlInitUnicodeString(&pipeName, AVOS_PIPE_NAME);
    InitializeObjectAttributes(&objAttr, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwCreateFile(&g_PipeHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttr,
                        &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

NTSTATUS AvosSendNetEvent(PNET_EVENT Event)
{
    if (!g_PipeHandle) {
        NTSTATUS st = AvosConnectPipe();
        if (!NT_SUCCESS(st)) return st;
    }
    IO_STATUS_BLOCK ioStatus;
    ExAcquireFastMutex(&g_PipeMutex);
    NTSTATUS status = ZwWriteFile(g_PipeHandle, NULL, NULL, NULL,
                                   &ioStatus, Event, sizeof(NET_EVENT), NULL, NULL);
    ExReleaseFastMutex(&g_PipeMutex);
    if (!NT_SUCCESS(status)) {
        ZwClose(g_PipeHandle);
        g_PipeHandle = NULL;
    }
    return status;
}
