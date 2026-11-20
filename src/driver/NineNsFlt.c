// NineNsFlt.c — WFP callout driver: DNS leak prevention.
//
// Blocks every outbound connect to remote port 53 except loopback, so all host
// DNS is forced through a local resolver on 127.0.0.1/::1. IPv4 values in WFP
// incoming data are host-order UINT32 (127.0.0.1 == 0x7F000001); this is the
// same representation used for filter conditions.

#define NTDDI_VERSION 0x0A000006 // Windows 10 RS3: FwpsCalloutRegister2
#define _WIN32_WINNT 0x0A00
#define NDIS630 1 // ndis.h (pulled in by fwpsk.h) hides NET_BUFFER_LIST types otherwise

#include <ntddk.h>
#include <initguid.h>
#include <guiddef.h>
#include <fwpsk.h>
#include <fwpmk.h>

#ifndef RPC_C_AUTHN_DEFAULT
#define RPC_C_AUTHN_DEFAULT 0xFFFFFFFF
#endif

// {6868F3F8-36B1-4315-9BFA-0FA6FC647E01}
DEFINE_GUID(kCalloutV4Key,
    0x6868f3f8, 0x36b1, 0x4315, 0x9b, 0xfa, 0x0f, 0xa6, 0xfc, 0x64, 0x7e, 0x01);
// {CFFAC966-5477-4E35-AF94-4B62877DEF6F}
DEFINE_GUID(kCalloutV6Key,
    0xcffac966, 0x5477, 0x4e35, 0xaf, 0x94, 0x4b, 0x62, 0x87, 0x7d, 0xef, 0x6f);
// {156C713B-08B6-49E6-A234-B9AC21FDC89D}
DEFINE_GUID(kSublayerKey,
    0x156c713b, 0x08b6, 0x49e6, 0xa2, 0x34, 0xb9, 0xac, 0x21, 0xfd, 0xc8, 0x9d);
// {2AE235DF-69D3-4835-BD86-0C3D05F95D59}
DEFINE_GUID(kFilterV4Key,
    0x2ae235df, 0x69d3, 0x4835, 0xbd, 0x86, 0x0c, 0x3d, 0x05, 0xf9, 0x5d, 0x59);
// {0361FFD8-57EB-4465-8B06-A4F525CC1359}
DEFINE_GUID(kFilterV6Key,
    0x0361ffd8, 0x57eb, 0x4465, 0x8b, 0x06, 0xa4, 0xf5, 0x25, 0xcc, 0x13, 0x59);

static const UINT8 kLoopbackV6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

static PDEVICE_OBJECT gDeviceObject = NULL;
static HANDLE gEngineHandle = NULL;
static UINT32 gCalloutIdV4 = 0;
static UINT32 gCalloutIdV6 = 0;
static UINT64 gFilterIdV4 = 0;
static UINT64 gFilterIdV6 = 0;

static BOOLEAN isLoopbackV4(UINT32 address)
{
    return (address & 0xFF000000u) == 0x7F000000u;
}

static BOOLEAN isLoopbackV6(const UINT8* address)
{
    ULONG i;
    if (RtlCompareMemory(address, kLoopbackV6, sizeof(kLoopbackV6)) == sizeof(kLoopbackV6)) {
        return TRUE;
    }
    // Dual-stack sockets reach loopback as ::ffff:127.0.0.0/8.
    for (i = 0; i < 10; ++i) {
        if (address[i] != 0) {
            return FALSE;
        }
    }
    return address[10] == 0xFF && address[11] == 0xFF && address[12] == 0x7F;
}

static void setVerdict(BOOLEAN allowed, FWPS_CLASSIFY_OUT0* classifyOut)
{
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }
    if (allowed) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    } else {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

static void NTAPI classifyV4(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER2* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    const FWP_VALUE0* remote;
    BOOLEAN allowed = FALSE;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    remote = &inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value;
    if (remote->type == FWP_UINT32) {
        allowed = isLoopbackV4(remote->uint32);
    }
    setVerdict(allowed, classifyOut);
}

static void NTAPI classifyV6(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER2* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    const FWP_VALUE0* remote;
    BOOLEAN allowed = FALSE;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    remote = &inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value;
    if (remote->type == FWP_BYTE_ARRAY16_TYPE && remote->byteArray16 != NULL) {
        allowed = isLoopbackV6(remote->byteArray16->byteArray16);
    }
    setVerdict(allowed, classifyOut);
}

static NTSTATUS NTAPI notifyCallout(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER2* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS registerCallouts(PDEVICE_OBJECT deviceObject)
{
    FWPS_CALLOUT2 callout;
    NTSTATUS status;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = kCalloutV4Key;
    callout.classifyFn = classifyV4;
    callout.notifyFn = notifyCallout;
    status = FwpsCalloutRegister2(deviceObject, &callout, &gCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    callout.calloutKey = kCalloutV6Key;
    callout.classifyFn = classifyV6;
    status = FwpsCalloutRegister2(deviceObject, &callout, &gCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        FwpsCalloutUnregisterById0(gCalloutIdV4);
        gCalloutIdV4 = 0;
    }
    return status;
}

static NTSTATUS addDnsCallout(
    HANDLE engineHandle,
    const GUID* layerKey,
    const GUID* calloutKey,
    wchar_t* name)
{
    FWPM_CALLOUT0 callout;

    // Management-plane callout object. Filters fail to add on a clean BFE
    // policy store without it, even when the runtime callout is registered.
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *calloutKey;
    callout.displayData.name = name;
    callout.displayData.description = L"Blocks non-loopback DNS connects";
    callout.applicableLayer = *layerKey;

    return FwpmCalloutAdd0(engineHandle, &callout, NULL, NULL);
}

static NTSTATUS addDnsFilter(
    HANDLE engineHandle,
    const GUID* layerKey,
    const GUID* calloutKey,
    const GUID* filterKey,
    wchar_t* name,
    UINT64* filterId)
{
    FWPM_FILTER_CONDITION0 condition;
    FWPM_FILTER0 filter;

    RtlZeroMemory(&condition, sizeof(condition));
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT16;
    condition.conditionValue.uint16 = 53;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = *filterKey;
    filter.displayData.name = name;
    filter.layerKey = *layerKey;
    filter.subLayerKey = kSublayerKey;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *calloutKey;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;

    return FwpmFilterAdd0(engineHandle, &filter, NULL, filterId);
}

static NTSTATUS addFilters(void)
{
    FWPM_SUBLAYER0 sublayer;
    NTSTATUS status;

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = kSublayerKey;
    sublayer.displayData.name = L"NineNsFlt sublayer";
    sublayer.displayData.description = L"Blocks non-loopback DNS connects";
    sublayer.weight = 0x100;

    status = FwpmTransactionBegin0(gEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FwpmSubLayerAdd0(gEngineHandle, &sublayer, NULL);
    if (NT_SUCCESS(status)) {
        status = addDnsCallout(gEngineHandle,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &kCalloutV4Key, L"NineNsFlt callout v4");
    }
    if (NT_SUCCESS(status)) {
        status = addDnsCallout(gEngineHandle,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &kCalloutV6Key, L"NineNsFlt callout v6");
    }
    if (NT_SUCCESS(status)) {
        status = addDnsFilter(gEngineHandle,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &kCalloutV4Key, &kFilterV4Key,
            L"NineNsFlt DNS v4", &gFilterIdV4);
    }
    if (NT_SUCCESS(status)) {
        status = addDnsFilter(gEngineHandle,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &kCalloutV6Key, &kFilterV6Key,
            L"NineNsFlt DNS v6", &gFilterIdV6);
    }

    if (NT_SUCCESS(status)) {
        status = FwpmTransactionCommit0(gEngineHandle);
    }
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(gEngineHandle);
    }
    return status;
}

static void driverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    if (gEngineHandle != NULL) {
        FwpmTransactionBegin0(gEngineHandle, 0);
        if (gFilterIdV4 != 0) {
            FwpmFilterDeleteById0(gEngineHandle, gFilterIdV4);
        }
        if (gFilterIdV6 != 0) {
            FwpmFilterDeleteById0(gEngineHandle, gFilterIdV6);
        }
        // Filters must be gone before their callout objects can be deleted.
        FwpmCalloutDeleteByKey0(gEngineHandle, &kCalloutV4Key);
        FwpmCalloutDeleteByKey0(gEngineHandle, &kCalloutV6Key);
        FwpmSubLayerDeleteByKey0(gEngineHandle, &kSublayerKey);
        FwpmTransactionCommit0(gEngineHandle);
        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = NULL;
    }
    if (gCalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(gCalloutIdV4);
    }
    if (gCalloutIdV6 != 0) {
        FwpsCalloutUnregisterById0(gCalloutIdV6);
    }
    if (gDeviceObject != NULL) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(registryPath);

    status = IoCreateDevice(
        driverObject, 0, NULL, FILE_DEVICE_NETWORK, 0, FALSE, &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    gDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = registerCallouts(gDeviceObject);
    if (!NT_SUCCESS(status)) {
        driverUnload(driverObject);
        return status;
    }

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &gEngineHandle);
    if (!NT_SUCCESS(status)) {
        driverUnload(driverObject);
        return status;
    }

    status = addFilters();
    if (!NT_SUCCESS(status)) {
        driverUnload(driverObject);
        return status;
    }

    driverObject->DriverUnload = driverUnload;
    return STATUS_SUCCESS;
}
