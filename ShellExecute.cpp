// This file was compile in Visual Studio using the BOF Template
#include <Windows.h>
#include "base\helpers.h"
/*TO-DO
* 
* Support arguments, this was already quite difficult so maybe later in the future
* Use TABS not spaces that's why I got fired from Pied Piper the compression company
** Steal the Algorithm??
*/
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

 // === STRUCTS === //
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    ULONG State;
    union {
        struct { ULONG InitFlags; ACCESS_MASK AdditionalFileAccess; } InitState;
        struct { HANDLE FileHandle; } FailSection;
        struct { USHORT DllCharacteristics; } ExeFormat;
        struct { HANDLE IFEOKey; } ExeName;
        struct {
            ULONG OutputFlags;
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union { ULONG_PTR Value; PVOID ValuePtr; };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// ===  DEFINITIONS === //
typedef NTSTATUS(NTAPI* NtCreateUserProcess_t)(
    PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
    ULONG, ULONG, PVOID, PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST);

typedef NTSTATUS(NTAPI* RtlCreateProcessParametersEx_t)(
    PVOID*, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING,
    PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);

typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);
typedef VOID(NTAPI* RtlDestroyProcessParameters_t)(PVOID);
typedef PVOID(NTAPI* RtlAllocateHeap_t)(PVOID, ULONG, SIZE_T);
typedef BOOLEAN(NTAPI* RtlFreeHeap_t)(PVOID, ULONG, PVOID);

extern "C" {
#include "beacon.h"
    // Define the Dynamic Function Resolution declaration for the GetLastError function
    DFR(KERNEL32, GetLastError);

    // Map GetLastError to KERNEL32$GetLastError 
    #define GetLastError KERNEL32$GetLastError 

    VOID go(IN PCHAR Args, IN ULONG Length) {
        if (Length == 0 || Args == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid command input.");
            return;
        }

        // === Parse BOF Arguments === //
        datap parser;
        BeaconDataParse(&parser, Args, Length);
        CHAR* extractedCmd = (CHAR*)BeaconDataExtract(&parser, NULL);

        if (!extractedCmd || extractedCmd[0] == '\0') {
            BeaconPrintf(CALLBACK_ERROR, "No valid command received.");
            return;
        }

        WCHAR wCmd[MAX_PATH];
        DFR_LOCAL(KERNEL32, MultiByteToWideChar);
        MultiByteToWideChar(CP_ACP, 0, extractedCmd, -1, wCmd, MAX_PATH);
        UNICODE_STRING NtImagePath;

        // === Load NTDLL === //
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        if (!hNtdll) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to load ntdll.dll.");
            return;
        }

        RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hNtdll, "RtlInitUnicodeString");
        RtlCreateProcessParametersEx_t RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
        RtlDestroyProcessParameters_t RtlDestroyProcessParameters = (RtlDestroyProcessParameters_t)GetProcAddress(hNtdll, "RtlDestroyProcessParameters");
        RtlAllocateHeap_t RtlAllocateHeap = (RtlAllocateHeap_t)GetProcAddress(hNtdll, "RtlAllocateHeap");
        RtlFreeHeap_t RtlFreeHeap = (RtlFreeHeap_t)GetProcAddress(hNtdll, "RtlFreeHeap");
        NtCreateUserProcess_t NtCreateUserProcess = (NtCreateUserProcess_t)GetProcAddress(hNtdll, "NtCreateUserProcess");

        if (!NtCreateUserProcess || !RtlCreateProcessParametersEx || !RtlDestroyProcessParameters || !RtlInitUnicodeString || !RtlAllocateHeap || !RtlFreeHeap) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resolve necessary functions.");
            return;
        }

        RtlInitUnicodeString(&NtImagePath, wCmd);

        PVOID ProcessParameters = NULL;
        NTSTATUS status = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x01);
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create process parameters.");
            return;
        }

        PS_CREATE_INFO CreateInfo = { 0 };
        CreateInfo.Size = sizeof(CreateInfo);
        CreateInfo.State = 0;

        DFR_LOCAL(KERNEL32, GetProcessHeap)
            PPS_ATTRIBUTE_LIST AttributeList = (PPS_ATTRIBUTE_LIST)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
        if (!AttributeList) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for attribute list.");
            RtlDestroyProcessParameters(ProcessParameters);
            return;
        }

        AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
        AttributeList->Attributes[0].Attribute = 0x20005;
        AttributeList->Attributes[0].Size = NtImagePath.Length;
        AttributeList->Attributes[0].ValuePtr = NtImagePath.Buffer;

        HANDLE hProcess = NULL, hThread = NULL;
        status = NtCreateUserProcess(
            &hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
            NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList
        );

        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "NtCreateUserProcess failed: 0x%X", status);
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "Successfully created process: %s", extractedCmd);
        }

        DFR_LOCAL(KERNEL32, CloseHandle);
        if (hProcess) CloseHandle(hProcess);
        if (hThread) CloseHandle(hThread);
        RtlFreeHeap(GetProcessHeap(), 0, AttributeList);
        RtlDestroyProcessParameters(ProcessParameters);
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif
