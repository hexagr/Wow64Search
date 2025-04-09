#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

BOOL IsProcessWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;
    FARPROC pIsWow64Process = GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (pIsWow64Process) {
        ((BOOL(WINAPI*)(HANDLE, PBOOL))pIsWow64Process)(hProcess, &bIsWow64);
    }
    return bIsWow64;
}

int main() {
    // Check if *this* program is running under WOW64
    if (IsProcessWow64(GetCurrentProcess())) {
        printf("[!] We appear to be running under WOW64 (32-bit on 64-bit Windows)\n\n");
    }
    else {
        printf("[*] We appear to be running as native 64-bit\n\n");
    }

    // Load NtQuerySystemInformation
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    ULONG bufferSize = 0;
    NTSTATUS status;
    PVOID buffer = NULL;

    // Query process info
    do {
        if (buffer) free(buffer);
        buffer = malloc(bufferSize);
        status = NtQuerySystemInformation(5, buffer, bufferSize, &bufferSize);
    } while (status == 0xC0000004);  // STATUS_INFO_LENGTH_MISMATCH

    // Iterate processes
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (procInfo->NextEntryOffset) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            (DWORD)(ULONG_PTR)procInfo->UniqueProcessId);

        if (hProcess) {
            BOOL isWow64 = IsProcessWow64(hProcess);
            CloseHandle(hProcess);

            printf("[%s] %.*S (PID: %d)\n",
                isWow64 ? "WOW64" : "x64",
                procInfo->ImageName.Length / 2,
                procInfo->ImageName.Buffer,
                (DWORD)(ULONG_PTR)procInfo->UniqueProcessId);
        }

        procInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)procInfo + procInfo->NextEntryOffset);
    }

    free(buffer);
    FreeLibrary(ntdll);
    return 0;
}
