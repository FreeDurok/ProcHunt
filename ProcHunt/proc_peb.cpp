// SPDX-License-Identifier: MIT
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include "proc_peb.h"
#include "utils.h"

#pragma comment(lib, "ntdll.lib")

// ---- 32/64 mirror ----
typedef struct _UNICODE_STRING32 { USHORT Length, MaximumLength; ULONG Buffer; } UNICODE_STRING32;
typedef struct _MY_CURDIR32 { UNICODE_STRING32 DosPath; ULONG Handle; } MY_CURDIR32;
typedef struct _MY_RTL_USER_PROCESS_PARAMETERS32 {
    ULONG MaximumLength, Length, Flags, DebugFlags;
    ULONG ConsoleHandle, ConsoleFlags;
    ULONG StdInput, StdOutput, StdError;
    MY_CURDIR32 CurrentDirectory;
    UNICODE_STRING32 DllPath, ImagePathName, CommandLine;
    ULONG Environment;
    UNICODE_STRING32 WindowTitle, DesktopInfo, ShellInfo, RuntimeData;
} MY_RTL_USER_PROCESS_PARAMETERS32;

typedef struct _MY_PEB32 {
    BYTE InheritedAddressSpace, ReadImageFileExecOptions, BeingDebugged, Reserved;
    ULONG Mutant, ImageBaseAddress, Ldr, ProcessParameters;
} MY_PEB32;

typedef struct _MY_CURDIR64 { UNICODE_STRING DosPath; HANDLE Handle; } MY_CURDIR64;
typedef struct _MY_RTL_USER_PROCESS_PARAMETERS64 {
    ULONG MaximumLength, Length, Flags, DebugFlags;
    HANDLE ConsoleHandle; ULONG ConsoleFlags;
    HANDLE StdInput, StdOutput, StdError;
    MY_CURDIR64 CurrentDirectory;
    UNICODE_STRING DllPath, ImagePathName, CommandLine;
    PVOID Environment;
    UNICODE_STRING WindowTitle, DesktopInfo, ShellInfo, RuntimeData;
} MY_RTL_USER_PROCESS_PARAMETERS64;
typedef struct _MY_PEB64 {
    BYTE InheritedAddressSpace, ReadImageFileExecOptions, BeingDebugged, Reserved;
    PVOID Mutant, ImageBaseAddress, Ldr;
    MY_RTL_USER_PROCESS_PARAMETERS64* ProcessParameters;
} MY_PEB64;

// ---- helpers ----
static bool ReadRaw(HANDLE h, LPCVOID addr, void* buf, SIZE_T bytes) {
    SIZE_T br = 0; return addr && bytes && ReadProcessMemory(h, addr, buf, bytes, &br) && br == bytes;
}
static bool USRead64(HANDLE h, const UNICODE_STRING& us, std::wstring& out) {
    out.clear(); if (!us.Buffer || us.Length == 0) return true;
    std::vector<wchar_t> tmp(us.Length / sizeof(wchar_t) + 1);
    SIZE_T br = 0; if (!ReadProcessMemory(h, us.Buffer, tmp.data(), us.Length, &br)) return false;
    tmp[br / sizeof(wchar_t)] = L'\0'; out.assign(tmp.data()); return true;
}
static bool USRead32(HANDLE h, const UNICODE_STRING32& us, std::wstring& out) {
    out.clear(); if (!us.Buffer || us.Length == 0) return true;
    std::vector<wchar_t> tmp(us.Length / sizeof(wchar_t) + 1);
    SIZE_T br = 0; if (!ReadProcessMemory(h, (LPCVOID)(uintptr_t)us.Buffer, tmp.data(), us.Length, &br)) return false;
    tmp[br / sizeof(wchar_t)] = L'\0'; out.assign(tmp.data()); return true;
}
static bool IsTargetWow64(HANDLE hProc, bool& isWow64) {
    using PFN_IsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    auto p = (PFN_IsWow64Process2)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process2");
    if (p) { USHORT pm = 0, nm = 0; if (!p(hProc, &pm, &nm)) return false; isWow64 = (pm != IMAGE_FILE_MACHINE_UNKNOWN); return true; }
    BOOL b = FALSE; if (!IsWow64Process(hProc, &b)) return false; isWow64 = b; return true;
}

bool ReadProcParams(DWORD pid, const wchar_t* exeNameHint, ProcParams& out) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;

    bool isWow64 = false; if (!IsTargetWow64(h, isWow64)) { CloseHandle(h); return false; }

    std::wstring img, cmd, cwd, wtitle, desk, shell, rtd;
    if (isWow64) {
        ULONG_PTR wow64Peb = 0; ULONG rl = 0;
        if (NtQueryInformationProcess(h, (PROCESSINFOCLASS)ProcessWow64Information, &wow64Peb, sizeof(wow64Peb), &rl) < 0 || !wow64Peb) { CloseHandle(h); return false; }
        MY_PEB32 peb32{}; if (!ReadRaw(h, (LPCVOID)wow64Peb, &peb32, sizeof(peb32))) { CloseHandle(h); return false; }
        MY_RTL_USER_PROCESS_PARAMETERS32 upp32{}; if (!ReadRaw(h, (LPCVOID)(uintptr_t)peb32.ProcessParameters, &upp32, sizeof(upp32))) { CloseHandle(h); return false; }
        USRead32(h, upp32.ImagePathName, img); USRead32(h, upp32.CommandLine, cmd);
        USRead32(h, upp32.CurrentDirectory.DosPath, cwd);
        USRead32(h, upp32.WindowTitle, wtitle); USRead32(h, upp32.DesktopInfo, desk);
        USRead32(h, upp32.ShellInfo, shell);    USRead32(h, upp32.RuntimeData, rtd);
    }
    else {
        PROCESS_BASIC_INFORMATION pbi{}; ULONG rl = 0;
        if (NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof(pbi), &rl) < 0 || !pbi.PebBaseAddress) { CloseHandle(h); return false; }
        MY_PEB64 peb{}; if (!ReadRaw(h, pbi.PebBaseAddress, &peb, sizeof(peb))) { CloseHandle(h); return false; }
        MY_RTL_USER_PROCESS_PARAMETERS64 upp{}; if (!ReadRaw(h, peb.ProcessParameters, &upp, sizeof(upp))) { CloseHandle(h); return false; }
        USRead64(h, upp.ImagePathName, img); USRead64(h, upp.CommandLine, cmd);
        USRead64(h, upp.CurrentDirectory.DosPath, cwd);
        USRead64(h, upp.WindowTitle, wtitle); USRead64(h, upp.DesktopInfo, desk);
        USRead64(h, upp.ShellInfo, shell);    USRead64(h, upp.RuntimeData, rtd);
    }

    CloseHandle(h);

    // name: exe hint > from image path > QueryFullProcessImageName
    std::wstring name = (exeNameHint && *exeNameHint) ? exeNameHint : L"";
    if (name.empty() || name == L"(specified)") {
        if (!img.empty()) name = util::basenameW(img);
        else {
            HANDLE h2 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (h2) {
                wchar_t buf[32768]; DWORD n = _countof(buf);
                if (QueryFullProcessImageNameW(h2, 0, buf, &n)) name = util::basenameW(buf);
                CloseHandle(h2);
            }
        }
    }

    out.name = name;
    out.imagePath = img;
    out.commandLine = cmd;
    out.currentDirectory = cwd;
    out.windowTitle = wtitle;
    out.desktopInfo = desk;
    out.shellInfo = shell;
    out.runtimeData = rtd;
    return true;
}
