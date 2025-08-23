// SPDX-License-Identifier: MIT
// build (x64):
//   cl /EHsc /W4 /permissive- /std:c++17 /DUNICODE /D_UNICODE ProcHunt.cpp proc_peb.cpp print.cpp output.cpp ntdll.lib wintrust.lib crypt32.lib
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cwchar>
#include <cstdio>

#include "heuristics.h"
#include "utils.h"
#include "codesign.h"
#include "proc_peb.h"
#include "print.h"
#include "output.h"

#define TOOL_NAME   L"ProcHunt - Heuristic Process Hunter"
#define TOOL_AUTHOR L"Author: @Alessio Carletti"

static bool g_json = false;
static int  g_min_score = -1;
static std::wstring g_out_path;

static bool EnablePrivilege(LPCWSTR name) {
    HANDLE tok{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) { CloseHandle(tok); return false; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(tok);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static void PrintUsageTop(const wchar_t* exe) {
    OutPrintf(L"\n========================================\n");
    OutPrintf(L"%s\n%s\n", TOOL_NAME, TOOL_AUTHOR);
    OutPrintf(L"========================================\n");
    PrintUsage(exe);
}

int wmain(int argc, wchar_t** argv) {
    EnablePrivilege(L"SeDebugPrivilege");

    bool listAll = true;
    DWORD targetPid = 0;
    std::vector<std::wstring> wlPub, wlPath;

    for (int i = 1; i < argc; ++i) {
        if (!_wcsicmp(argv[i], L"-h") || !_wcsicmp(argv[i], L"--help")) {
            OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 0;
        }
        else if (!_wcsicmp(argv[i], L"-a") || !_wcsicmp(argv[i], L"--all")) {
            listAll = true;
        }
        else if (!_wcsicmp(argv[i], L"-p") || !_wcsicmp(argv[i], L"--pid")) {
            if (i + 1 >= argc) { OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 1; }
            targetPid = _wtoi(argv[++i]); listAll = false;
        }
        else if (!_wcsicmp(argv[i], L"--json")) {
            g_json = true;
        }
        else if (!_wcsicmp(argv[i], L"--whitelist-pub")) {
            if (i + 1 >= argc) { OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 1; }
            util::load_list_file(argv[++i], wlPub);
        }
        else if (!_wcsicmp(argv[i], L"--whitelist-path")) {
            if (i + 1 >= argc) { OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 1; }
            util::load_list_file(argv[++i], wlPath);
        }
        else if (!_wcsicmp(argv[i], L"--min-score") || !_wcsicmp(argv[i], L"--threshold") || !_wcsicmp(argv[i], L"-t")) {
            if (i + 1 >= argc) { OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 1; }
            g_min_score = _wtoi(argv[++i]); if (g_min_score < 0) g_min_score = 0; if (g_min_score > 100) g_min_score = 100;
        }
        else if (!_wcsicmp(argv[i], L"-o") || !_wcsicmp(argv[i], L"--output")) {
            if (i + 1 >= argc) { OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 1; }
            g_out_path = argv[++i];
        }
        else {
            OutInit(L""); PrintUsageTop(argv[0]); OutClose(); return 1;
        }
    }

    heur::SetPublisherWhitelist(wlPub);
    heur::SetPathWhitelist(wlPath);

    // Init output (UTF-8). If path=="" -> stdout, else file.
    OutInit(g_out_path);

    bool firstJson = true;
    if (g_json && listAll) OutPrintf(L"[");

    auto handle_one = [&](DWORD pid, const wchar_t* exeName) {
        ProcParams pp{};
        if (!ReadProcParams(pid, exeName, pp)) return;

        SignInfo sig{};
        if (!pp.imagePath.empty()) sig = VerifyFileSignature(pp.imagePath);

        auto res = heur::EvaluateProcess(pp.imagePath, pp.commandLine, pp.currentDirectory, pp.name, sig);
        if (g_min_score >= 0 && res.score < g_min_score) return;

        if (!g_json) {
            PrintText(pid, pp.name, pp.imagePath, pp.commandLine, pp.currentDirectory,
                pp.windowTitle, pp.desktopInfo, pp.shellInfo, pp.runtimeData, sig, res);
        }
        else {
            PrintJsonObject(firstJson, pid, pp.name, pp.imagePath, pp.commandLine, pp.currentDirectory,
                pp.windowTitle, pp.desktopInfo, pp.shellInfo, pp.runtimeData, sig, res);
        }
        };

    if (!listAll && targetPid) {
        handle_one(targetPid, L"(specified)");
        if (g_json && listAll) OutPrintf(L"]\n");
        OutClose();
        return 0;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        OutClose(); return 1;
    }
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            handle_one(pe.th32ProcessID, pe.szExeFile);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (g_json && listAll) OutPrintf(L"\n]\n");
    OutClose();
    return 0;
}
