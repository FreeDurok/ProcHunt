#pragma once
#include <windows.h>
#include <string>

struct ProcParams {
    std::wstring name;
    std::wstring imagePath;
    std::wstring commandLine;
    std::wstring currentDirectory;
    std::wstring windowTitle;
    std::wstring desktopInfo;
    std::wstring shellInfo;
    std::wstring runtimeData;
};

// Legge PEB → RTL_USER_PROCESS_PARAMETERS e risolve `name`.
bool ReadProcParams(DWORD pid, const wchar_t* exeNameHint, ProcParams& out);
