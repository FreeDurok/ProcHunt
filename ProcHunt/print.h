#pragma once
#include <string>
#include "codesign.h"
#include "heuristics.h"

void PrintUsage(const wchar_t* exe);

void PrintText(
    unsigned long pid, const std::wstring& name,
    const std::wstring& img, const std::wstring& cmd, const std::wstring& cwd,
    const std::wstring& wtitle, const std::wstring& desk, const std::wstring& shell, const std::wstring& rtd,
    const SignInfo& sig, const heur::Result& heur);

void PrintJsonObject(
    bool& first,
    unsigned long pid, const std::wstring& name,
    const std::wstring& img, const std::wstring& cmd, const std::wstring& cwd,
    const std::wstring& wtitle, const std::wstring& desk, const std::wstring& shell, const std::wstring& rtd,
    const SignInfo& sig, const heur::Result& heur);
