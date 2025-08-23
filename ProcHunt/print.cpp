// SPDX-License-Identifier: MIT
#include <string>
#include "print.h"
#include "output.h"
#include "utils.h"

void PrintUsage(const wchar_t* exe) {
    const wchar_t* me = util::BasenamePtr(exe);
    OutPrintf(L"Usage:\n");
    OutPrintf(L"  %s            (enumerate all processes)\n", me);
    OutPrintf(L"  %s -a         (enumerate all processes)\n", me);
    OutPrintf(L"  %s -p <pid>   (single specified PID)\n", me);
    OutPrintf(L"  %s --pid <pid>\n", me);
    OutPrintf(L"Options:\n");
    OutPrintf(L"  --json                         Output JSON\n");
    OutPrintf(L"  --whitelist-pub <file>         Whitelist publishers (one per line)\n");
    OutPrintf(L"  --whitelist-path <file>        Whitelist path prefixes (one per line)\n");
    OutPrintf(L"  --min-score <0-100>            Show only items with score >= threshold\n");
    OutPrintf(L"  --threshold <0-100>            Alias of --min-score\n");
    OutPrintf(L"  -t <0-100>                     Alias of --min-score\n");
    OutPrintf(L"  -o, --output <file>            Write output to file (UTF-8)\n");
}

void PrintText(
    unsigned long pid, const std::wstring& name,
    const std::wstring& img, const std::wstring& cmd, const std::wstring& cwd,
    const std::wstring& wtitle, const std::wstring& desk, const std::wstring& shell, const std::wstring& rtd,
    const SignInfo& sig, const heur::Result& heur)
{
    OutPrintf(L"\nPID %-6lu  %-30s\n", pid, name.empty() ? L"(unknown)" : name.c_str());
    if (!img.empty())    OutPrintf(L"  ImagePathName    : %s\n", img.c_str());
    if (!cmd.empty())    OutPrintf(L"  CommandLine      : %s\n", cmd.c_str());
    if (!cwd.empty())    OutPrintf(L"  CurrentDirectory : %s\n", cwd.c_str());
    if (!wtitle.empty()) OutPrintf(L"  WindowTitle      : %s\n", wtitle.c_str());
    if (!desk.empty())   OutPrintf(L"  DesktopInfo      : %s\n", desk.c_str());
    if (!shell.empty())  OutPrintf(L"  ShellInfo        : %s\n", shell.c_str());
    if (!rtd.empty())    OutPrintf(L"  RuntimeData      : %s\n", rtd.c_str());
    OutPrintf(L"  Signature        : %s (%s)\n", sig.trusted ? L"VALID" : L"INVALID/UNSIGNED", sig.trustStatus.c_str());
    if (!sig.publisher.empty())  OutPrintf(L"  Publisher        : %s\n", sig.publisher.c_str());
    if (!sig.thumbprint.empty()) OutPrintf(L"  Thumbprint       : %s\n", sig.thumbprint.c_str());
    OutPrintf(L"  SuspicionScore   : %d\n", heur.score);
    for (const auto& r : heur.reasons) OutPrintf(L"    - %s\n", r.c_str());
}

void PrintJsonObject(
    bool& first,
    unsigned long pid, const std::wstring& name,
    const std::wstring& img, const std::wstring& cmd, const std::wstring& cwd,
    const std::wstring& wtitle, const std::wstring& desk, const std::wstring& shell, const std::wstring& rtd,
    const SignInfo& sig, const heur::Result& heur)
{
    if (!first) OutPrintf(L",");
    first = false;
    OutPrintf(L"\n  {");
    OutPrintf(L"\"pid\":%lu,", pid);
    OutPrintf(L"\"name\":\"%s\",", util::json_escape(name).c_str());
    OutPrintf(L"\"imagePath\":\"%s\",", util::json_escape(img).c_str());
    OutPrintf(L"\"commandLine\":\"%s\",", util::json_escape(cmd).c_str());
    OutPrintf(L"\"currentDirectory\":\"%s\",", util::json_escape(cwd).c_str());
    OutPrintf(L"\"windowTitle\":\"%s\",", util::json_escape(wtitle).c_str());
    OutPrintf(L"\"desktopInfo\":\"%s\",", util::json_escape(desk).c_str());
    OutPrintf(L"\"shellInfo\":\"%s\",", util::json_escape(shell).c_str());
    OutPrintf(L"\"runtimeData\":\"%s\",", util::json_escape(rtd).c_str());
    OutPrintf(L"\"signature\":{");
    OutPrintf(L"\"trusted\":%s,", sig.trusted ? L"true" : L"false");
    OutPrintf(L"\"status\":\"%s\",", util::json_escape(sig.trustStatus).c_str());
    OutPrintf(L"\"publisher\":\"%s\",", util::json_escape(sig.publisher).c_str());
    OutPrintf(L"\"thumbprint\":\"%s\"},", util::json_escape(sig.thumbprint).c_str());
    OutPrintf(L"\"heuristics\":{");
    OutPrintf(L"\"score\":%d,", heur.score);
    OutPrintf(L"\"reasons\":[");
    for (size_t i = 0; i < heur.reasons.size(); ++i)
        OutPrintf(L"\"%s\"%s", util::json_escape(heur.reasons[i]).c_str(), (i + 1 < heur.reasons.size()) ? L"," : L"");
    OutPrintf(L"]}}");
}
