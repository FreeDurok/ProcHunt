// SPDX-License-Identifier: MIT
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <cstdarg>
#include <cstdio>
#include <string>

#include "output.h"

static FILE* g_out = stdout;

static std::string W2U8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static void u8vprint(FILE* f, const wchar_t* fmt, va_list ap) {
    va_list ap_len;
#ifdef _MSC_VER
    ap_len = ap;
#else
    va_copy(ap_len, ap);
#endif
    int need = _vscwprintf(fmt, ap_len);
#ifndef _MSC_VER
    va_end(ap_len);
#endif
    if (need < 0) return;
    std::wstring w((size_t)need + 1, L'\0');
    vswprintf_s(&w[0], w.size(), fmt, ap);
    w.resize((size_t)need);
    auto u8 = W2U8(w);
    fwrite(u8.data(), 1, u8.size(), f);
}

void OutInit(const std::wstring& outPath) {
    _setmode(_fileno(stdout), _O_BINARY);
    if (outPath.empty()) {
        g_out = stdout;
        SetConsoleOutputCP(CP_UTF8); // best-effort console UTF-8
    }
    else {
        if (_wfopen_s(&g_out, outPath.c_str(), L"wb") != 0 || !g_out) {
            fwprintf(stderr, L"Cannot open output file: %s\n", outPath.c_str());
            g_out = stdout;
        }
    }
}
void OutClose() {
    if (g_out && g_out != stdout) { fclose(g_out); g_out = stdout; }
    fflush(stdout);
}
void OutPrintf(const wchar_t* fmt, ...) {
    va_list ap; va_start(ap, fmt); u8vprint(g_out, fmt, ap); va_end(ap);
}
