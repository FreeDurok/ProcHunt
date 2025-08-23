#include "utils.h"
#include <algorithm>
#include <cwchar>
#include <cstdio>
#include <windows.h>
#include <vector>

namespace util {
    std::wstring lcase(const std::wstring& s) { std::wstring o = s; std::transform(o.begin(), o.end(), o.begin(), ::towlower); return o; }
    bool iequals(const std::wstring& a, const std::wstring& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) if (::towlower(a[i]) != ::towlower(b[i])) return false;
        return true;
    }
    bool icmp(const std::wstring& a, const std::wstring& b) { return iequals(a, b); }

    std::wstring basenameW(const std::wstring& path) {
        size_t p1 = path.find_last_of(L'\\'), p2 = path.find_last_of(L'/');
        size_t p = (p1 == std::wstring::npos) ? p2 : ((p2 == std::wstring::npos) ? p1 : std::max<size_t>(p1, p2));
        if (p == std::wstring::npos) return path; return path.substr(p + 1);
    }
    const wchar_t* BasenamePtr(const wchar_t* path) {
        if (!path) return L"";
        const wchar_t* b1 = wcsrchr(path, L'\\'); const wchar_t* b2 = wcsrchr(path, L'/');
        const wchar_t* b = (b1 && (!b2 || b1 > b2)) ? b1 : b2;
        return b ? b + 1 : path;
    }
    std::wstring dirnameW(const std::wstring& path) {
        size_t p1 = path.find_last_of(L'\\'), p2 = path.find_last_of(L'/');
        size_t p = (p1 == std::wstring::npos) ? p2 : ((p2 == std::wstring::npos) ? p1 : std::max<size_t>(p1, p2));
        if (p == std::wstring::npos) return L""; return path.substr(0, p);
    }
    std::wstring rstrip_slash(const std::wstring& p) {
        std::wstring s = p; while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) s.pop_back(); return s;
    }
    std::wstring replace_common_lookalikes(std::wstring s) {
        for (auto& ch : s) {
            switch (ch) {
            case L'0': ch = L'o'; break; case L'1': ch = L'l'; break;
            case L'5': ch = L's'; break; case L'3': ch = L'e'; break; case L'7': ch = L't'; break; default: break;
            }
        }
        return s;
    }

    std::wstring json_escape(const std::wstring& s) {
        std::wstring o; o.reserve(s.size() + 8);
        for (wchar_t c : s) {
            switch (c) {
            case L'\\': o += L"\\\\"; break;
            case L'"':  o += L"\\\""; break;
            case L'\b': o += L"\\b"; break;
            case L'\f': o += L"\\f"; break;
            case L'\n': o += L"\\n"; break;
            case L'\r': o += L"\\r"; break;
            case L'\t': o += L"\\t"; break;
            default:
                if (c < 0x20) { wchar_t buf[7]; _snwprintf_s(buf, _TRUNCATE, L"\\u%04X", (unsigned)c); o += buf; }
                else o.push_back(c);
            }
        }
        return o;
    }

    bool load_list_file(const std::wstring& path, std::vector<std::wstring>& out) {
        if (path.empty()) return false;
        FILE* f = nullptr;
#if defined(_MSC_VER)
        _wfopen_s(&f, path.c_str(), L"rt, ccs=UTF-8");
#else
        f = _wfopen(path.c_str(), L"rt, ccs=UTF-8");
#endif
        if (!f) return false;
        wchar_t line[4096];
        while (fgetws(line, _countof(line), f)) {
            std::wstring s(line);
            // trim
            while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' ' || s.back() == L'\t')) s.pop_back();
            size_t start = 0; while (start < s.size() && (s[start] == L' ' || s[start] == L'\t')) ++start;
            s = s.substr(start);
            if (s.empty() || s[0] == L'#' || s[0] == L';') continue;
            out.push_back(s);
        }
        fclose(f);
        return true;
    }
} // namespace util
