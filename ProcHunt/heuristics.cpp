#include "heuristics.h"
#include "utils.h"
#include <algorithm>
#include <regex>

using std::wstring;

namespace {
    std::vector<wstring> g_pub_wl = {
        L"Microsoft Windows", L"Microsoft Corporation", L"Microsoft Windows Publisher"
    };
    std::vector<wstring> g_path_wl = {
        L"C:\\Windows\\System32", L"C:\\Windows\\SysWOW64",
        L"C:\\Program Files", L"C:\\Program Files (x86)"
    };

    bool any_starts_with(const wstring& val, const std::vector<wstring>& prefixes) {
        auto lc = util::lcase(val);
        for (auto p : prefixes) {
            auto lcp = util::lcase(util::rstrip_slash(p));
            if (!lcp.empty() && lc.rfind(lcp, 0) == 0) return true;
        }
        return false;
    }
    bool any_equals_ci(const wstring& val, const std::vector<wstring>& items) {
        for (auto& it : items) if (util::iequals(val, it)) return true;
        return false;
    }
    bool has_any(const wstring& s, std::initializer_list<const wchar_t*> needles) {
        auto ls = util::lcase(s);
        for (auto n : needles) if (ls.find(util::lcase(n)) != wstring::npos) return true;
        return false;
    }
    bool path_in_user_writable(const wstring& p) {
        return has_any(p, { L"\\users\\", L"\\appdata\\", L"\\temp\\", L"\\downloads\\", L"\\public\\", L"\\tasks\\",
                           L"\\onedrive\\", L"\\recycle.bin\\", L"\\desktop\\", L"\\documents\\", L"\\programdata\\" });
    }
    bool path_is_unc(const wstring& p) {
        return p.rfind(L"\\\\", 0) == 0 || has_any(p, { L"http://", L"https://" });
    }
    bool path_is_temp_or_downloads(const wstring& p) {
        return has_any(p, { L"\\temp\\", L"\\tmp\\", L"\\downloads\\" });
    }
    bool path_is_system(const wstring& p) {
        return has_any(p, { L"\\windows\\system32\\", L"\\windows\\syswow64\\", L"\\program files\\", L"\\program files (x86)\\" });
    }
    bool masquerading(const wstring& name, const wstring& imgDir) {
        static const wchar_t* sysNames[] = { L"svchost.exe", L"lsass.exe", L"services.exe", L"winlogon.exe",
                                            L"explorer.exe", L"smss.exe", L"taskhostw.exe" };
        auto lname = util::lcase(name);
        for (auto n : sysNames) if (lname == util::lcase(n) && !path_is_system(imgDir)) return true;
        if (util::replace_common_lookalikes(lname) != lname) return true;
        return false;
    }
    bool cmd_has_lolbins(const wstring& cmd) {
        return has_any(cmd, { L"powershell", L" -enc", L"-w hidden", L"-nop", L"iex ",
                             L"wscript", L"cscript", L".js ", L".vbs ",
                             L"mshta", L"javascript:", L"vbscript:",
                             L"rundll32 ", L"regsvr32 /s", L"/i:http", L"scrobj.dll",
                             L"certutil -urlcache", L"bitsadmin /transfer",
                             L"curl ", L"wget ", L"invoke-webrequest",
                             L"schtasks /create", L"reg add ", L"netsh add helper",
                             L"add-mppreference -exclusionpath" });
    }
    bool cmd_obfuscated(const wstring& orig) {
        if (orig.size() > 4096) return true;
        static std::wregex b64(LR"(([A-Za-z0-9+/]{120,}={0,2}))");
        return std::regex_search(orig, b64);
    }
} // anon

namespace heur {

    void SetPublisherWhitelist(const std::vector<std::wstring>& pubs) {
        for (auto& p : pubs) if (!p.empty()) g_pub_wl.push_back(p);
    }
    void SetPathWhitelist(const std::vector<std::wstring>& paths) {
        for (auto& p : paths) if (!p.empty()) g_path_wl.push_back(p);
    }

    Result EvaluateProcess(const wstring& imagePath,
        const wstring& commandLine,
        const wstring& currentDir,
        const wstring& processName,
        const SignInfo& sig)
    {
        Result r{};
        const wstring img = util::lcase(imagePath);
        const wstring cmd = util::lcase(commandLine);
        const wstring cwd = util::lcase(currentDir);
        const wstring name = util::lcase(processName);
        const wstring imgDir = util::dirnameW(img);

        // Whitelists (early exits reduce score)
        bool pathWhitelisted = any_starts_with(imagePath, g_path_wl);
        bool pubWhitelisted = (!sig.publisher.empty() && any_equals_ci(sig.publisher, g_pub_wl));

        // 1) Image path in user-writable
        if (!img.empty() && path_in_user_writable(img)) { r.score += 40; r.reasons.push_back(L"Image in user-writable path"); }
        // 2) UNC/Web
        if (!img.empty() && path_is_unc(img)) { r.score += 35; r.reasons.push_back(L"Image on UNC/Web path"); }
        // 3) CurrentDirectory anomalies
        if (!cwd.empty()) {
            if (path_is_temp_or_downloads(cwd) || path_is_unc(cwd)) { 
                r.score += 25; r.reasons.push_back(L"CWD in Temp/Downloads/UNC"); 
            }
            if (!img.empty() && !path_is_system(img) && util::icmp(util::rstrip_slash(imgDir), util::rstrip_slash(cwd)) == false) {
                r.score += 10; r.reasons.push_back(L"CWD != executable directory");
            }
            if (!img.empty() && !path_is_system(img) && cwd.find(L"\\windows\\system32") != wstring::npos) {
                r.score += 10; r.reasons.push_back(L"Non-system binary with System32 as CWD");
            }
        }
        // 4) Masquerading
        if (masquerading(name.empty() ? util::basenameW(img) : name, imgDir)) { r.score += 25; r.reasons.push_back(L"Masquerading name/location"); }

        // 5) Command line
        if (cmd_has_lolbins(cmd)) { r.score += 30; r.reasons.push_back(L"LOLBin/suspicious command line"); }
        if (cmd_obfuscated(commandLine)) { r.score += 20; r.reasons.push_back(L"Obfuscated/encoded command line"); }

        // 6) Name mismatch
        if (!img.empty()) {
            auto base = util::basenameW(img);
            if (!name.empty() && !util::iequals(name, util::lcase(base))) { r.score += 10; r.reasons.push_back(L"Process name != image basename"); }
        }

        // 7) Signature
        if (sig.trusted) {
            r.reasons.push_back(L"Signature: VALID");
            if (pubWhitelisted) r.reasons.push_back(L"Publisher whitelisted");
            // reduce score if trusted & whitelisted path/publisher
            if (pubWhitelisted || pathWhitelisted) r.score = std::max(0, r.score - 30);
        }
        else {
            r.reasons.push_back(L"Signature: INVALID/UNSIGNED");
            r.score += 30;
        }

        // 8) Path whitelist final tweak
        if (pathWhitelisted) r.reasons.push_back(L"Path whitelisted");

        if (r.score < 0) r.score = 0; if (r.score > 100) r.score = 100;
        if (r.reasons.empty()) r.reasons.push_back(L"No obvious indicators");
        return r;
    }
} // namespace heur
