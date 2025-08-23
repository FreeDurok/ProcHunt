#include "codesign.h"
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

static std::wstring ToHex(const BYTE* data, DWORD len) {
    static const wchar_t* hex = L"0123456789ABCDEF";
    std::wstring out; out.reserve(len * 2);
    for (DWORD i = 0; i < len; ++i) { out.push_back(hex[(data[i] >> 4) & 0xF]); out.push_back(hex[data[i] & 0xF]); }
    return out;
}
static std::wstring StatusToText(LONG st) {
    switch (st) {
    case ERROR_SUCCESS: return L"ERROR_SUCCESS";
    case TRUST_E_NOSIGNATURE: return L"TRUST_E_NOSIGNATURE";
    case TRUST_E_EXPLICIT_DISTRUST: return L"TRUST_E_EXPLICIT_DISTRUST";
    case TRUST_E_SUBJECT_NOT_TRUSTED: return L"TRUST_E_SUBJECT_NOT_TRUSTED";
    case CRYPT_E_SECURITY_SETTINGS: return L"CRYPT_E_SECURITY_SETTINGS";
    default: { wchar_t buf[32]; _snwprintf_s(buf, _TRUNCATE, L"0x%08X", (unsigned)st); return buf; }
    }
}

SignInfo VerifyFileSignature(const std::wstring& filePath) {
    SignInfo info{};
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO wfi{}; wfi.cbStruct = sizeof(wfi);
    wfi.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA wtd{}; wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &wfi;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(nullptr, &action, &wtd);
    info.trusted = (status == ERROR_SUCCESS);
    info.trustStatus = StatusToText(status);

    if (wtd.hWVTStateData) {
        auto provData = WTHelperProvDataFromStateData(wtd.hWVTStateData);
        if (provData) {
            auto signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
            if (signer && signer->csCertChain > 0) {
                auto& certData = signer->pasCertChain[signer->csCertChain - 1];
                PCCERT_CONTEXT pCert = certData.pCert;
                if (pCert) {
                    // Publisher (Subject simple display)
                    DWORD cch = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                    if (cch > 1) {
                        std::wstring tmp(cch, L'\0');
                        CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, &tmp[0], cch);
                        if (!tmp.empty() && tmp.back() == L'\0') tmp.pop_back();
                        info.publisher = tmp;
                    }
                    // Thumbprint (SHA1)
                    DWORD cb = 0;
                    if (CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, nullptr, &cb) && cb > 0) {
                        std::vector<BYTE> buf(cb);
                        if (CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, buf.data(), &cb))
                            info.thumbprint = ToHex(buf.data(), cb);
                    }
                }
            }
        }
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &wtd);
    }
    return info;
}
