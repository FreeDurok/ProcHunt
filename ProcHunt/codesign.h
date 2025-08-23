#pragma once
#include <string>

struct SignInfo {
    bool trusted = false;            // WinVerifyTrust == ERROR_SUCCESS
    std::wstring trustStatus;        // textual status / code
    std::wstring publisher;          // Subject (simple display)
    std::wstring thumbprint;         // SHA1 hex
};

// Verify file signature and extract publisher/thumbprint.
// Uses WinVerifyTrust (UI-less, cache-only URL retrieval).
SignInfo VerifyFileSignature(const std::wstring& filePath);
