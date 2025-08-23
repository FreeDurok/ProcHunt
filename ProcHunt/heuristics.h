#pragma once
#include <string>
#include <vector>
#include "codesign.h"

namespace heur {
    struct Result {
        int score = 0;
        std::vector<std::wstring> reasons;
    };

    void SetPublisherWhitelist(const std::vector<std::wstring>& pubs);
    void SetPathWhitelist(const std::vector<std::wstring>& paths);

    Result EvaluateProcess(const std::wstring& imagePath,
        const std::wstring& commandLine,
        const std::wstring& currentDir,
        const std::wstring& processName,
        const SignInfo& sig);
} // namespace heur
