#pragma once
#include <string>
#include <vector>

namespace util {
	std::wstring lcase(const std::wstring& s);
	bool iequals(const std::wstring& a, const std::wstring& b);
	bool icmp(const std::wstring& a, const std::wstring& b);

	std::wstring basenameW(const std::wstring& path);
	std::wstring dirnameW(const std::wstring& path);
	const wchar_t* BasenamePtr(const wchar_t* path);
	std::wstring rstrip_slash(const std::wstring& p);
	std::wstring replace_common_lookalikes(std::wstring s);

	// JSON
	std::wstring json_escape(const std::wstring& s);

	// IO
	bool load_list_file(const std::wstring& path, std::vector<std::wstring>& out);
} // namespace util
