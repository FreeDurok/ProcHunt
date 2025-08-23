#pragma once
#include <string>

// Inizializza output: "" => stdout, altrimenti file UTF-8 (wb). Setta console CP=UTF-8.
void OutInit(const std::wstring& outPath);

// Flush/chiude file se necessario.
void OutClose();

// printf wide → bytes UTF-8 (stdout/file)
void OutPrintf(const wchar_t* fmt, ...);
