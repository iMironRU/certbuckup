#include "journal.h"

#include <windows.h>

#include <string>
#include <vector>

namespace certmig {

namespace {

std::wstring ExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, n);
    size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? L"." : path.substr(0, slash);
}

std::string ToUtf8(const std::wstring& s) {
    if (s.empty()) return "";
    int need = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0,
                                   nullptr, nullptr);
    std::string out(need > 0 ? need - 1 : 0, '\0');
    if (need > 0)
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &out[0], need, nullptr,
                            nullptr);
    return out;
}

std::wstring TimeStamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf(buf, 32, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth,
             st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// Заменяет разделители, чтобы одно поле не разорвало строку журнала.
std::wstring Clean(const std::wstring& s) {
    std::wstring out = s;
    for (wchar_t& ch : out) {
        if (ch == L'\n' || ch == L'\r' || ch == L'\t' || ch == L'|') ch = L' ';
    }
    return out;
}

}  // namespace

std::wstring JournalPath() {
    return ExeDir() + L"\\cert-migrator-journal.log";
}

void JournalOp(const std::wstring& op, const std::wstring& subject,
               const std::wstring& thumb, const std::wstring& from,
               const std::wstring& to, const std::wstring& result) {
    std::wstring line = TimeStamp() + L"\t" + Clean(op) + L"\t" +
                        Clean(subject) + L"\t" + Clean(thumb) + L"\t" +
                        Clean(from) + L" -> " + Clean(to) + L"\t" +
                        Clean(result) + L"\r\n";

    // Только дополнение. FILE_APPEND_DATA без FILE_WRITE_DATA - процесс не
    // может перезаписать уже записанное, только добавить в конец.
    HANDLE h = CreateFileW(JournalPath().c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    std::string utf8 = ToUtf8(line);
    DWORD written = 0;
    SetFilePointer(h, 0, nullptr, FILE_END);
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written,
              nullptr);
    CloseHandle(h);
}

}  // namespace certmig
