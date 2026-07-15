#include "backup.h"

#include <windows.h>

#include "journal.h"
#include "rutoken.h"

namespace certmig {

namespace {

std::wstring ExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, n);
    size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? L"." : path.substr(0, slash);
}

std::wstring FolderInn(const ContainerInfo& c) {
    if (!c.innLe.empty()) return c.innLe;
    if (!c.inn.empty()) return c.inn;
    return L"noinn";
}

std::wstring MMYY(const FILETIME& ft) {
    FILETIME local;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&ft, &local) ||
        !FileTimeToSystemTime(&local, &st))
        return L"0000";
    wchar_t buf[8];
    swprintf(buf, 8, L"%02u%02u", st.wMonth, st.wYear % 100);
    return buf;
}

// 8.3-имя контейнера для CryptoPro: первые 8 hex от thumbprint (FAT12-профиль).
std::wstring Name83(const ContainerInfo& c) {
    if (c.thumbprint.size() >= 8) return c.thumbprint.substr(0, 8);
    if (c.folderId >= 0) {
        wchar_t buf[12];
        swprintf(buf, 12, L"%08X", c.folderId);
        return buf;
    }
    return L"CONT0001";
}

bool EnsureDir(const std::wstring& path) {
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

bool WriteBytes(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()),
                        &written, nullptr) &&
              written == data.size();
    CloseHandle(h);
    return ok;
}

void AppendIndex(const std::wstring& targetBase, const ContainerInfo& c,
                 const std::wstring& human, const std::wstring& name83) {
    std::wstring path = targetBase + L"\\index.csv";
    bool isNew = GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;

    std::wstring fio = c.surname.empty() && c.given.empty()
                           ? c.subjectCN
                           : c.surname + L" " + c.given;
    std::wstring row;
    if (isNew)
        row += L"ИНН;Владелец;Действует до;Thumbprint;Папка;Контейнер\r\n";
    row += c.Inn() + L";" + fio + L";" + FormatDate(c.notAfter) + L";" +
           c.thumbprint + L";" + human + L";" + name83 + L"\r\n";

    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    int need = WideCharToMultiByte(CP_UTF8, 0, row.c_str(), -1, nullptr, 0,
                                   nullptr, nullptr);
    std::string utf8(need > 0 ? need - 1 : 0, '\0');
    if (need > 0)
        WideCharToMultiByte(CP_UTF8, 0, row.c_str(), -1, &utf8[0], need, nullptr,
                            nullptr);
    DWORD w = 0;
    SetFilePointer(h, 0, nullptr, FILE_END);
    if (isNew) {
        const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
        WriteFile(h, bom, 3, &w, nullptr);
    }
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &w, nullptr);
    CloseHandle(h);
}

// Ридер rtComLite, на котором лежит папка folderId (имена не совпадают с FQCN).
std::wstring FindReaderForFolder(int folderId) {
    for (const std::wstring& r : EnumReaders()) {
        TokenScan s = ScanToken(r);
        if (s.ok && s.containerFolders.count(folderId)) return r;
    }
    return L"";
}

// Удаляет папку с содержимым (для перезаписи существующей копии). Рекурсивно,
// но на практике внутри только .key-файлы.
void RemoveDirRecursive(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring full = dir + L"\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveDirRecursive(full);
            else
                DeleteFileW(full.c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

}  // namespace

std::wstring DefaultBackupDir() { return ExeDir() + L"\\cert"; }

std::wstring BackupTargetPath(const ContainerInfo& c,
                              const std::wstring& targetBase) {
    return targetBase + L"\\" + FolderInn(c) + L"." + MMYY(c.notAfter) + L"\\" +
           Name83(c);
}

BackupResult BackupToFolder(const ContainerInfo& c,
                            const std::wstring& targetBase, bool overwrite) {
    BackupResult r;
    std::wstring subj = c.subjectCN + L" / " + c.Inn();

    if (c.medium == KeyMedium::HardWare) {
        r.message = L"Контейнер аппаратный (ключ в чипе) — копировать нечего.";
        JournalOp(L"backup", subj, c.thumbprint, c.name, targetBase,
                  L"отказ: аппаратный ключ");
        return r;
    }
    if (c.medium != KeyMedium::FileToken || c.folderId < 0) {
        r.message = L"Копирование с токена доступно только для файловых "
                    L"контейнеров Рутокен.";
        return r;
    }

    r.reader = FindReaderForFolder(c.folderId);
    if (r.reader.empty()) {
        r.message = L"Не найден токен с контейнером — переподключите носитель.";
        JournalOp(L"backup", subj, c.thumbprint, c.name, targetBase,
                  L"ошибка: токен не найден");
        return r;
    }

    std::wstring err;
    if (!ReadContainer(r.reader, c.folderId, &r.files, &err)) {
        r.message = L"Ошибка чтения контейнера: " + err;
        JournalOp(L"backup", subj, c.thumbprint, r.reader, targetBase,
                  L"ошибка чтения: " + err);
        return r;
    }

    r.human = FolderInn(c) + L"." + MMYY(c.notAfter);
    r.name83 = Name83(c);
    std::wstring wrapper = targetBase + L"\\" + r.human;
    r.dest = wrapper + L"\\" + r.name83;

    if (!EnsureDir(targetBase) || !EnsureDir(wrapper)) {
        r.message = L"Не удалось создать папку: " + wrapper;
        return r;
    }
    if (GetFileAttributesW(r.dest.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (!overwrite) {
            r.skipped = true;
            r.message = L"Копия уже существует: " + r.dest;
            JournalOp(L"backup", subj, c.thumbprint, r.reader, r.dest,
                      L"пропуск: папка существует");
            return r;
        }
        RemoveDirRecursive(r.dest);  // перезапись по подтверждению оператора
    }
    if (!EnsureDir(r.dest)) {
        r.message = L"Не удалось создать папку контейнера: " + r.dest;
        return r;
    }

    for (const ContainerFile& f : r.files) {
        if (!WriteBytes(r.dest + L"\\" + f.name, f.data)) {
            r.message = L"Не удалось записать файл: " + f.name;
            JournalOp(L"backup", subj, c.thumbprint, r.reader, r.dest,
                      L"ошибка записи: " + f.name);
            return r;
        }
    }

    AppendIndex(targetBase, c, r.human, r.name83);
    JournalOp(L"backup", subj, c.thumbprint, r.reader, r.dest, L"OK");
    r.ok = true;
    r.message = L"Скопировано: " + r.dest;
    return r;
}

}  // namespace certmig
