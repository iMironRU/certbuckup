#include "backup.h"

#include <windows.h>
#include <sddl.h>

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

// Снимает признак неэкспортируемости в буфере header.key: байт 25, бит 0x80
// (см. память export-flag-and-header-checksum). Работает только на сборках CSP
// без контроля целостности заголовка (гейт по версии - в UI). Возвращает
// false, если структура не та (не трогаем).
bool ClearExportFlagInFiles(std::vector<ContainerFile>* files) {
    for (ContainerFile& f : *files) {
        if (f.name == L"header.key") {
            if (f.data.size() <= 25) return false;
            f.data[25] |= 0x80;
            return true;
        }
    }
    return false;
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
                            const std::wstring& targetBase, bool overwrite,
                            bool clearExportFlag) {
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

    if (clearExportFlag) ClearExportFlagInFiles(&r.files);

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

namespace {

// SID текущего пользователя строкой (S-1-5-...). Реестровые контейнеры
// КриптоПро лежат по-пользовательски.
std::wstring CurrentUserSid() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return L"";
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    std::wstring sid;
    if (len && GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) {
        TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &s)) {
            sid = s;
            LocalFree(s);
        }
    }
    CloseHandle(tok);
    return sid;
}

// Путь ключа контейнера в реестре. 32-битный процесс: HKLM\SOFTWARE сам
// редиректится в WOW6432Node, где КриптоПро и держит контейнеры.
std::wstring RegKeyPath(const std::wstring& sid, const std::wstring& name) {
    return L"SOFTWARE\\Crypto Pro\\Settings\\USERS\\" + sid + L"\\Keys\\" + name;
}

}  // namespace

BackupResult BackupToRegistry(const ContainerInfo& c, bool overwrite,
                              bool clearExportFlag) {
    BackupResult r;
    std::wstring subj = c.subjectCN + L" / " + c.Inn();

    if (c.medium == KeyMedium::HardWare) {
        r.message = L"Контейнер аппаратный — копировать нечего.";
        return r;
    }
    if (c.medium != KeyMedium::FileToken || c.folderId < 0) {
        r.message = L"В реестр копируется только файловый контейнер с токена.";
        return r;
    }

    r.reader = FindReaderForFolder(c.folderId);
    if (r.reader.empty()) {
        r.message = L"Не найден токен с контейнером — переподключите носитель.";
        return r;
    }
    std::wstring err;
    if (!ReadContainer(r.reader, c.folderId, &r.files, &err)) {
        r.message = L"Ошибка чтения контейнера: " + err;
        return r;
    }

    std::wstring sid = CurrentUserSid();
    if (sid.empty()) {
        r.message = L"Не удалось определить SID пользователя.";
        return r;
    }
    r.name83 = Name83(c);
    std::wstring path = RegKeyPath(sid, r.name83);
    r.dest = L"реестр: " + r.name83;

    // Уже есть?
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &h) ==
        ERROR_SUCCESS) {
        RegCloseKey(h);
        if (!overwrite) {
            r.skipped = true;
            r.message = L"Контейнер уже есть в реестре: " + r.name83;
            JournalOp(L"backup-reg", subj, c.thumbprint, r.reader, r.dest,
                      L"пропуск: уже существует");
            return r;
        }
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.c_str());
    }

    HKEY key = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0,
                              KEY_WRITE, nullptr, &key, nullptr);
    if (rc != ERROR_SUCCESS) {
        r.message = (rc == ERROR_ACCESS_DENIED)
                        ? L"Нет прав на запись в реестр — запустите от "
                          L"администратора."
                        : L"Ошибка создания ключа реестра.";
        JournalOp(L"backup-reg", subj, c.thumbprint, r.reader, r.dest,
                  L"ошибка: " + r.message);
        return r;
    }

    if (clearExportFlag) ClearExportFlagInFiles(&r.files);

    for (const ContainerFile& f : r.files) {
        RegSetValueExW(key, f.name.c_str(), 0, REG_BINARY, f.data.data(),
                       static_cast<DWORD>(f.data.size()));
    }
    RegCloseKey(key);

    JournalOp(L"backup-reg", subj, c.thumbprint, r.reader, r.dest, L"OK");
    r.ok = true;
    r.message = L"Скопировано в реестр: " + r.name83;
    return r;
}

bool RegistryContainerExists(const ContainerInfo& c) {
    std::wstring sid = CurrentUserSid();
    if (sid.empty()) return false;
    std::wstring path = RegKeyPath(sid, Name83(c));
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &h) ==
        ERROR_SUCCESS) {
        RegCloseKey(h);
        return true;
    }
    return false;
}

}  // namespace certmig
