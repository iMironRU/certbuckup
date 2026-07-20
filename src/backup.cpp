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

// Человекочитаемое имя контейнера из данных сертификата: организация, ИНН,
// срок. Вместо GUID-образной строки, которую показывает CryptoPro.
std::wstring AutoFriendlyName(const ContainerInfo& c) {
    std::wstring org = !c.subjectO.empty() ? c.subjectO : c.subjectCN;
    std::wstring inn = !c.innLe.empty() ? c.innLe : c.inn;
    std::wstring name = org;
    if (!inn.empty()) name += L" " + inn;
    // Срок: до ММ.ГГГГ.
    FILETIME local;
    SYSTEMTIME st;
    if (FileTimeToLocalFileTime(&c.notAfter, &local) &&
        FileTimeToSystemTime(&local, &st)) {
        wchar_t buf[16];
        swprintf(buf, 16, L" до %02u.%04u", st.wMonth, st.wYear);
        name += buf;
    }
    return name;
}

// Строит содержимое name.key с читаемым именем (CP1251), сохраняя исходный
// размер (добивка 0xFF). Формат: 30 <len+2> 16 <len> <строка CP1251> ...FF.
std::vector<BYTE> BuildNameKey(size_t origSize, const std::wstring& name) {
    int n = WideCharToMultiByte(1251, 0, name.c_str(), -1, nullptr, 0, nullptr,
                                nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 0)
        WideCharToMultiByte(1251, 0, name.c_str(), -1, &s[0], n, nullptr,
                            nullptr);
    if (s.size() > 250) s.resize(250);  // длина - один байт

    std::vector<BYTE> nk;
    nk.push_back(0x30);
    nk.push_back(static_cast<BYTE>(s.size() + 2));
    nk.push_back(0x16);
    nk.push_back(static_cast<BYTE>(s.size()));
    nk.insert(nk.end(), s.begin(), s.end());
    while (nk.size() < origSize) nk.push_back(0xFF);
    if (nk.size() > origSize && origSize > 0) nk.resize(origSize);
    return nk;
}

// Разбирает строку имени из содержимого name.key (обратно BuildNameKey).
std::wstring ParseNameKey(const std::vector<BYTE>& data) {
    if (data.size() < 4 || data[0] != 0x30 || data[2] != 0x16) return L"";
    size_t len = data[3];
    if (4 + len > data.size()) return L"";
    std::string s(reinterpret_cast<const char*>(data.data() + 4), len);
    int n = MultiByteToWideChar(1251, 0, s.c_str(), static_cast<int>(s.size()),
                                nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(1251, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

// Переписывает name.key в буфере файлов контейнера (для копирования).
void SetFriendlyName(std::vector<ContainerFile>* files,
                     const std::wstring& name) {
    for (ContainerFile& f : *files) {
        if (f.name == L"name.key") {
            f.data = BuildNameKey(f.data.size(), name);
            return;
        }
    }
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
                            bool clearExportFlag, bool renameReadable) {
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
    if (renameReadable) SetFriendlyName(&r.files, AutoFriendlyName(c));

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
                              bool clearExportFlag, bool renameReadable) {
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
    if (renameReadable) SetFriendlyName(&r.files, AutoFriendlyName(c));

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

std::wstring CryptoProStoreDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(buf, n) : L"";
    return base + L"\\Crypto Pro";
}

// Имя папки дискового контейнера: <8.3>.000 - формат HDIMAGE КриптоПро.
static std::wstring CpContainerDir(const ContainerInfo& c) {
    return CryptoProStoreDir() + L"\\" + Name83(c) + L".000";
}

bool CryptoProStoreExists(const ContainerInfo& c) {
    return GetFileAttributesW(CpContainerDir(c).c_str()) !=
           INVALID_FILE_ATTRIBUTES;
}

BackupResult BackupToCryptoProStore(const ContainerInfo& c, bool overwrite,
                                    bool clearExportFlag, bool renameReadable) {
    BackupResult r;
    std::wstring subj = c.subjectCN + L" / " + c.Inn();

    if (c.medium == KeyMedium::HardWare) {
        r.message = L"Контейнер аппаратный — копировать нечего.";
        return r;
    }
    if (c.medium != KeyMedium::FileToken || c.folderId < 0) {
        r.message = L"В папку КриптоПро копируется только файловый контейнер "
                    L"с токена.";
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

    r.name83 = Name83(c);
    r.dest = CpContainerDir(c);

    if (GetFileAttributesW(r.dest.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (!overwrite) {
            r.skipped = true;
            r.message = L"Контейнер уже в папке КриптоПро: " + r.name83;
            JournalOp(L"backup-cp", subj, c.thumbprint, r.reader, r.dest,
                      L"пропуск: уже существует");
            return r;
        }
        RemoveDirRecursive(r.dest);
    }
    if (!EnsureDir(CryptoProStoreDir()) || !EnsureDir(r.dest)) {
        r.message = L"Не удалось создать папку: " + r.dest;
        return r;
    }

    if (clearExportFlag) ClearExportFlagInFiles(&r.files);
    if (renameReadable) SetFriendlyName(&r.files, AutoFriendlyName(c));

    for (const ContainerFile& f : r.files) {
        if (!WriteBytes(r.dest + L"\\" + f.name, f.data)) {
            r.message = L"Не удалось записать файл: " + f.name;
            JournalOp(L"backup-cp", subj, c.thumbprint, r.reader, r.dest,
                      L"ошибка записи: " + f.name);
            return r;
        }
    }

    JournalOp(L"backup-cp", subj, c.thumbprint, r.reader, r.dest, L"OK");
    r.ok = true;
    r.message = L"Скопировано в папку КриптоПро: " + r.name83;
    return r;
}

// --- Переименование дружественного имени контейнера на месте ---------------

namespace {

enum RenameKind { RK_NONE, RK_REGISTRY, RK_HDIMAGE };

// По уникальному имени (FQCN) определяет носитель и идентификатор хранилища:
//   REGISTRY\<имя>           -> ключ реестра Keys\<имя>
//   HDIMAGE\<папка>.000\...  -> папка %LOCALAPPDATA%\Crypto Pro\<папка>.000
RenameKind LocateContainer(const ContainerInfo& c, std::wstring* id) {
    std::vector<std::wstring> seg;
    std::wstring cur;
    for (wchar_t ch : c.uniqueName) {
        if (ch == L'\\') {
            if (!cur.empty()) seg.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) seg.push_back(cur);
    if (seg.size() >= 2) {
        if (_wcsicmp(seg[0].c_str(), L"REGISTRY") == 0) { *id = seg[1]; return RK_REGISTRY; }
        if (_wcsicmp(seg[0].c_str(), L"HDIMAGE") == 0) { *id = seg[1]; return RK_HDIMAGE; }
    }
    return RK_NONE;
}

std::wstring HdimageNameKeyPath(const std::wstring& folder) {
    return CryptoProStoreDir() + L"\\" + folder + L"\\name.key";
}

std::vector<BYTE> ReadFileBytes(const std::wstring& path) {
    std::vector<BYTE> data;
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return data;
    BYTE buf[1024];
    DWORD rd = 0;
    while (ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd)
        data.insert(data.end(), buf, buf + rd);
    CloseHandle(f);
    return data;
}

}  // namespace

std::wstring ReadableName(const ContainerInfo& c) { return AutoFriendlyName(c); }

bool NameLooksLikeGuid(const std::wstring& s) {
    if (s.size() < 16) return false;
    int hex = 0, other = 0;
    for (wchar_t ch : s) {
        if (ch == L'-' || ch == L' ' || ch == L'.' || ch == L'_') continue;
        bool ishex = (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
                     (ch >= L'A' && ch <= L'F');
        if (ishex) ++hex; else ++other;
    }
    return other == 0 && hex >= 16;  // только hex + разделители, длинная строка
}

bool RenameSupported(const ContainerInfo& c) {
    std::wstring id;
    return LocateContainer(c, &id) != RK_NONE;
}

std::wstring ReadCurrentFriendlyName(const ContainerInfo& c) {
    std::wstring id;
    RenameKind k = LocateContainer(c, &id);
    std::vector<BYTE> data;
    if (k == RK_REGISTRY) {
        std::wstring sid = CurrentUserSid();
        if (sid.empty()) return L"";
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegKeyPath(sid, id).c_str(), 0,
                          KEY_READ, &h) != ERROR_SUCCESS)
            return L"";
        DWORD cb = 0, type = 0;
        if (RegQueryValueExW(h, L"name.key", nullptr, &type, nullptr, &cb) ==
                ERROR_SUCCESS && cb) {
            data.resize(cb);
            RegQueryValueExW(h, L"name.key", nullptr, &type, data.data(), &cb);
        }
        RegCloseKey(h);
    } else if (k == RK_HDIMAGE) {
        data = ReadFileBytes(HdimageNameKeyPath(id));
    }
    return ParseNameKey(data);
}

RenameResult RenameContainerInPlace(const ContainerInfo& c,
                                    const std::wstring& newName) {
    RenameResult r;
    std::wstring id;
    RenameKind k = LocateContainer(c, &id);
    std::wstring subj = c.subjectCN + L" / " + c.Inn();

    if (k == RK_REGISTRY) {
        std::wstring sid = CurrentUserSid();
        if (sid.empty()) { r.message = L"Не удалось определить SID."; return r; }
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegKeyPath(sid, id).c_str(), 0,
                          KEY_READ | KEY_WRITE, &h) != ERROR_SUCCESS) {
            r.message = L"Нет доступа к реестру — запустите от администратора.";
            return r;
        }
        DWORD cb = 0, type = 0;
        RegQueryValueExW(h, L"name.key", nullptr, &type, nullptr, &cb);
        std::vector<BYTE> nk = BuildNameKey(cb ? cb : 300, newName);
        LONG rc = RegSetValueExW(h, L"name.key", 0, REG_BINARY, nk.data(),
                                 static_cast<DWORD>(nk.size()));
        RegCloseKey(h);
        if (rc != ERROR_SUCCESS) { r.message = L"Ошибка записи в реестр."; return r; }
    } else if (k == RK_HDIMAGE) {
        std::wstring path = HdimageNameKeyPath(id);
        std::vector<BYTE> old = ReadFileBytes(path);
        std::vector<BYTE> nk = BuildNameKey(old.empty() ? 300 : old.size(), newName);
        HANDLE w = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (w == INVALID_HANDLE_VALUE) {
            r.message = L"Не удалось открыть name.key для записи.";
            return r;
        }
        DWORD wr = 0;
        bool ok = WriteFile(w, nk.data(), static_cast<DWORD>(nk.size()), &wr,
                            nullptr);
        CloseHandle(w);
        if (!ok) { r.message = L"Ошибка записи name.key."; return r; }
    } else {
        r.message = L"Переименование этого носителя пока не поддерживается.";
        return r;
    }

    JournalOp(L"rename", subj, c.thumbprint, c.name, newName, L"OK");
    r.ok = true;
    r.message = L"Переименовано: " + newName;
    return r;
}

// --- Проверка и починка раскладки primary/masks -----------------------------

namespace {

// Где физически лежит копия и как читать/писать её файлы-значения.
struct CopyLoc {
    enum Kind { None, Reg, Dir } kind = None;
    std::wstring regName;  // для Reg: 8.3-имя ключа реестра
    std::wstring dir;      // для Dir: папка (HDIMAGE или FAT12) с .key-файлами
};

std::vector<std::wstring> SplitBackslash(const std::wstring& s) {
    std::vector<std::wstring> seg;
    std::wstring cur;
    for (wchar_t ch : s) {
        if (ch == L'\\') { if (!cur.empty()) seg.push_back(cur); cur.clear(); }
        else cur.push_back(ch);
    }
    if (!cur.empty()) seg.push_back(cur);
    return seg;
}

// FAT12-контейнер: файлы в папке <буква диска>\<номер>. Буква в FQCN не
// указана — сканируем логические диски в поиске папки с ключевыми файлами.
std::wstring FindFat12Dir(const std::wstring& folder) {
    wchar_t drives[256];
    DWORD n = GetLogicalDriveStringsW(255, drives);
    if (n == 0 || n > 255) return L"";
    for (wchar_t* p = drives; *p; p += wcslen(p) + 1) {
        std::wstring dir = std::wstring(p);  // оканчивается на "\\", напр. "D:\\"
        if (!dir.empty() && dir.back() != L'\\') dir += L'\\';
        dir += folder;
        if (GetFileAttributesW((dir + L"\\primary.key").c_str()) !=
            INVALID_FILE_ATTRIBUTES)
            return dir;
    }
    return L"";
}

CopyLoc LocateCopy(const ContainerInfo& c) {
    CopyLoc loc;
    std::vector<std::wstring> seg = SplitBackslash(c.uniqueName);
    if (seg.size() >= 2 && _wcsicmp(seg[0].c_str(), L"REGISTRY") == 0) {
        loc.kind = CopyLoc::Reg;
        loc.regName = seg[1];
    } else if (seg.size() >= 2 && _wcsicmp(seg[0].c_str(), L"HDIMAGE") == 0) {
        loc.kind = CopyLoc::Dir;
        loc.dir = CryptoProStoreDir() + L"\\" + seg[1];
    } else if (seg.size() >= 3 && _wcsicmp(seg[0].c_str(), L"FAT12") == 0) {
        std::wstring d = FindFat12Dir(seg[2]);
        if (!d.empty()) { loc.kind = CopyLoc::Dir; loc.dir = d; }
    }
    return loc;
}

std::vector<BYTE> ReadCopyValue(const CopyLoc& loc, const wchar_t* name) {
    if (loc.kind == CopyLoc::Reg) {
        std::wstring sid = CurrentUserSid();
        if (sid.empty()) return {};
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegKeyPath(sid, loc.regName).c_str(),
                          0, KEY_READ, &h) != ERROR_SUCCESS)
            return {};
        std::vector<BYTE> data;
        DWORD cb = 0, type = 0;
        if (RegQueryValueExW(h, name, nullptr, &type, nullptr, &cb) ==
                ERROR_SUCCESS && cb) {
            data.resize(cb);
            RegQueryValueExW(h, name, nullptr, &type, data.data(), &cb);
        }
        RegCloseKey(h);
        return data;
    }
    if (loc.kind == CopyLoc::Dir) return ReadFileBytes(loc.dir + L"\\" + name);
    return {};
}

bool WriteCopyValue(const CopyLoc& loc, const wchar_t* name,
                    const std::vector<BYTE>& data) {
    if (loc.kind == CopyLoc::Reg) {
        std::wstring sid = CurrentUserSid();
        if (sid.empty()) return false;
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegKeyPath(sid, loc.regName).c_str(),
                          0, KEY_WRITE, &h) != ERROR_SUCCESS)
            return false;
        LONG rc = RegSetValueExW(h, name, 0, REG_BINARY, data.data(),
                                 static_cast<DWORD>(data.size()));
        RegCloseKey(h);
        return rc == ERROR_SUCCESS;
    }
    if (loc.kind == CopyLoc::Dir) {
        std::wstring path = loc.dir + L"\\" + name;
        HANDLE w = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (w == INVALID_HANDLE_VALUE) return false;
        DWORD wr = 0;
        bool ok = WriteFile(w, data.data(), static_cast<DWORD>(data.size()), &wr,
                            nullptr) &&
                  wr == data.size();
        CloseHandle(w);
        return ok;
    }
    return false;
}

// Файл-«primary» по сигнатуре: 30 22 04 20 … (две 32-байтные части).
bool LooksPrimary(const std::vector<BYTE>& b) {
    return b.size() >= 4 && b[0] == 0x30 && b[1] == 0x22 && b[2] == 0x04 &&
           b[3] == 0x20;
}
// Файл-«masks» по сигнатуре: 30 36 04 20 …
bool LooksMasks(const std::vector<BYTE>& b) {
    return b.size() >= 4 && b[0] == 0x30 && b[1] == 0x36 && b[2] == 0x04 &&
           b[3] == 0x20;
}

}  // namespace

CopyLayout DetectCopyLayout(const ContainerInfo& c) {
    // Токенные и аппаратные контейнеры — источник истины, не копии.
    if (c.medium == KeyMedium::FileToken || c.medium == KeyMedium::HardWare)
        return CopyLayout::NotApplicable;
    CopyLoc loc = LocateCopy(c);
    if (loc.kind == CopyLoc::None) return CopyLayout::NotApplicable;

    std::vector<BYTE> pri = ReadCopyValue(loc, L"primary.key");
    std::vector<BYTE> mas = ReadCopyValue(loc, L"masks.key");
    if (pri.empty() || mas.empty()) return CopyLayout::Unknown;

    if (LooksMasks(pri) && LooksPrimary(mas)) return CopyLayout::Swapped;
    if (LooksPrimary(pri) && LooksMasks(mas)) return CopyLayout::Ok;
    return CopyLayout::Unknown;  // нестандартная структура — не трогаем
}

RepairResult RepairContainerLayout(const ContainerInfo& c) {
    RepairResult r;
    std::wstring subj = c.subjectCN + L" / " + c.Inn();

    if (DetectCopyLayout(c) != CopyLayout::Swapped) {
        r.message = L"Починка не требуется (раскладка в порядке или неизвестна).";
        return r;
    }
    CopyLoc loc = LocateCopy(c);

    std::vector<BYTE> pri = ReadCopyValue(loc, L"primary.key");
    std::vector<BYTE> mas = ReadCopyValue(loc, L"masks.key");
    std::vector<BYTE> pri2 = ReadCopyValue(loc, L"primary2.key");
    std::vector<BYTE> mas2 = ReadCopyValue(loc, L"masks2.key");
    if (pri.empty() || mas.empty()) {
        r.message = L"Не удалось прочитать файлы контейнера.";
        return r;
    }

    // Перестановка: primary <- masks, masks <- primary (и вторая пара).
    bool ok = WriteCopyValue(loc, L"primary.key", mas) &&
              WriteCopyValue(loc, L"masks.key", pri);
    if (ok && !pri2.empty() && !mas2.empty()) {
        ok = WriteCopyValue(loc, L"primary2.key", mas2) &&
             WriteCopyValue(loc, L"masks2.key", pri2);
    }

    if (!ok) {
        r.message = (loc.kind == CopyLoc::Reg)
                        ? L"Ошибка записи в реестр (нужны права администратора?)."
                        : L"Ошибка записи при починке.";
        JournalOp(L"repair", subj, c.thumbprint, c.name, c.uniqueName,
                  L"ошибка записи");
        return r;
    }
    JournalOp(L"repair", subj, c.thumbprint, c.name, c.uniqueName,
              L"OK: primary/masks переставлены");
    r.ok = true;
    r.message = L"Починено: primary/masks переставлены местами.";
    return r;
}

}  // namespace certmig
