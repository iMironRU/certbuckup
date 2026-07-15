// CertMigrator - инвентаризация контейнеров КриптоПро (ТЗ 7.1).
//
// Первый этап: таблица Container <-> Thumbprint <-> Subject(CN,O) <-> NotAfter.
// Копирование, перепривязка и снятие флага - следующие этапы, здесь их нет.

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "capabilities.h"
#include "journal.h"
#include "resolver.h"
#include "rutoken.h"

namespace {

std::wstring ExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, n);
    size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? L"." : path.substr(0, slash);
}

// ИНН для имени папки: юрлица, иначе физлица (для КЭП без юрлица).
std::wstring FolderInn(const certmig::ContainerInfo& c) {
    if (!c.innLe.empty()) return c.innLe;
    if (!c.inn.empty()) return c.inn;
    return L"noinn";
}

// ММГГ по дате окончания сертификата: месяц и две цифры года.
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

bool EnsureDir(const std::wstring& path) {
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

bool WriteBytes(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()),
                        &written, nullptr) &&
              written == data.size();
    CloseHandle(h);
    return ok;
}

// Находит ридер rtComLite, на котором лежит папка folderId. Имя ридера
// rtComLite (Aktiv Rutoken lite 0) не совпадает с коротким id из FQCN,
// поэтому ищем по факту наличия папки-контейнера.
std::wstring FindReaderForFolder(int folderId) {
    for (const std::wstring& r : certmig::EnumReaders()) {
        certmig::TokenScan s = certmig::ScanToken(r);
        if (s.ok && s.containerFolders.count(folderId)) return r;
    }
    return L"";
}

// Вывод в UTF-8: иначе кириллица превращается в мусор и при печати в консоль,
// и при перенаправлении в файл.
void Out(const std::wstring& s) {
    if (s.empty()) return;
    int need = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0,
                                   nullptr, nullptr);
    if (need <= 1) return;
    std::string utf8(static_cast<size_t>(need - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &utf8[0], need, nullptr,
                        nullptr);
    fwrite(utf8.data(), 1, utf8.size(), stdout);
}

void OutLine(const std::wstring& s = L"") {
    Out(s);
    fputc('\n', stdout);
}

std::wstring Pad(const std::wstring& s, size_t width) {
    if (s.size() >= width) {
        if (width <= 1) return s.substr(0, width);
        return s.substr(0, width - 1) + L"…";
    }
    return s + std::wstring(width - s.size(), L' ');
}

std::wstring KeySpecName(DWORD spec) {
    switch (spec) {
        case AT_KEYEXCHANGE: return L"обмен";
        case AT_SIGNATURE:   return L"подпись";
        default:             return L"-";
    }
}

std::wstring MediumName(certmig::KeyMedium m) {
    switch (m) {
        case certmig::KeyMedium::Registry: return L"реестр (копируется)";
        case certmig::KeyMedium::FileToken: return L"файловый (копируется)";
        case certmig::KeyMedium::HardWare:
            return L"аппаратный — ключ в чипе, НЕ копируется";
        default: return L"?";
    }
}

std::wstring CapMark(certmig::CapState s) {
    switch (s) {
        case certmig::CapState::Present: return L"[+]";
        case certmig::CapState::Partial: return L"[~]";
        default: return L"[-]";
    }
}

// Отчёт о возможностях окружения и доступных способах копирования (ТЗ 3).
void PrintEnvironment(const certmig::Environment& env) {
    OutLine(L"Окружение:");
    for (const certmig::Capability& c : env.caps) {
        OutLine(L"  " + CapMark(c.state) + L" " + c.name +
                (c.detail.empty() ? L"" : L" — " + c.detail));
        OutLine(L"        " + c.enables);
        if (c.state != certmig::CapState::Present && !c.hint.empty())
            OutLine(L"        ↓ " + c.hint);
    }
    OutLine();
    OutLine(L"Способы копирования:");
    for (const certmig::CopyBackend& b : env.backends) {
        std::wstring mark = b.available ? L"[+]" : L"[-]";
        OutLine(L"  " + mark + L" " + b.name + L"  (" + b.scope + L")");
        if (!b.reason.empty()) OutLine(L"        " + b.reason);
    }
}

// Резервное копирование одного контейнера в папку targetBase\ИНН.ММГГ
// (ТЗ 2.2). Читает шесть файлов с токена через rtComLite, пишет их. На токене
// ничего не меняется. Пишет запись в журнал (ТЗ 6). Возвращает код возврата.
int BackupContainer(const certmig::ContainerInfo& c,
                    const std::wstring& targetBase) {
    std::wstring subj = c.subjectCN + L" / " + c.Inn();

    if (c.medium == certmig::KeyMedium::HardWare) {
        OutLine(L"Контейнер аппаратный (ключ в чипе) — копировать нечего.");
        certmig::JournalOp(L"backup", subj, c.thumbprint, c.name, targetBase,
                           L"отказ: аппаратный ключ");
        return 3;
    }
    if (c.medium != certmig::KeyMedium::FileToken || c.folderId < 0) {
        OutLine(L"Этот бэкенд копирует только файловые контейнеры с токена.");
        OutLine(L"Для реестра используйте keycopy (пока не реализован).");
        return 3;
    }

    std::wstring reader = FindReaderForFolder(c.folderId);
    if (reader.empty()) {
        OutLine(L"Не найден токен с контейнером — переподключите носитель.");
        certmig::JournalOp(L"backup", subj, c.thumbprint, c.name, targetBase,
                           L"ошибка: токен не найден");
        return 4;
    }

    std::vector<certmig::ContainerFile> files;
    std::wstring err;
    if (!certmig::ReadContainer(reader, c.folderId, &files, &err)) {
        OutLine(L"Ошибка чтения контейнера: " + err);
        certmig::JournalOp(L"backup", subj, c.thumbprint, reader, targetBase,
                           L"ошибка чтения: " + err);
        return 4;
    }

    std::wstring folderName = FolderInn(c) + L"." + MMYY(c.notAfter);
    std::wstring dest = targetBase + L"\\" + folderName;

    if (!EnsureDir(targetBase)) {
        OutLine(L"Не удалось создать папку: " + targetBase);
        return 5;
    }
    if (!EnsureDir(dest)) {
        // CREATE_NEW ниже всё равно защитит от перезаписи, но папка уже есть -
        // предупреждаем явно, чтобы не смешать два контейнера.
        DWORD a = GetFileAttributesW(dest.c_str());
        if (a != INVALID_FILE_ATTRIBUTES) {
            OutLine(L"Папка уже существует: " + dest);
            OutLine(L"Удалите её или выберите другую цель — перезаписывать не буду.");
            certmig::JournalOp(L"backup", subj, c.thumbprint, reader, dest,
                               L"отказ: папка существует");
            return 5;
        }
    }

    for (const certmig::ContainerFile& f : files) {
        if (!WriteBytes(dest + L"\\" + f.name, f.data)) {
            OutLine(L"Не удалось записать файл: " + f.name);
            certmig::JournalOp(L"backup", subj, c.thumbprint, reader, dest,
                               L"ошибка записи: " + f.name);
            return 5;
        }
    }

    OutLine(L"Скопировано в: " + dest);
    for (const certmig::ContainerFile& f : files)
        OutLine(L"    " + f.name + L"  (" + std::to_wstring(f.data.size()) +
                L" байт)");
    certmig::JournalOp(L"backup", subj, c.thumbprint, reader, dest, L"OK");
    OutLine(L"Журнал: " + certmig::JournalPath());
    return 0;
}

std::wstring ExportableName(certmig::Exportable e, DWORD err) {
    wchar_t code[32];
    swprintf(code, 32, L" (0x%08lX)", err);
    switch (e) {
        case certmig::Exportable::Yes: return L"да";
        case certmig::Exportable::No:  return L"НЕТ" + std::wstring(code);
        default: return L"не определено" + std::wstring(code);
    }
}

}  // namespace

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);

    bool verbose = false;
    bool envOnly = false;
    int backupIndex = 0;             // 1-based номер строки для --backup
    std::wstring targetBase;         // --to; по умолчанию папка cert рядом с exe
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            OutLine(L"CertMigrator - инвентаризация и резервирование КЭП КриптоПро");
            OutLine(L"Использование: cert-migrator [-v] [--env] [--backup N] [--to DIR]");
            OutLine(L"  -v          подробно: unique-имя, ОГРН, тип провайдера");
            OutLine(L"  --env       только проверка окружения");
            OutLine(L"  --scan      диагностика rtComLite (папки-контейнеры)");
            OutLine(L"  --backup N  скопировать контейнер №N в DIR\\ИНН.ММГГ");
            OutLine(L"  --to DIR    цель копирования (по умолчанию: cert рядом с exe)");
            return 0;
        }
        if (a == "-v" || a == "--verbose") verbose = true;
        if (a == "--env") envOnly = true;
        if (a == "--backup" && i + 1 < argc) backupIndex = atoi(argv[++i]);
        if (a == "--to" && i + 1 < argc) {
            std::string t = argv[++i];
            int need = MultiByteToWideChar(CP_ACP, 0, t.c_str(), -1, nullptr, 0);
            targetBase.resize(need > 0 ? need - 1 : 0);
            if (need > 0)
                MultiByteToWideChar(CP_ACP, 0, t.c_str(), -1, &targetBase[0], need);
        }
        if (a == "--scan") {
            // Диагностика rtComLite: какие токены видны и какие папки на них
            // распознаны как файловые контейнеры.
            std::vector<std::wstring> readers = certmig::EnumReaders();
            OutLine(L"rtComLite видит ридеров: " +
                    std::to_wstring(readers.size()));
            for (const std::wstring& r : readers) {
                certmig::TokenScan s = certmig::ScanToken(r);
                OutLine(L"  " + r + (s.ok ? L"  [ok]" : L"  [ошибка: " + s.error + L"]"));
                for (int f : s.containerFolders) {
                    wchar_t hex[16];
                    swprintf(hex, 16, L"0x%04X", f);
                    OutLine(L"      контейнер-папка " + std::to_wstring(f) +
                            L" (" + hex + L")");
                }
            }
            return 0;
        }
    }

    // ТЗ 3: проба окружения. Показываем, что есть и что из этого можно.
    certmig::Environment env = certmig::ProbeEnvironment();
    PrintEnvironment(env);
    OutLine();

    if (envOnly) return 0;

    // Инвентаризация опирается на CryptoAPI: без CSP её не построить.
    if (env.caps.empty() || env.caps[0].state != certmig::CapState::Present) {
        OutLine(L"КриптоПро CSP не обнаружен — инвентаризация недоступна.");
        return 2;
    }

    std::vector<certmig::ContainerInfo> items = certmig::EnumerateContainers();
    if (items.empty()) {
        OutLine(L"Контейнеров не найдено.");
        OutLine(L"Проверьте, подключён ли носитель.");
        return 0;
    }

    // Резервное копирование выбранного контейнера (ТЗ 2.2).
    if (backupIndex > 0) {
        if (backupIndex > static_cast<int>(items.size())) {
            OutLine(L"Нет контейнера №" + std::to_wstring(backupIndex) +
                    L" (всего " + std::to_wstring(items.size()) + L").");
            return 2;
        }
        if (targetBase.empty()) targetBase = ExeDir() + L"\\cert";
        const certmig::ContainerInfo& c = items[backupIndex - 1];
        OutLine(L"Копирование №" + std::to_wstring(backupIndex) + L": " +
                c.subjectCN + L" (" + c.Inn() + L"), до " +
                certmig::FormatDate(c.notAfter));
        OutLine();
        return BackupContainer(c, targetBase);
    }

    const size_t kNum = 4, kInn = 15, kCN = 32, kFrom = 13, kTo = 13,
                 kDays = 11, kReader = 22;

    OutLine(Pad(L"#", kNum) + Pad(L"ИНН", kInn) + Pad(L"Владелец", kCN) +
            Pad(L"Действует с", kFrom) + Pad(L"по", kTo) +
            Pad(L"Осталось", kDays) + Pad(L"Носитель", kReader));
    OutLine(std::wstring(kNum + kInn + kCN + kFrom + kTo + kDays + kReader, L'-'));

    int expiring = 0, orphans = 0;
    int row = 0;

    for (const certmig::ContainerInfo& c : items) {
        ++row;
        std::wstring cn = c.subjectCN, from = L"-", date = L"-", days = L"-";
        std::wstring inn = c.Inn();
        if (inn.empty()) inn = L"—";

        if (c.hasCert) {
            from = certmig::FormatDate(c.notBefore);
            date = certmig::FormatDate(c.notAfter);
            int d = certmig::DaysUntil(c.notAfter);
            // Подсветка истекающих (ТЗ 2.1). Порог 30 дней.
            if (d < 0) {
                days = L"ИСТЁК";
                ++expiring;
            } else if (d < 30) {
                days = std::to_wstring(d) + L" дн !";
                ++expiring;
            } else {
                days = std::to_wstring(d) + L" дн";
            }
        } else {
            cn = L"<нет сертификата>";
            ++orphans;
        }

        OutLine(Pad(std::to_wstring(row), kNum) + Pad(inn, kInn) +
                Pad(cn, kCN) + Pad(from, kFrom) + Pad(date, kTo) +
                Pad(days, kDays) + Pad(c.reader, kReader));

        if (!c.subjectO.empty() && c.subjectO != c.subjectCN)
            OutLine(L"    организация: " + c.subjectO);
        if (!c.surname.empty() || !c.given.empty())
            OutLine(L"    ФИО:         " + c.surname + L" " + c.given);
        if (!c.snils.empty()) OutLine(L"    СНИЛС:       " + c.snils);
        OutLine(L"    носитель:    " + MediumName(c.medium) + L", ключ: " +
                KeySpecName(c.keySpec));
        OutLine(L"    экспорт:     " + ExportableName(c.exportable, c.exportError));
        OutLine(L"    контейнер:   " + c.name);
        if (!c.thumbprint.empty()) OutLine(L"    thumbprint:  " + c.thumbprint);
        if (verbose) {
            if (!c.uniqueName.empty()) OutLine(L"    unique:      " + c.uniqueName);
            if (!c.ogrn.empty()) OutLine(L"    ОГРН:        " + c.ogrn);
            if (!c.inn.empty()) OutLine(L"    ИНН физлица: " + c.inn);
            if (!c.innLe.empty()) OutLine(L"    ИНН юрлица:  " + c.innLe);
            OutLine(L"    провайдер:   " + c.provName + L" (тип " +
                    std::to_wstring(c.provType) + L")");
            if (!c.serial.empty()) OutLine(L"    serial:      " + c.serial);
        }
        if (!c.error.empty()) OutLine(L"    ! " + c.error);
        OutLine();
    }

    OutLine(L"Всего контейнеров: " + std::to_wstring(items.size()) +
            L", без сертификата: " + std::to_wstring(orphans) +
            L", истекают или истекли: " + std::to_wstring(expiring));
    return 0;
}
