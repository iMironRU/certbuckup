// CertMigrator - инвентаризация контейнеров КриптоПро (ТЗ 7.1).
//
// Первый этап: таблица Container <-> Thumbprint <-> Subject(CN,O) <-> NotAfter.
// Копирование, перепривязка и снятие флага - следующие этапы, здесь их нет.

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "backup.h"
#include "capabilities.h"
#include "journal.h"
#include "resolver.h"
#include "rutoken.h"
#include "tui.h"

namespace {

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
        case certmig::KeyMedium::FileToken: return L"файловый на токене (копируется)";
        case certmig::KeyMedium::DiskFile: return L"файловый на диске (копируется)";
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

// Обёртка над модулем backup для консольного режима --backup.
int BackupContainer(const certmig::ContainerInfo& c,
                    const std::wstring& targetBase) {
    certmig::BackupResult r = certmig::BackupToFolder(c, targetBase);
    OutLine(r.message);
    if (!r.ok) return 3;
    OutLine(L"  (контейнер CryptoPro: " + r.name83 + L", 8.3-совместимо)");
    for (const certmig::ContainerFile& f : r.files)
        OutLine(L"    " + f.name + L"  (" + std::to_wstring(f.data.size()) +
                L" байт)");
    OutLine(L"Индекс: " + targetBase + L"\\index.csv");
    if (certmig::JournalEnabled())
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
    // Не показывать системный диалог «Диск отсутствует» (0xc0000013) при опросе
    // пустых сменных дисков (картридер/дисковод без носителя). Иначе
    // перечисление FAT12-контейнеров упирается в модалку. Действует на весь
    // процесс, включая фоновый поток скана и обращения CSP/CryptoAPI к дискам.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    bool verbose = false;
    bool envOnly = false;
    bool textList = false;           // --list: текстовый вывод вместо TUI
    bool backupToReg = false;        // --backup-reg: копия в реестр
    bool backupToCp = false;         // --backup-cp: копия в папку КриптоПро
    bool renameOne = false;          // --rename: переименовать на месте
    bool noRename = false;           // --norename: копировать без переписи name.key
    bool repairOne = false;          // --repair N: починить раскладку primary/masks
    bool checkCopies = false;        // --check-copies: статус раскладки всех копий
    int backupIndex = 0;             // 1-based номер строки для --backup
    std::wstring targetBase;         // --to; по умолчанию папка cert рядом с exe
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            OutLine(L"CertMigrator - инвентаризация и резервирование КЭП КриптоПро");
            OutLine(L"Без параметров запускается интерфейс (TUI).");
            OutLine(L"Использование: cert-migrator [--list [-v]] [--env] [--backup N] [--to DIR]");
            OutLine(L"  (без флагов) запустить интерфейс");
            OutLine(L"  --list      текстовый список контейнеров");
            OutLine(L"  -v          к --list: unique-имя, ОГРН, тип провайдера");
            OutLine(L"  --env       только проверка окружения");
            OutLine(L"  --scan      диагностика rtComLite (папки-контейнеры)");
            OutLine(L"  --backup N  скопировать контейнер №N в DIR\\ИНН.ММГГ");
            OutLine(L"  --to DIR    цель копирования (по умолчанию: cert рядом с exe)");
            OutLine(L"  --log       вести журнал операций рядом с exe");
            OutLine(L"              (по умолчанию журнал не ведётся и файл не создаётся)");
            return 0;
        }
        if (a == "-v" || a == "--verbose") verbose = true;
        if (a == "--list") textList = true;
        if (a == "--env") envOnly = true;
        if (a == "--tui") return certmig::RunTui();
        if (a == "--tui-dump") return certmig::RunTuiDump();
        if (a == "--backup" && i + 1 < argc) backupIndex = atoi(argv[++i]);
        if (a == "--backup-reg" && i + 1 < argc) {
            backupIndex = atoi(argv[++i]);
            backupToReg = true;
        }
        if (a == "--backup-cp" && i + 1 < argc) {
            backupIndex = atoi(argv[++i]);
            backupToCp = true;
        }
        if (a == "--rename" && i + 1 < argc) {
            backupIndex = atoi(argv[++i]);
            renameOne = true;
        }
        if (a == "--norename") noRename = true;
        // Журнал по умолчанию выключен: на чужой машине не оставляем след.
        if (a == "--log") certmig::SetJournalEnabled(true);
        if (a == "--repair" && i + 1 < argc) {
            backupIndex = atoi(argv[++i]);
            repairOne = true;
        }
        if (a == "--check-copies") checkCopies = true;
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

    // По умолчанию (без текстовых флагов) - интерфейс.
    if (!envOnly && !textList && !checkCopies && backupIndex == 0)
        return certmig::RunTui();

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

    // Проверка раскладки primary/masks у всех файловых копий.
    if (checkCopies) {
        OutLine(L"Проверка раскладки копий (битые — с перепутанными "
                L"primary/masks):");
        OutLine();
        int broken = 0, checked = 0;
        int idx = 0;
        for (const certmig::ContainerInfo& c : items) {
            ++idx;
            certmig::CopyLayout lay = certmig::DetectCopyLayout(c);
            if (lay == certmig::CopyLayout::NotApplicable) continue;
            ++checked;
            std::wstring st = lay == certmig::CopyLayout::Ok ? L"[ OK ]"
                              : lay == certmig::CopyLayout::Swapped
                                  ? L"[БИТАЯ]  ← чинится: --repair " +
                                        std::to_wstring(idx)
                                  : L"[?]";
            if (lay == certmig::CopyLayout::Swapped) ++broken;
            OutLine(L"  №" + std::to_wstring(idx) + L"  " + st + L"  " +
                    c.subjectCN + L" (" + c.Inn() + L")  " + c.uniqueName);
        }
        OutLine();
        OutLine(L"Копий проверено: " + std::to_wstring(checked) +
                L", битых: " + std::to_wstring(broken));
        return broken > 0 ? 1 : 0;
    }

    // Резервное копирование выбранного контейнера (ТЗ 2.2).
    if (backupIndex > 0) {
        if (backupIndex > static_cast<int>(items.size())) {
            OutLine(L"Нет контейнера №" + std::to_wstring(backupIndex) +
                    L" (всего " + std::to_wstring(items.size()) + L").");
            return 2;
        }
        if (targetBase.empty()) targetBase = certmig::DefaultBackupDir();
        const certmig::ContainerInfo& c = items[backupIndex - 1];
        OutLine(L"Копирование №" + std::to_wstring(backupIndex) + L": " +
                c.subjectCN + L" (" + c.Inn() + L"), до " +
                certmig::FormatDate(c.notAfter));
        OutLine();
        if (repairOne) {
            certmig::CopyLayout lay = certmig::DetectCopyLayout(c);
            OutLine(lay == certmig::CopyLayout::Swapped
                        ? L"Раскладка битая — переставляю primary/masks…"
                    : lay == certmig::CopyLayout::Ok
                        ? L"Раскладка уже правильная."
                        : L"Это не файловая копия или структура не распознана.");
            certmig::RepairResult rr = certmig::RepairContainerLayout(c);
            OutLine(rr.message);
            return rr.ok ? 0 : (lay == certmig::CopyLayout::Ok ? 0 : 3);
        }
        if (renameOne) {
            OutLine(L"Текущее имя: " + certmig::ReadCurrentFriendlyName(c) +
                    (certmig::NameLooksLikeGuid(
                         certmig::ReadCurrentFriendlyName(c))
                         ? L"  (похоже на GUID)"
                         : L""));
            certmig::RenameResult rr =
                certmig::RenameContainerInPlace(c, certmig::ReadableName(c));
            OutLine(rr.message);
            return rr.ok ? 0 : 3;
        }
        if (backupToReg || backupToCp) {
            bool rename = !noRename;
            certmig::BackupResult r =
                backupToReg
                    ? certmig::BackupToRegistry(c, false, false, rename)
                    : certmig::BackupToCryptoProStore(c, false, false, rename);
            OutLine(r.message);
            if (certmig::JournalEnabled())
                OutLine(L"Журнал: " + certmig::JournalPath());
            return r.ok ? 0 : 3;
        }
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
