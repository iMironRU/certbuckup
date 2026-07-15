// CertMigrator - инвентаризация контейнеров КриптоПро (ТЗ 7.1).
//
// Первый этап: таблица Container <-> Thumbprint <-> Subject(CN,O) <-> NotAfter.
// Копирование, перепривязка и снятие флага - следующие этапы, здесь их нет.

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "capabilities.h"
#include "resolver.h"
#include "rutoken.h"

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
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            OutLine(L"CertMigrator - инвентаризация контейнеров КриптоПро");
            OutLine(L"Использование: cert-migrator [-v] [--env]");
            OutLine(L"  -v      показывать уникальные имена и тип провайдера");
            OutLine(L"  --env   только проверка окружения, без инвентаризации");
            return 0;
        }
        if (a == "-v" || a == "--verbose") verbose = true;
        if (a == "--env") envOnly = true;
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

    const size_t kInn = 15, kCN = 34, kFrom = 13, kTo = 13, kDays = 11,
                 kReader = 22;

    OutLine(Pad(L"ИНН", kInn) + Pad(L"Владелец", kCN) + Pad(L"Действует с", kFrom) +
            Pad(L"по", kTo) + Pad(L"Осталось", kDays) + Pad(L"Носитель", kReader));
    OutLine(std::wstring(kInn + kCN + kFrom + kTo + kDays + kReader, L'-'));

    int expiring = 0, orphans = 0;

    for (const certmig::ContainerInfo& c : items) {
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

        OutLine(Pad(inn, kInn) + Pad(cn, kCN) + Pad(from, kFrom) +
                Pad(date, kTo) + Pad(days, kDays) + Pad(c.reader, kReader));

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
