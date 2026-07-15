// CertMigrator - инвентаризация контейнеров КриптоПро (ТЗ 7.1).
//
// Первый этап: таблица Container <-> Thumbprint <-> Subject(CN,O) <-> NotAfter.
// Копирование, перепривязка и снятие флага - следующие этапы, здесь их нет.

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "resolver.h"

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
        case certmig::KeyMedium::Registry: return L"реестр";
        case certmig::KeyMedium::FileToken: return L"файловый";
        case certmig::KeyMedium::HardWare: return L"аппаратный";
        default: return L"?";
    }
}

}  // namespace

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);

    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            OutLine(L"CertMigrator - инвентаризация контейнеров КриптоПро");
            OutLine(L"Использование: cert-migrator [-v]");
            OutLine(L"  -v   показывать уникальные имена и тип провайдера");
            return 0;
        }
        if (a == "-v" || a == "--verbose") verbose = true;
    }

    // ТЗ 3: проверка окружения. Без CSP дальше идти бессмысленно.
    certmig::CspInfo csp = certmig::DetectCsp();
    if (!csp.installed) {
        OutLine(L"КриптоПро CSP не обнаружен.");
        OutLine(L"Инструмент работает только поверх установленного CSP.");
        return 2;
    }
    std::wstring provs;
    for (size_t i = 0; i < csp.providers.size(); ++i) {
        if (i) provs += L", ";
        provs += csp.providers[i];
    }
    OutLine(L"КриптоПро CSP " + csp.version + L"  |  доступно: " + provs);
    OutLine();

    std::vector<certmig::ContainerInfo> items = certmig::EnumerateContainers();
    if (items.empty()) {
        OutLine(L"Контейнеров не найдено.");
        OutLine(L"Проверьте, подключён ли носитель.");
        return 0;
    }

    const size_t kCN = 30, kO = 22, kDate = 14, kDays = 12, kReader = 24,
                 kKey = 9, kMed = 11;

    OutLine(Pad(L"Владелец (CN)", kCN) + Pad(L"Организация (O)", kO) +
            Pad(L"Действует до", kDate) + Pad(L"Осталось", kDays) +
            Pad(L"Носитель", kReader) + Pad(L"Ключ", kKey) +
            Pad(L"Тип", kMed));
    OutLine(std::wstring(kCN + kO + kDate + kDays + kReader + kKey + kMed, L'-'));

    int expiring = 0, orphans = 0;

    for (const certmig::ContainerInfo& c : items) {
        std::wstring cn = c.subjectCN, org = c.subjectO, date = L"-",
                     days = L"-";

        if (c.hasCert) {
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

        OutLine(Pad(cn, kCN) + Pad(org, kO) + Pad(date, kDate) +
                Pad(days, kDays) + Pad(c.reader, kReader) +
                Pad(KeySpecName(c.keySpec), kKey) + Pad(MediumName(c.medium), kMed));

        OutLine(L"    контейнер:  " + c.name);
        if (!c.thumbprint.empty()) OutLine(L"    thumbprint: " + c.thumbprint);
        if (verbose) {
            if (!c.uniqueName.empty()) OutLine(L"    unique:     " + c.uniqueName);
            OutLine(L"    провайдер:  " + c.provName + L" (тип " +
                    std::to_wstring(c.provType) + L")");
            if (!c.serial.empty()) OutLine(L"    serial:     " + c.serial);
        }
        if (!c.error.empty()) OutLine(L"    ! " + c.error);
        OutLine();
    }

    OutLine(L"Всего контейнеров: " + std::to_wstring(items.size()) +
            L", без сертификата: " + std::to_wstring(orphans) +
            L", истекают или истекли: " + std::to_wstring(expiring));
    return 0;
}
