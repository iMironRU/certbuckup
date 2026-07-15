// Резервное копирование контейнера в папку (ТЗ 2.2).
//
// Выделено из main, чтобы вызывать и из консольного вывода (--backup), и из
// TUI. Возвращает результат структурой, ничего не печатает сам.
#pragma once

#include <string>
#include <vector>

#include "resolver.h"
#include "rutoken.h"

namespace certmig {

struct BackupResult {
    bool ok = false;
    std::wstring dest;        // куда записано (папка 8.3-контейнера)
    std::wstring name83;      // имя контейнера 8.3
    std::wstring human;       // человекочитаемая обёртка ИНН.ММГГ
    std::wstring reader;      // с какого токена читали
    std::wstring message;     // человекочитаемый итог/причина отказа
    std::vector<ContainerFile> files;  // что скопировано (имя+размер)
};

// Копирует файловый контейнер c в targetBase\ИНН.ММГГ\8.3\. Читает 6 файлов
// с токена через rtComLite, пишет их, дополняет index.csv и журнал.
// Аппаратные и не-файловые контейнеры отклоняются.
BackupResult BackupToFolder(const ContainerInfo& c,
                            const std::wstring& targetBase);

// Путь к папке cert рядом с exe - цель по умолчанию.
std::wstring DefaultBackupDir();

}  // namespace certmig
