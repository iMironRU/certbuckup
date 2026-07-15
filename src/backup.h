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
    bool skipped = false;     // папка уже существует, копирование не делали
    std::wstring dest;        // куда записано (папка 8.3-контейнера)
    std::wstring name83;      // имя контейнера 8.3
    std::wstring human;       // человекочитаемая обёртка ИНН.ММГГ
    std::wstring reader;      // с какого токена читали
    std::wstring message;     // человекочитаемый итог/причина отказа
    std::vector<ContainerFile> files;  // что скопировано (имя+размер)
};

// Куда ляжет копия контейнера: targetBase\ИНН.ММГГ\8.3. Позволяет заранее
// проверить, не занята ли папка, до чтения токена.
std::wstring BackupTargetPath(const ContainerInfo& c,
                              const std::wstring& targetBase);

// Копирует файловый контейнер c в targetBase\ИНН.ММГГ\8.3\. Читает 6 файлов
// с токена через rtComLite, пишет их, дополняет index.csv и журнал.
// Аппаратные и не-файловые контейнеры отклоняются. Если папка уже есть и
// overwrite == false - возвращает skipped без записи; при overwrite == true
// перезаписывает.
BackupResult BackupToFolder(const ContainerInfo& c,
                            const std::wstring& targetBase,
                            bool overwrite = false,
                            bool clearExportFlag = false);

// Копирует контейнер в реестр Windows (хранилище контейнеров КриптоПро):
// 6 файлов как бинарные значения под ключом Crypto Pro Settings USERS
// <SID> Keys <8.3-имя>. Требует прав администратора (запись в HKLM).
BackupResult BackupToRegistry(const ContainerInfo& c, bool overwrite = false,
                              bool clearExportFlag = false);

// Есть ли уже такой контейнер в реестре (для предупреждения о перезаписи).
bool RegistryContainerExists(const ContainerInfo& c);

// Копирует контейнер в хранилище КриптоПро на диске (HDIMAGE):
// %LOCALAPPDATA%\Crypto Pro\<8.3-имя>.000 с 6 файлами. Per-user, без админа.
// CryptoPro читает такой контейнер как локальный дисковый.
BackupResult BackupToCryptoProStore(const ContainerInfo& c,
                                    bool overwrite = false,
                                    bool clearExportFlag = false);
std::wstring CryptoProStoreDir();          // %LOCALAPPDATA%\Crypto Pro
bool CryptoProStoreExists(const ContainerInfo& c);

// Путь к папке cert рядом с exe - цель по умолчанию.
std::wstring DefaultBackupDir();

}  // namespace certmig
