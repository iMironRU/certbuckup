// Резолвер: контейнер <-> сертификат (ТЗ 4).
//
// Работает через CryptoAPI, не через парсинг вывода csptest/certmgr.
//
// Порядок путей обратный тому, что заложен в ТЗ 4, и это сделано намеренно.
// На реальных носителях хранилище My оказалось пустым, поэтому матч через
// CRYPT_KEY_PROV_INFO не даёт ни одной строки. Основной путь здесь -
// чтение сертификата из самого контейнера (KP_CERTIFICATE).
#pragma once

#include <windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>

namespace certmig {

// Типы провайдеров КриптоПро. Перебираем все три: на одной машине могут
// сосуществовать контейнеры разных поколений ГОСТ.
struct ProviderType {
    DWORD type;
    const wchar_t* name;
    const wchar_t* title;
};

extern const ProviderType kProviders[];
extern const size_t kProviderCount;

// Класс ключа: определяет, можно ли контейнер копировать (ТЗ 1).
enum class KeyMedium {
    Unknown,
    Registry,   // реестр
    FileToken,  // файловый контейнер на токене - копируется
    HardWare,   // ключ сгенерирован внутри чипа - копирование невозможно
};

// Экспортируемость приватного ключа (ТЗ 2.1). Меряется попыткой
// CryptExportKey, а не гадается по имени носителя.
enum class Exportable {
    Unknown,
    Yes,
    No,
};

struct ContainerInfo {
    std::wstring name;         // имя контейнера, как отдаёт PP_ENUMCONTAINERS
    std::wstring uniqueName;   // PP_UNIQUE_CONTAINER
    std::wstring reader;       // носитель, вытащенный из имени
    DWORD provType = 0;
    std::wstring provName;

    bool hasCert = false;
    DWORD keySpec = 0;         // AT_KEYEXCHANGE или AT_SIGNATURE

    // Поля сертификата (ТЗ 2.1)
    std::wstring subjectCN;
    std::wstring subjectO;
    std::wstring thumbprint;   // SHA1
    std::wstring serial;
    FILETIME notBefore{};
    FILETIME notAfter{};

    // Российские атрибуты. В стандартном X.509 их нет, УЦ кладёт их
    // отдельными OID'ами в Subject.
    std::wstring inn;     // ИНН физлица (1.2.643.3.131.1.1)
    std::wstring innLe;   // ИНН юрлица  (1.2.643.100.4)
    std::wstring ogrn;    // ОГРН        (1.2.643.100.1)
    std::wstring snils;   // СНИЛС       (1.2.643.100.3)
    std::wstring surname; // фамилия     (2.5.4.4)
    std::wstring given;   // имя-отчество (2.5.4.42)

    // ИНН, который стоит показывать: физлица, иначе юрлица.
    const std::wstring& Inn() const { return inn.empty() ? innLe : inn; }

    KeyMedium medium = KeyMedium::Unknown;
    Exportable exportable = Exportable::Unknown;
    // Код ошибки CryptExportKey, если экспорт не удался. Нужен, чтобы
    // отличить "ключ неэкспортируемый" от "не спросили PIN".
    DWORD exportError = 0;

    // Пустая строка - ошибок не было. Иначе причина, по которой сертификат
    // не удалось разрешить; строка контейнера всё равно попадает в вывод,
    // иначе оператор не увидит проблемный носитель.
    std::wstring error;
};

// Проверка окружения (ТЗ 3): установлен ли CSP и какой версии.
struct CspInfo {
    bool installed = false;
    std::wstring version;
    // Какие поколения ГОСТ доступны. Пусто быть не может, если installed.
    std::vector<std::wstring> providers;
};

CspInfo DetectCsp();

// Перечислить все контейнеры по всем типам провайдера и разрешить
// связь с сертификатом для каждого.
std::vector<ContainerInfo> EnumerateContainers();

// Сколько дней осталось до NotAfter. Отрицательное - сертификат истёк.
int DaysUntil(const FILETIME& ft);

// NotAfter в вид YYYY-MM-DD.
std::wstring FormatDate(const FILETIME& ft);

}  // namespace certmig
