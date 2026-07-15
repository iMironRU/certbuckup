#include "resolver.h"

#include <cstdio>
#include <map>
#include <set>

#include "rutoken.h"

namespace certmig {

const ProviderType kProviders[] = {
    {75, L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider", L"ГОСТ 2001"},
    {80, L"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", L"ГОСТ 2012-256"},
    {81, L"Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider", L"ГОСТ 2012-512"},
};
const size_t kProviderCount = sizeof(kProviders) / sizeof(kProviders[0]);

namespace {

// OID'ы российских атрибутов Subject. В wincrypt.h их нет: это не часть
// X.509, а расширения, которые кладёт УЦ.
const char kOidInn[]   = "1.2.643.3.131.1.1";  // ИНН физлица
const char kOidInnLe[] = "1.2.643.100.4";      // ИНН юрлица
const char kOidOgrn[]  = "1.2.643.100.1";      // ОГРН
const char kOidSnils[] = "1.2.643.100.3";      // СНИЛС

std::wstring AnsiToWide(const char* s) {
    if (!s || !*s) return L"";
    int need = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (need <= 0) return L"";
    std::wstring out(static_cast<size_t>(need - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s, -1, &out[0], need);
    return out;
}

std::wstring LastErrorText(DWORD code) {
    wchar_t buf[64];
    swprintf(buf, 64, L"0x%08lX", code);
    return buf;
}

// Носитель определяется по PP_UNIQUE_CONTAINER, а не по имени контейнера.
// PP_ENUMCONTAINERS отдаёт голый GUID без всякого указания на носитель, тогда
// как уникальное имя несёт префикс:
//   SCARD\rutoken_lt_39445e29\0A00\28A9  - контейнер на токене
//   REGISTRY\\...                        - реестр
//   HDIMAGE\\...                         - файл на диске
// Это данные от самого CSP, а не разбор чужого stdout.
void ParseMedium(const std::wstring& unique, KeyMedium* medium,
                 std::wstring* reader) {
    *medium = KeyMedium::Unknown;
    *reader = L"?";
    if (unique.empty()) return;

    size_t sep = unique.find(L'\\');
    std::wstring head = (sep == std::wstring::npos) ? unique : unique.substr(0, sep);

    if (_wcsicmp(head.c_str(), L"REGISTRY") == 0) {
        *medium = KeyMedium::Registry;
        *reader = L"реестр";
        return;
    }
    if (_wcsicmp(head.c_str(), L"SCARD") == 0) {
        // FileToken здесь предварительно: реальный тип (файловый или
        // аппаратный) уточняется сканом токена в EnumerateContainers.
        *medium = KeyMedium::FileToken;
        // Следующий сегмент - идентификатор носителя, напр. rutoken_lt_39445e29.
        size_t start = sep + 1;
        size_t end = unique.find(L'\\', start);
        *reader = (end == std::wstring::npos) ? unique.substr(start)
                                              : unique.substr(start, end - start);
        return;
    }
    if (_wcsicmp(head.c_str(), L"HDIMAGE") == 0) {
        *medium = KeyMedium::FileToken;
        *reader = L"диск";
        return;
    }
    *reader = head;
}

// Из FQCN достаёт ID папки контейнера на токене. Уникальное имя вида
//   SCARD\rutoken_lt_39445e29\0A00\28A9
// несёт в 3-м сегменте (0A00) шестнадцатеричный ID папки: 0x0A00 = 2560.
// Этот ID совпадает с папкой в файловой системе токена (см. rutoken.cpp).
int ParseFolderId(const std::wstring& unique) {
    if (_wcsnicmp(unique.c_str(), L"SCARD\\", 6) != 0) return -1;
    // Разбиваем по '\' и берём сегмент с индексом 2.
    size_t p = unique.find(L'\\');              // после SCARD
    p = (p == std::wstring::npos) ? p : unique.find(L'\\', p + 1);  // после носителя
    if (p == std::wstring::npos) return -1;
    size_t start = p + 1;
    size_t end = unique.find(L'\\', start);
    std::wstring seg = (end == std::wstring::npos) ? unique.substr(start)
                                                   : unique.substr(start, end - start);
    if (seg.empty()) return -1;
    wchar_t* endp = nullptr;
    long id = wcstol(seg.c_str(), &endp, 16);
    return (endp && *endp == 0 && id > 0) ? static_cast<int>(id) : -1;
}

std::wstring ToHex(const BYTE* data, DWORD len) {
    static const wchar_t* kHex = L"0123456789ABCDEF";
    std::wstring out;
    out.reserve(len * 2);
    for (DWORD i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

std::wstring GetNameAttr(PCCERT_CONTEXT ctx, const char* oid) {
    DWORD need = CertGetNameStringW(ctx, CERT_NAME_ATTR_TYPE, 0,
                                    const_cast<char*>(oid), nullptr, 0);
    if (need <= 1) return L"";
    std::wstring out(need, L'\0');
    CertGetNameStringW(ctx, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(oid),
                       &out[0], need);
    out.resize(need - 1);
    return out;
}

// Достаёт сертификат прямо из контейнера (путь 1 из ТЗ 4).
// На стенде это единственный работающий путь: хранилище My пустое.
bool ReadCertFromContainer(HCRYPTPROV prov, ContainerInfo* info) {
    // На всех проверенных контейнерах ключ оказался AT_KEYEXCHANGE, а не
    // AT_SIGNATURE - типично для КЭП российских УЦ. Поэтому обмен пробуем
    // первым, но перебираем оба: иначе часть парка молча выпадет из вывода.
    const DWORD kKeySpecs[] = {AT_KEYEXCHANGE, AT_SIGNATURE};

    for (DWORD spec : kKeySpecs) {
        HCRYPTKEY key = 0;
        if (!CryptGetUserKey(prov, spec, &key)) continue;

        DWORD cb = 0;
        if (!CryptGetKeyParam(key, KP_CERTIFICATE, nullptr, &cb, 0) || cb == 0) {
            CryptDestroyKey(key);
            continue;
        }

        std::vector<BYTE> der(cb);
        if (!CryptGetKeyParam(key, KP_CERTIFICATE, der.data(), &cb, 0)) {
            CryptDestroyKey(key);
            continue;
        }
        CryptDestroyKey(key);

        PCCERT_CONTEXT ctx = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), cb);
        if (!ctx) continue;

        info->hasCert = true;
        info->keySpec = spec;
        info->subjectCN = GetNameAttr(ctx, szOID_COMMON_NAME);
        info->subjectO = GetNameAttr(ctx, szOID_ORGANIZATION_NAME);
        info->notBefore = ctx->pCertInfo->NotBefore;
        info->notAfter = ctx->pCertInfo->NotAfter;

        info->inn = GetNameAttr(ctx, kOidInn);
        info->innLe = GetNameAttr(ctx, kOidInnLe);
        info->ogrn = GetNameAttr(ctx, kOidOgrn);
        info->snils = GetNameAttr(ctx, kOidSnils);
        info->surname = GetNameAttr(ctx, szOID_SUR_NAME);
        info->given = GetNameAttr(ctx, szOID_GIVEN_NAME);

        BYTE hash[20];
        DWORD cbHash = sizeof(hash);
        if (CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, hash,
                                              &cbHash)) {
            info->thumbprint = ToHex(hash, cbHash);
        }

        // Серийный номер CryptoAPI отдаёт little-endian, разворачиваем.
        const CRYPT_INTEGER_BLOB& sn = ctx->pCertInfo->SerialNumber;
        std::vector<BYTE> rev(sn.pbData, sn.pbData + sn.cbData);
        for (size_t i = 0, j = rev.size(); i < j / 2; ++i) {
            BYTE t = rev[i];
            rev[i] = rev[j - 1 - i];
            rev[j - 1 - i] = t;
        }
        info->serial = ToHex(rev.data(), static_cast<DWORD>(rev.size()));

        CertFreeCertificateContext(ctx);
        return true;
    }
    return false;
}

// Меряет экспортируемость: пробует узнать размер PRIVATEKEYBLOB.
// Ключ при этом не выгружается - запрашивается только длина, буфер нулевой.
//
// Это единственный честный способ: по имени носителя экспортируемость не
// определить, а именно она решает, можно ли скопировать контейнер штатным
// CryptoAPI (CryptExportKey -> CryptImportKey) или нужен keycopy.
void ProbeExportable(HCRYPTPROV prov, DWORD keySpec, ContainerInfo* info) {
    HCRYPTKEY key = 0;
    if (!CryptGetUserKey(prov, keySpec, &key)) {
        info->exportError = GetLastError();
        return;
    }

    DWORD cb = 0;
    if (CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, nullptr, &cb)) {
        info->exportable = Exportable::Yes;
    } else {
        // NTE_BAD_KEY_STATE (0x8009000B) и NTE_PERM (0x80090010) означают
        // именно запрет экспорта. Прочие коды - что-то другое, и объявлять
        // ключ неэкспортируемым по ним нельзя.
        DWORD err = GetLastError();
        info->exportError = err;
        if (err == static_cast<DWORD>(NTE_BAD_KEY_STATE) ||
            err == static_cast<DWORD>(NTE_PERM)) {
            info->exportable = Exportable::No;
        }
    }
    CryptDestroyKey(key);
}

std::wstring GetProvParamString(HCRYPTPROV prov, DWORD param) {
    DWORD cb = 0;
    if (!CryptGetProvParam(prov, param, nullptr, &cb, 0) || cb == 0) return L"";
    std::vector<BYTE> buf(cb);
    if (!CryptGetProvParam(prov, param, buf.data(), &cb, 0)) return L"";
    return AnsiToWide(reinterpret_cast<const char*>(buf.data()));
}

bool ResolveOne(const ProviderType& pt, const std::wstring& contName,
                ContainerInfo* info) {
    info->name = contName;
    info->provType = pt.type;
    info->provName = pt.title;

    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, contName.c_str(), pt.name, pt.type, 0)) {
        info->error = L"CryptAcquireContext: " + LastErrorText(GetLastError());
        return true;
    }

    info->uniqueName = GetProvParamString(prov, PP_UNIQUE_CONTAINER);
    ParseMedium(info->uniqueName, &info->medium, &info->reader);
    info->folderId = ParseFolderId(info->uniqueName);

    if (!ReadCertFromContainer(prov, info)) {
        // Контейнер без сертификата внутри. По ТЗ 8.3 это "orphan":
        // показываем строкой, а не прячем - иначе оператор не узнает,
        // что носитель вообще есть.
        info->error = L"сертификат не найден в контейнере";
    }

    if (info->keySpec) ProbeExportable(prov, info->keySpec, info);

    CryptReleaseContext(prov, 0);
    return true;
}

}  // namespace

CspInfo DetectCsp() {
    CspInfo info;
    // Перебираем все поколения, а не останавливаемся на первом: на машине
    // обычно доступны сразу несколько, и знать надо про все - от этого
    // зависит, какие контейнеры вообще откроются.
    for (size_t i = 0; i < kProviderCount; ++i) {
        HCRYPTPROV prov = 0;
        if (!CryptAcquireContextW(&prov, nullptr, kProviders[i].name,
                                  kProviders[i].type, CRYPT_VERIFYCONTEXT)) {
            continue;
        }
        info.installed = true;
        info.providers.push_back(kProviders[i].title);

        if (info.version.empty()) {
            DWORD ver = 0, cb = sizeof(ver);
            if (CryptGetProvParam(prov, PP_VERSION,
                                  reinterpret_cast<BYTE*>(&ver), &cb, 0)) {
                wchar_t buf[32];
                swprintf(buf, 32, L"%lu.%lu", (ver >> 8) & 0xFF, ver & 0xFF);
                info.version = buf;
            }
        }
        CryptReleaseContext(prov, 0);
    }
    return info;
}

// Уточняет тип носителя реальным сканом токенов (ТЗ 7.2, 1). До этого все
// SCARD-контейнеры помечены FileToken предварительно. Скан показывает, у каких
// на токене есть настоящая 6-файловая структура: есть - файловый (копируется),
// нет - ключ внутри чипа, аппаратный (копировать нечего).
//
// Имя ридера rtComLite (Aktiv Rutoken lite 0) не совпадает с коротким id из
// FQCN (rutoken_lt_39445e29), поэтому не пытаемся сопоставлять их по имени, а
// сканируем все токены и объединяем их папки-контейнеры. ID папки (folderId)
// уникально указывает на файловый контейнер: если он есть в объединении -
// контейнер файловый; если нет - помечаем аппаратным. Консервативно: при
// сомнении лучше исключить из копирования, чем копировать вслепую.
void RefineMediumByScan(std::vector<ContainerInfo>* items) {
    std::vector<std::wstring> readers = EnumReaders();
    if (readers.empty()) return;  // rtComLite недоступен - оставляем как есть

    std::set<int> fileFolders;
    bool anyOk = false;
    for (const std::wstring& r : readers) {
        TokenScan s = ScanToken(r);
        if (!s.ok) continue;
        anyOk = true;
        fileFolders.insert(s.containerFolders.begin(), s.containerFolders.end());
    }
    if (!anyOk) return;  // ни один токен не отсканировался - не трогаем

    for (ContainerInfo& c : *items) {
        if (c.medium != KeyMedium::FileToken) continue;  // реестр не трогаем
        c.medium = (c.folderId >= 0 && fileFolders.count(c.folderId))
                       ? KeyMedium::FileToken
                       : KeyMedium::HardWare;
    }
}

std::vector<ContainerInfo> EnumerateContainers() {
    std::vector<ContainerInfo> out;
    // Один и тот же физический контейнер виден под всеми типами провайдера
    // (75/80/81), поэтому без дедупликации каждый попадает в вывод трижды.
    // Ключ - PP_UNIQUE_CONTAINER: он привязан к носителю и не зависит от типа.
    std::set<std::wstring> seen;

    for (size_t i = 0; i < kProviderCount; ++i) {
        const ProviderType& pt = kProviders[i];

        HCRYPTPROV prov = 0;
        if (!CryptAcquireContextW(&prov, nullptr, pt.name, pt.type,
                                  CRYPT_VERIFYCONTEXT)) {
            continue;
        }

        // PP_ENUMCONTAINERS отдаёт имена в ANSI. Первый вызов с CRYPT_FIRST,
        // дальше CRYPT_NEXT до исчерпания.
        DWORD flags = CRYPT_FIRST;
        for (;;) {
            DWORD cb = 0;
            if (!CryptGetProvParam(prov, PP_ENUMCONTAINERS, nullptr, &cb, flags)) {
                break;
            }
            std::vector<BYTE> buf(cb ? cb : 1024);
            cb = static_cast<DWORD>(buf.size());
            if (!CryptGetProvParam(prov, PP_ENUMCONTAINERS, buf.data(), &cb,
                                   flags)) {
                break;
            }

            std::wstring name =
                AnsiToWide(reinterpret_cast<const char*>(buf.data()));
            if (!name.empty()) {
                ContainerInfo info;
                ResolveOne(pt, name, &info);
                // Дедуп по уникальному имени. Если его получить не удалось,
                // падаем обратно на имя контейнера - лучше показать дубль,
                // чем потерять носитель.
                const std::wstring& key =
                    info.uniqueName.empty() ? info.name : info.uniqueName;
                if (seen.insert(key).second) out.push_back(info);
            }

            flags = CRYPT_NEXT;
        }

        CryptReleaseContext(prov, 0);
    }

    RefineMediumByScan(&out);
    return out;
}

int DaysUntil(const FILETIME& ft) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    ULARGE_INTEGER a, b;
    a.LowPart = ft.dwLowDateTime;
    a.HighPart = ft.dwHighDateTime;
    b.LowPart = now.dwLowDateTime;
    b.HighPart = now.dwHighDateTime;

    long long diff = static_cast<long long>(a.QuadPart) -
                     static_cast<long long>(b.QuadPart);
    return static_cast<int>(diff / (10000000LL * 60 * 60 * 24));
}

std::wstring FormatDate(const FILETIME& ft) {
    SYSTEMTIME st;
    FILETIME local;
    if (!FileTimeToLocalFileTime(&ft, &local)) return L"?";
    if (!FileTimeToSystemTime(&local, &st)) return L"?";
    wchar_t buf[16];
    swprintf(buf, 16, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return buf;
}

}  // namespace certmig
