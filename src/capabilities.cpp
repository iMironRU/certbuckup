#include "capabilities.h"

#include <windows.h>
#include <winscard.h>
#include <urlmon.h>

#include "resolver.h"

namespace certmig {

namespace {

// Официальные точки загрузки. rtComLite взят из самой утилиты Контура -
// она ссылается на этот адрес в блоке диагностики.
const wchar_t* kHintCsp =
    L"КриптоПро CSP: https://www.cryptopro.ru/products/csp/downloads";
const wchar_t* kHintRtComLite =
    L"Компонент Рутокен (Контур): https://help.kontur.ru/rtComLite.exe";
const wchar_t* kHintRutokenDrv =
    L"Драйверы Рутокен: https://www.rutoken.ru/support/download/rutoken/";

bool FileExists(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// Читает строковое значение из реестра. wow - KEY_WOW64_32KEY или _64KEY,
// чтобы дотянуться и до 32-битных регистраций из 64-битного процесса.
bool ReadRegString(HKEY root, const wchar_t* subkey, const wchar_t* value,
                   REGSAM wow, std::wstring* out) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | wow, &h) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t buf[1024];
    DWORD cb = sizeof(buf);
    DWORD type = 0;
    LONG r = RegQueryValueExW(h, value, nullptr, &type,
                             reinterpret_cast<BYTE*>(buf), &cb);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return false;
    }
    buf[(cb / sizeof(wchar_t)) < 1024 ? (cb / sizeof(wchar_t)) : 1023] = 0;
    *out = buf;
    return true;
}

// Ищет csptest.exe в штатных местах установки CSP.
std::wstring FindCsptest() {
    const wchar_t* candidates[] = {
        L"C:\\Program Files (x86)\\Crypto Pro\\CSP\\csptest.exe",
        L"C:\\Program Files\\Crypto Pro\\CSP\\csptest.exe",
    };
    for (const wchar_t* c : candidates) {
        if (FileExists(c)) return c;
    }
    return L"";
}

// Разрешает ProgID COM-объекта в путь его InprocServer32, пробуя обе
// разрядные ветки реестра. Нужен и путь, и подтверждение, что DLL на месте.
bool ResolveComServer(const wchar_t* progId, std::wstring* clsidOut,
                      std::wstring* dllOut, bool* is32bit) {
    const REGSAM views[] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    for (REGSAM view : views) {
        std::wstring clsid;
        std::wstring progKey = std::wstring(progId) + L"\\CLSID";
        if (!ReadRegString(HKEY_CLASSES_ROOT, progKey.c_str(), nullptr, view,
                           &clsid)) {
            continue;
        }
        std::wstring inproc = L"CLSID\\" + clsid + L"\\InprocServer32";
        std::wstring dll;
        if (!ReadRegString(HKEY_CLASSES_ROOT, inproc.c_str(), nullptr, view,
                           &dll)) {
            continue;
        }
        *clsidOut = clsid;
        *dllOut = dll;
        *is32bit = (view == KEY_WOW64_32KEY);
        return true;
    }
    return false;
}

bool SmartCardServiceUp() {
    SCARDCONTEXT ctx = 0;
    LONG r = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx);
    if (r != SCARD_S_SUCCESS) return false;
    SCardReleaseContext(ctx);
    return true;
}

}  // namespace

bool InstallRtComLite(std::wstring* status) {
    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n >= MAX_PATH) {
        *status = L"нет временной папки";
        return false;
    }
    std::wstring dest = std::wstring(tmp) + L"rtComLite.exe";

    *status = L"скачиваю rtComLite…";
    // URLDownloadToFile надёжнее при инициализированном COM на этом потоке.
    HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    HRESULT hr = URLDownloadToFileW(nullptr,
                                    L"https://help.kontur.ru/rtComLite.exe",
                                    dest.c_str(), 0, nullptr);
    if (SUCCEEDED(init)) CoUninitialize();
    if (FAILED(hr)) {
        *status = L"не удалось скачать (нет сети?)";
        return false;
    }
    // Запускаем установщик - у него собственный интерфейс.
    HINSTANCE r = ShellExecuteW(nullptr, L"open", dest.c_str(), nullptr, nullptr,
                                SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(r) <= 32) {
        *status = L"не удалось запустить установщик";
        return false;
    }
    *status = L"установщик запущен — завершите установку и перезапустите";
    return true;
}

Environment ProbeEnvironment() {
    Environment env;

    // 1. КриптоПро CSP - основа инвентаризации и путь keycopy.
    CspInfo csp = DetectCsp();
    {
        Capability c;
        c.name = L"КриптоПро CSP";
        if (csp.installed) {
            c.state = CapState::Present;
            c.detail = L"версия " + csp.version;
            c.enables = L"инвентаризация (CryptoAPI), копирование через keycopy";
        } else {
            c.state = CapState::Missing;
            c.enables = L"без него не работает ни инвентаризация, ни keycopy";
            c.hint = kHintCsp;
        }
        env.caps.push_back(c);
    }

    // 2. csptest.exe - исполняемый примитив keycopy.
    env.csptestPath = FindCsptest();
    {
        Capability c;
        c.name = L"csptest.exe";
        if (!env.csptestPath.empty()) {
            c.state = CapState::Present;
            c.detail = env.csptestPath;
            c.enables = L"примитив keycopy (копирование контейнера)";
        } else {
            c.state = CapState::Missing;
            c.enables = L"нужен для копирования через КриптоПро";
            c.hint = kHintCsp;
        }
        env.caps.push_back(c);
    }

    // 3. rtComLite - сырое копирование файлов контейнера с Рутокена без CSP.
    std::wstring clsid, dll;
    bool comIs32 = false;
    bool rtOk = ResolveComServer(L"rtCOMLite.rtContext", &clsid, &dll, &comIs32);
    bool rtDllPresent = rtOk && FileExists(dll);
    // In-proc COM грузится только в процесс своей разрядности. Сверяем
    // разрядность компонента с нашей собственной (sizeof(void*)).
    const bool selfIs32 = (sizeof(void*) == 4);
    const bool bitnessOk = (comIs32 == selfIs32);
    {
        Capability c;
        c.name = L"rtComLite (COM Рутокен)";
        if (rtOk && rtDllPresent) {
            c.state = bitnessOk ? CapState::Present : CapState::Partial;
            c.detail = dll;
            if (!bitnessOk) {
                c.detail += comIs32 ? L"  (32-бит COM в 64-бит процессе)"
                                    : L"  (64-бит COM в 32-бит процессе)";
            }
            c.enables = L"копирование Рутокен-контейнера без КриптоПро";
        } else {
            c.state = CapState::Missing;
            c.enables = L"копирование Рутокена без КриптоПро";
            c.hint = kHintRtComLite;
        }
        env.caps.push_back(c);
    }

    // 4. PKCS#11 Рутокена - для собственного низкоуровневого чтения (задел).
    bool p11 = FileExists(L"C:\\Windows\\System32\\rtPKCS11ECP.dll") ||
               FileExists(L"C:\\Windows\\SysWOW64\\rtPKCS11ECP.dll");
    {
        Capability c;
        c.name = L"PKCS#11 Рутокен";
        c.state = p11 ? CapState::Present : CapState::Missing;
        c.enables = L"прямое чтение файлов токена (свой бэкенд, задел)";
        if (p11) {
            c.detail = L"rtPKCS11ECP.dll установлен";
        } else {
            c.hint = kHintRutokenDrv;
        }
        env.caps.push_back(c);
    }

    // 5. Служба смарт-карт - без неё токены не видны никому.
    {
        Capability c;
        c.name = L"Служба смарт-карт";
        c.state = SmartCardServiceUp() ? CapState::Present : CapState::Missing;
        c.enables = L"доступ к токенам (WinSCard)";
        if (c.state == CapState::Missing)
            c.detail = L"служба SCardSvr не отвечает";
        env.caps.push_back(c);
    }

    // Выводим доступные бэкенды копирования из набора возможностей.
    {
        CopyBackend b;
        b.name = L"КриптоПро keycopy";
        b.scope = L"реестр, файловые токены, FKC — любые носители CSP";
        if (csp.installed && !env.csptestPath.empty()) {
            b.available = true;
        } else {
            b.reason = csp.installed ? L"нет csptest.exe" : L"нет КриптоПро CSP";
        }
        env.backends.push_back(b);
    }
    {
        CopyBackend b;
        b.name = L"rtComLite (сырьё, без CSP)";
        b.scope = L"только Рутокен, файловые контейнеры";
        if (rtOk && rtDllPresent && bitnessOk) {
            b.available = true;
        } else if (rtOk && rtDllPresent) {
            b.reason = L"разрядность COM не совпадает с процессом";
        } else {
            b.reason = L"нет компонента rtComLite";
        }
        env.backends.push_back(b);
    }

    return env;
}

}  // namespace certmig
