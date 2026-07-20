#include "capabilities.h"

#include <windows.h>
#include <winscard.h>
#include <urlmon.h>
#include <shellapi.h>
#include <winhttp.h>
#include <objbase.h>

#include <string>

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

    // Тихая установка: у инсталлятора Контура ядро NSIS, ключ /S ставит без
    // мастера. Регистрация COM-компонента требует прав администратора, поэтому
    // без повышения запускаем через "runas" (один запрос UAC), иначе "open".
    // Ждём завершения и проверяем, что компонент реально зарегистрировался.
    *status = L"устанавливаю rtComLite (тихо)…";
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = IsProcessElevated() ? L"open" : L"runas";
    sei.lpFile = dest.c_str();
    sei.lpParameters = L"/S";
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        *status = L"не удалось запустить установку (UAC отклонён?)";
        return false;
    }
    WaitForSingleObject(sei.hProcess, 180000);  // до 3 минут на установку
    CloseHandle(sei.hProcess);

    // Проверяем регистрацию COM-компонента Рутокена.
    CLSID clsid;
    bool registered =
        SUCCEEDED(CLSIDFromProgID(L"rtCOMLite.rtContext", &clsid));
    if (registered) {
        *status = L"rtComLite установлен.";
        return true;
    }
    *status = L"установка завершилась, но компонент не найден — перезапустите "
              L"программу или поставьте вручную.";
    return false;
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

bool StartSmartCardService(std::wstring* status) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        *status = L"Не удалось подключиться к диспетчеру служб.";
        return false;
    }
    SC_HANDLE svc = OpenServiceW(scm, L"SCardSvr",
                                 SERVICE_START | SERVICE_QUERY_STATUS |
                                     SERVICE_CHANGE_CONFIG);
    if (!svc) {
        DWORD e = GetLastError();
        CloseServiceHandle(scm);
        *status = (e == ERROR_ACCESS_DENIED)
                      ? L"Нет прав — запустите программу от администратора."
                      : L"Служба SCardSvr не найдена.";
        return false;
    }
    // Если служба отключена — вернуть в «запуск вручную», иначе StartService
    // отказом (ERROR_SERVICE_DISABLED). Требует прав администратора.
    ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                         SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr);

    bool ok = false;
    if (StartServiceW(svc, 0, nullptr)) {
        ok = true;
    } else {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) {
            ok = true;
        } else if (e == ERROR_ACCESS_DENIED) {
            *status = L"Нет прав — запустите программу от администратора.";
        } else {
            *status = L"Не удалось запустить службу (код " +
                      std::to_wstring(e) + L").";
        }
    }
    if (ok) {
        SERVICE_STATUS ss;
        for (int i = 0; i < 20; ++i) {  // ждём перехода в running (~3 с)
            if (!QueryServiceStatus(svc, &ss)) break;
            if (ss.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(150);
        }
        *status = L"Служба смарт-карт запущена.";
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool IsProcessElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el;
    DWORD cb = sizeof(el);
    bool elevated = false;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb))
        elevated = el.TokenIsElevated != 0;
    CloseHandle(tok);
    return elevated;
}

bool RelaunchAsAdmin() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";  // запрос UAC
    sei.lpFile = path;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) != FALSE;
}

namespace {

// HTTPS GET через WinHTTP. Пустая строка при любой ошибке/офлайне.
std::string HttpsGet(const wchar_t* host, const wchar_t* path, DWORD timeoutMs) {
    std::string body;
    HINTERNET s = WinHttpOpen(L"CertBuckUp-update-check",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return body;
    WinHttpSetTimeouts(s, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
    HINTERNET c = WinHttpConnect(s, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (c) {
        HINTERNET r = WinHttpOpenRequest(c, L"GET", path, nullptr,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
        if (r) {
            if (WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(r, nullptr)) {
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(r, &avail) || avail == 0) break;
                    std::string buf(avail, '\0');
                    DWORD rd = 0;
                    if (!WinHttpReadData(r, &buf[0], avail, &rd) || rd == 0) break;
                    buf.resize(rd);
                    body += buf;
                    if (body.size() > 200000) break;  // защита от гигантского тела
                }
            }
            WinHttpCloseHandle(r);
        }
        WinHttpCloseHandle(c);
    }
    WinHttpCloseHandle(s);
    return body;
}

// Разбор "x.y.z" в три числа. Хвост (напр. "-rc1") игнорируется.
void ParseVer(const std::string& v, int out[3]) {
    out[0] = out[1] = out[2] = 0;
    int idx = 0, cur = 0;
    bool any = false;
    for (char ch : v) {
        if (ch >= '0' && ch <= '9') {
            cur = cur * 10 + (ch - '0');
            any = true;
        } else if (ch == '.') {
            if (idx < 2) out[idx] = cur;
            ++idx;
            cur = 0;
            if (idx > 2) break;
        } else {
            break;  // конец числовой части
        }
    }
    if (any && idx <= 2) out[idx] = cur;
}

bool VersionGreater(const std::string& a, const std::string& b) {
    int va[3], vb[3];
    ParseVer(a, va);
    ParseVer(b, vb);
    for (int i = 0; i < 3; ++i) {
        if (va[i] != vb[i]) return va[i] > vb[i];
    }
    return false;
}

std::wstring Widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

std::string Narrow(const std::wstring& s) {
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr,
                                nullptr);
    std::string a(n > 0 ? n - 1 : 0, '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &a[0], n, nullptr, nullptr);
    return a;
}

}  // namespace

UpdateInfo CheckForUpdate(const std::wstring& currentVersion) {
    UpdateInfo u;
    std::string json = HttpsGet(L"api.github.com",
                                L"/repos/iMironRU/certbuckup/releases/latest",
                                4000);
    if (json.empty()) return u;  // офлайн / ошибка — тихо
    size_t p = json.find("\"tag_name\"");
    if (p == std::string::npos) { u.checked = true; return u; }
    p = json.find(':', p);
    if (p == std::string::npos) { u.checked = true; return u; }
    p = json.find('"', p);
    if (p == std::string::npos) { u.checked = true; return u; }
    size_t q = json.find('"', p + 1);
    if (q == std::string::npos) { u.checked = true; return u; }
    std::string tag = json.substr(p + 1, q - p - 1);  // напр. "v0.3.1"
    std::string ver = tag;
    if (!ver.empty() && (ver[0] == 'v' || ver[0] == 'V')) ver = ver.substr(1);

    u.checked = true;
    u.latest = Widen(tag);
    u.newer = VersionGreater(ver, Narrow(currentVersion));
    u.url = L"https://github.com/iMironRU/certbuckup/releases/latest";
    return u;
}

}  // namespace certmig
