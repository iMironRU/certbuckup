#include "rutoken.h"

#include <objbase.h>
#include <oaidl.h>

namespace certmig {

const wchar_t* ContainerFileName(int offset) {
    // ВНИМАНИЕ: физический файл folderId+1 - это masks.key, а +2 - primary.key
    // (и так же +4=masks2, +5=primary2). Раньше здесь было наоборот, и копия
    // не проходила проверку ключа (0x8009000A). Проверено побайтово против
    // рабочей копии, снятой утилитой Контура с того же контейнера: статичные
    // primary2/masks2 совпадают ТОЛЬКО при такой (обменянной) раскладке.
    // Роль определяется структурой: 60-байтный "30 36 04 20 .." = masks,
    // 70-байтный "30 22 04 20 .." = primary.
    switch (offset) {
        case 1: return L"masks.key";
        case 2: return L"primary.key";
        case 3: return L"header.key";
        case 4: return L"masks2.key";
        case 5: return L"primary2.key";
        case 6: return L"name.key";
        default: return L"";
    }
}

namespace {

// PIN Рутокена по умолчанию. Если он не сменён, входим сами - ровно как
// утилита Контура. Смысл: резервирование парка без ввода PIN на каждый токен.
const wchar_t kDefaultPin[] = L"12345678";

// --- Тонкая обёртка над IDispatch (позднее связывание по имени) ------------

VARIANT VI4(long v)              { VARIANT r; VariantInit(&r); r.vt = VT_I4;   r.lVal = v; return r; }
VARIANT VBstr(const wchar_t* s)  { VARIANT r; VariantInit(&r); r.vt = VT_BSTR; r.bstrVal = SysAllocString(s); return r; }
VARIANT VDisp(IDispatch* d)      { VARIANT r; VariantInit(&r); r.vt = VT_DISPATCH; r.pdispVal = d; return r; }

// Вызов метода/свойства по имени. args - в обычном порядке, разворот внутри.
HRESULT DInvoke(IDispatch* d, const wchar_t* name, WORD flags, VARIANT* res,
                VARIANT* args, UINT nargs) {
    if (!d) return E_POINTER;
    LPOLESTR nm = const_cast<LPOLESTR>(name);
    DISPID id = 0;
    HRESULT hr = d->GetIDsOfNames(IID_NULL, &nm, 1, LOCALE_USER_DEFAULT, &id);
    if (FAILED(hr)) return hr;

    std::vector<VARIANT> rev(nargs);
    for (UINT i = 0; i < nargs; ++i) rev[i] = args[nargs - 1 - i];

    DISPPARAMS dp = {nargs ? rev.data() : nullptr, nullptr, nargs, 0};
    if (res) VariantInit(res);
    EXCEPINFO ei;
    memset(&ei, 0, sizeof(ei));
    UINT argErr = 0;
    return d->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, flags, &dp, res, &ei,
                    &argErr);
}

HRESULT Call0(IDispatch* d, const wchar_t* name, VARIANT* res = nullptr) {
    return DInvoke(d, name, DISPATCH_METHOD, res, nullptr, 0);
}

// SAFEARRAY -> список long. Элементы могут быть VT_VARIANT или скалярами.
std::vector<long> ToLongVec(VARIANT& v) {
    std::vector<long> out;
    if (!(v.vt & VT_ARRAY)) return out;
    SAFEARRAY* sa = (v.vt & VT_BYREF) ? *v.pparray : v.parray;
    if (!sa) return out;
    VARTYPE et;
    if (FAILED(SafeArrayGetVartype(sa, &et))) return out;
    long lb = 0, ub = -1;
    SafeArrayGetLBound(sa, 1, &lb);
    SafeArrayGetUBound(sa, 1, &ub);
    for (long i = lb; i <= ub; ++i) {
        VARIANT el;
        VariantInit(&el);
        if (et == VT_VARIANT) {
            SafeArrayGetElement(sa, &i, &el);
        } else if (et == VT_I4) {
            long x = 0; SafeArrayGetElement(sa, &i, &x); el.vt = VT_I4; el.lVal = x;
        } else if (et == VT_I2) {
            short x = 0; SafeArrayGetElement(sa, &i, &x); el.vt = VT_I2; el.iVal = x;
        } else if (et == VT_BSTR) {
            BSTR b = nullptr; SafeArrayGetElement(sa, &i, &b); el.vt = VT_BSTR; el.bstrVal = b;
        } else {
            continue;
        }
        VARIANT as4;
        VariantInit(&as4);
        if (SUCCEEDED(VariantChangeType(&as4, &el, 0, VT_I4))) out.push_back(as4.lVal);
        VariantClear(&as4);
        VariantClear(&el);
    }
    return out;
}

// SAFEARRAY -> байты (ReadBinary). Быстрый путь для VT_UI1.
std::vector<BYTE> ToByteVec(VARIANT& v) {
    std::vector<BYTE> out;
    if (!(v.vt & VT_ARRAY)) return out;
    SAFEARRAY* sa = (v.vt & VT_BYREF) ? *v.pparray : v.parray;
    if (!sa) return out;
    VARTYPE et;
    if (FAILED(SafeArrayGetVartype(sa, &et))) return out;
    long lb = 0, ub = -1;
    SafeArrayGetLBound(sa, 1, &lb);
    SafeArrayGetUBound(sa, 1, &ub);
    if (ub < lb) return out;
    if (et == VT_UI1) {
        void* p = nullptr;
        if (SUCCEEDED(SafeArrayAccessData(sa, &p))) {
            out.assign(static_cast<BYTE*>(p),
                       static_cast<BYTE*>(p) + (ub - lb + 1));
            SafeArrayUnaccessData(sa);
        }
        return out;
    }
    for (long i = lb; i <= ub; ++i) {
        VARIANT el;
        VariantInit(&el);
        SafeArrayGetElement(sa, &i, &el);
        VARIANT b;
        VariantInit(&b);
        if (SUCCEEDED(VariantChangeType(&b, &el, 0, VT_UI1))) out.push_back(b.bVal);
        VariantClear(&b);
        VariantClear(&el);
    }
    return out;
}

std::wstring HrText(HRESULT hr) {
    wchar_t buf[32];
    swprintf(buf, 32, L"0x%08lX", static_cast<unsigned long>(hr));
    return buf;
}

// Держатель COM-инициализации: аккуратно закрыть только если сами открыли.
struct ComInit {
    bool owned = false;
    ComInit() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        owned = SUCCEEDED(hr);  // S_FALSE (уже инициализирован) тоже успех
    }
    ~ComInit() {
        if (owned) CoUninitialize();
    }
};

// Открыть контекст rtComLite и один ридер с авторизацией дефолтным PIN.
// Возвращает false и заполняет err, если PIN не дефолтный либо COM недоступен.
// При успехе ctx и reader живут до RtClose().
bool RtOpen(const std::wstring& readerName, IDispatch** ctxOut,
            IDispatch** readerOut, std::wstring* err) {
    *ctxOut = nullptr;
    *readerOut = nullptr;

    CLSID clsid;
    HRESULT hr = CLSIDFromProgID(L"rtCOMLite.rtContext", &clsid);
    if (FAILED(hr)) { *err = L"нет rtComLite (CLSIDFromProgID " + HrText(hr) + L")"; return false; }

    IDispatch* ctx = nullptr;
    hr = CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
                          reinterpret_cast<void**>(&ctx));
    if (FAILED(hr)) { *err = L"CoCreateInstance " + HrText(hr); return false; }

    if (FAILED(hr = Call0(ctx, L"Acquire"))) {
        *err = L"Acquire " + HrText(hr); ctx->Release(); return false;
    }

    VARIANT a[3] = {VBstr(readerName.c_str()), VI4(2), VI4(5000)};
    VARIANT r;
    hr = DInvoke(ctx, L"OpenReader", DISPATCH_METHOD, &r, a, 3);
    VariantClear(&a[0]);
    if (FAILED(hr) || r.vt != VT_DISPATCH || !r.pdispVal) {
        *err = L"OpenReader " + HrText(hr); ctx->Release(); return false;
    }
    IDispatch* reader = r.pdispVal;

    if (FAILED(hr = Call0(reader, L"BeginTransaction"))) {
        *err = L"BeginTransaction " + HrText(hr);
        reader->Release(); ctx->Release(); return false;
    }

    // Только дефолтный PIN. Не дефолтный - выходим с явной причиной: ввод
    // PIN оператором это отдельный сценарий, здесь его нет намеренно.
    VARIANT pinType = VI4(2);
    VARIANT isDef;
    hr = DInvoke(reader, L"IsPINDefault", DISPATCH_METHOD, &isDef, &pinType, 1);
    bool def = SUCCEEDED(hr) && (isDef.vt == VT_BOOL) && (isDef.boolVal != 0);
    if (!def) {
        *err = L"PIN не дефолтный (нужен ввод оператора)";
        Call0(reader, L"EndTransaction");
        reader->Release(); ctx->Release(); return false;
    }

    VARIANT auth[2] = {VI4(2), VBstr(kDefaultPin)};
    hr = DInvoke(reader, L"AuthenticateOwner", DISPATCH_METHOD, nullptr, auth, 2);
    VariantClear(&auth[1]);
    if (FAILED(hr)) {
        *err = L"AuthenticateOwner " + HrText(hr);
        Call0(reader, L"EndTransaction");
        reader->Release(); ctx->Release(); return false;
    }

    *ctxOut = ctx;
    *readerOut = reader;
    return true;
}

void RtClose(IDispatch* ctx, IDispatch* reader) {
    if (reader) {
        VARIANT t = VI4(2);
        DInvoke(reader, L"ResetAccessRights", DISPATCH_METHOD, nullptr, &t, 1);
        Call0(reader, L"EndTransaction");
    }
    if (ctx && reader) {
        VARIANT a[2] = {VDisp(reader), VI4(0)};  // 0 == LEAVE
        DInvoke(ctx, L"CloseReader", DISPATCH_METHOD, nullptr, a, 2);
    }
    if (reader) reader->Release();
    if (ctx) {
        Call0(ctx, L"Free");
        ctx->Release();
    }
}

// Является ли текущая папка (folderId) валидным файловым контейнером:
// ровно шесть файлов с ID folderId+1 .. folderId+6.
bool IsContainerFolder(int folderId, const std::vector<long>& files) {
    if (folderId <= 0 || files.size() != 6) return false;
    std::set<long> ids(files.begin(), files.end());
    for (int k = 1; k <= 6; ++k) {
        if (!ids.count(static_cast<long>(folderId) + k)) return false;
    }
    return true;
}

// Рекурсивный обход. folderId - ID текущей папки (0 для корня).
void Walk(IDispatch* reader, int folderId, std::set<int>* found) {
    VARIANT rf, ri;
    if (FAILED(Call0(reader, L"EnumFolders", &rf))) return;
    if (FAILED(Call0(reader, L"EnumFiles", &ri))) { VariantClear(&rf); return; }
    std::vector<long> folders = ToLongVec(rf);
    std::vector<long> files = ToLongVec(ri);
    VariantClear(&rf);
    VariantClear(&ri);

    if (IsContainerFolder(folderId, files)) found->insert(folderId);

    for (long child : folders) {
        VARIANT c = VI4(child);
        if (SUCCEEDED(DInvoke(reader, L"SelectFolder", DISPATCH_METHOD, nullptr,
                              &c, 1))) {
            Walk(reader, static_cast<int>(child), found);
            Call0(reader, L"SelectUpperFolder");
        }
    }
}

}  // namespace

std::vector<std::wstring> EnumReaders() {
    std::vector<std::wstring> out;
    ComInit com;

    CLSID clsid;
    if (FAILED(CLSIDFromProgID(L"rtCOMLite.rtContext", &clsid))) return out;
    IDispatch* ctx = nullptr;
    if (FAILED(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IDispatch,
                                reinterpret_cast<void**>(&ctx))))
        return out;
    if (SUCCEEDED(Call0(ctx, L"Acquire"))) {
        VARIANT r;
        if (SUCCEEDED(Call0(ctx, L"EnumReaders", &r)) && (r.vt & VT_ARRAY)) {
            SAFEARRAY* sa = (r.vt & VT_BYREF) ? *r.pparray : r.parray;
            if (sa) {
                long lb = 0, ub = -1;
                SafeArrayGetLBound(sa, 1, &lb);
                SafeArrayGetUBound(sa, 1, &ub);
                for (long i = lb; i <= ub; ++i) {
                    VARIANT el;
                    VariantInit(&el);
                    if (SUCCEEDED(SafeArrayGetElement(sa, &i, &el))) {
                        VARIANT s;
                        VariantInit(&s);
                        if (SUCCEEDED(VariantChangeType(&s, &el, 0, VT_BSTR)) &&
                            s.bstrVal)
                            out.push_back(s.bstrVal);
                        VariantClear(&s);
                    }
                    VariantClear(&el);
                }
            }
        }
        VariantClear(&r);
        Call0(ctx, L"Free");
    }
    ctx->Release();
    return out;
}

TokenScan ScanToken(const std::wstring& readerName) {
    TokenScan scan;
    ComInit com;

    IDispatch* ctx = nullptr;
    IDispatch* reader = nullptr;
    if (!RtOpen(readerName, &ctx, &reader, &scan.error)) return scan;

    HRESULT hr = Call0(reader, L"SelectMF");
    if (SUCCEEDED(hr)) {
        Walk(reader, 0, &scan.containerFolders);
        scan.ok = true;
    } else {
        scan.error = L"SelectMF " + HrText(hr);
    }

    RtClose(ctx, reader);
    return scan;
}

namespace {

// Ищет папку folderId в дереве и читает её шесть файлов.
bool FindAndRead(IDispatch* reader, int wantFolder, int curFolder,
                 std::vector<ContainerFile>* out) {
    VARIANT rf, ri;
    if (FAILED(Call0(reader, L"EnumFolders", &rf))) return false;
    std::vector<long> folders = ToLongVec(rf);
    VariantClear(&rf);

    if (curFolder == wantFolder) {
        (void)Call0(reader, L"EnumFiles", &ri);
        std::vector<long> files = ToLongVec(ri);
        VariantClear(&ri);
        if (!IsContainerFolder(curFolder, files)) return false;
        for (int off = 1; off <= 6; ++off) {
            int fid = curFolder + off;
            VARIANT sz, av[3] = {VI4(fid), VI4(0), VI4(0)};
            if (FAILED(DInvoke(reader, L"GetFileSize", DISPATCH_METHOD, &sz,
                               av, 1)))
                return false;
            long n = (sz.vt == VT_I4) ? sz.lVal : 0;
            av[2] = VI4(n);
            VARIANT data;
            if (FAILED(DInvoke(reader, L"ReadBinary", DISPATCH_METHOD, &data,
                               av, 3)))
                return false;
            ContainerFile cf;
            cf.name = ContainerFileName(off);
            cf.data = ToByteVec(data);
            VariantClear(&data);
            out->push_back(cf);
        }
        return true;
    }

    for (long child : folders) {
        VARIANT c = VI4(child);
        if (SUCCEEDED(DInvoke(reader, L"SelectFolder", DISPATCH_METHOD, nullptr,
                              &c, 1))) {
            bool done = FindAndRead(reader, wantFolder, static_cast<int>(child),
                                    out);
            Call0(reader, L"SelectUpperFolder");
            if (done) return true;
        }
    }
    return false;
}

}  // namespace

bool ReadContainer(const std::wstring& readerName, int folderId,
                   std::vector<ContainerFile>* out, std::wstring* error) {
    ComInit com;
    IDispatch* ctx = nullptr;
    IDispatch* reader = nullptr;
    if (!RtOpen(readerName, &ctx, &reader, error)) return false;

    bool ok = false;
    if (SUCCEEDED(Call0(reader, L"SelectMF"))) {
        ok = FindAndRead(reader, folderId, 0, out);
        if (!ok && error->empty()) *error = L"контейнер не найден на токене";
    } else if (error->empty()) {
        *error = L"SelectMF не удалась";
    }

    RtClose(ctx, reader);
    return ok;
}

}  // namespace certmig
