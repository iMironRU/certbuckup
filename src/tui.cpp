#include "tui.h"

#include <windows.h>

#include <mutex>
#include <string>
#include <vector>

#include "backup.h"
#include "capabilities.h"
#include "resolver.h"

namespace certmig {

namespace {

// --- Палитра Nocturne: ремап 16-цветной таблицы консоли ---------------------
// Индексы, которыми пользуемся (остальные не трогаем).
enum {
    C_BG = 0,       // фон #161826
    C_SURFACE = 1,  // поверхность окна/диалога #232532
    C_NEUTRAL = 2,  // нейтраль-900 #292b31
    C_WARN = 4,     // предупреждение (битая копия) #e06c75
    C_ACCENT = 5,   // акцент #9184d9
    C_DIM = 8,      // приглушённый текст
    C_TEXT = 7,     // основной текст #e9e9ed
    C_ACCENTHI = 13,// светлый акцент #d2cefd
    C_WHITE = 15,
};

COLORREF Rgb(int r, int g, int b) {
    return static_cast<COLORREF>((b << 16) | (g << 8) | r);
}

// Таблица палитры Nocturne по индексам. Для VT-режима (Windows Terminal
// игнорирует палитру консоли, поэтому цвет задаём truecolor-escape'ами).
COLORREF g_pal[16];
void InitPalette() {
    for (int i = 0; i < 16; ++i) g_pal[i] = Rgb(0x80, 0x80, 0x80);
    g_pal[C_BG] = Rgb(0x16, 0x18, 0x26);
    g_pal[C_SURFACE] = Rgb(0x23, 0x25, 0x32);
    g_pal[C_NEUTRAL] = Rgb(0x29, 0x2b, 0x31);
    g_pal[C_WARN] = Rgb(0xe0, 0x6c, 0x75);
    g_pal[C_ACCENT] = Rgb(0x91, 0x84, 0xd9);
    g_pal[C_DIM] = Rgb(0x8a, 0x87, 0x94);
    g_pal[C_TEXT] = Rgb(0xe9, 0xe9, 0xed);
    g_pal[C_ACCENTHI] = Rgb(0xd2, 0xce, 0xfd);
    g_pal[C_WHITE] = Rgb(0xff, 0xff, 0xff);
}
inline int Rd(COLORREF c) { return c & 0xFF; }
inline int Gr(COLORREF c) { return (c >> 8) & 0xFF; }
inline int Bl(COLORREF c) { return (c >> 16) & 0xFF; }

// Атрибуты (fg | bg<<4).
inline WORD Attr(int fg, int bg) {
    return static_cast<WORD>((fg & 0x0F) | ((bg & 0x0F) << 4));
}

const WORD A_BG = Attr(C_TEXT, C_BG);
const WORD A_DIM = Attr(C_DIM, C_BG);
const WORD A_ACC = Attr(C_ACCENTHI, C_BG);
const WORD A_BORDER = Attr(C_ACCENT, C_BG);
const WORD A_SEL = Attr(C_WHITE, C_ACCENT);
const WORD A_SURF = Attr(C_TEXT, C_SURFACE);
const WORD A_SURFDIM = Attr(C_DIM, C_SURFACE);
const WORD A_SURFACC = Attr(C_ACCENTHI, C_SURFACE);
const WORD A_TAG = Attr(C_BG, C_ACCENT);
const WORD A_WARN = Attr(C_WARN, C_BG);       // текст-предупреждение
const WORD A_WARNTAG = Attr(C_BG, C_WARN);    // плашка "битая копия"

// Размер холста. Не константы: подстраиваются под фактическое окно консоли
// в Console::Init. По умолчанию - на случай дампа без консоли.
int W = 104, H = 32;

// Версия и репозиторий - показываются в футере и на экране окружения.
const wchar_t* kVersion = L"0.2.1";
const wchar_t* kRepoUrl = L"github.com/iMironRU/certbuckup";        // показ
const wchar_t* kRepoUrlFull = L"https://github.com/iMironRU/certbuckup";  // ссылка

// --- Холст ------------------------------------------------------------------
// Кликабельная ссылка (OSC 8): участок текста на строке, за которым URL.
struct Hyperlink {
    int x, y, len;
    std::wstring url;
};

struct Canvas {
    std::vector<CHAR_INFO> cells;
    std::vector<Hyperlink> links;
    Canvas() : cells(W * H) { Clear(A_BG); }

    void Clear(WORD attr) {
        for (CHAR_INFO& ci : cells) {
            ci.Char.UnicodeChar = L' ';
            ci.Attributes = attr;
        }
        links.clear();
    }
    void Put(int x, int y, wchar_t ch, WORD attr) {
        if (x < 0 || y < 0 || x >= W || y >= H) return;
        cells[y * W + x].Char.UnicodeChar = ch;
        cells[y * W + x].Attributes = attr;
    }
    void Text(int x, int y, const std::wstring& s, WORD attr, int maxw = -1) {
        int n = static_cast<int>(s.size());
        if (maxw >= 0 && n > maxw) n = maxw;
        for (int i = 0; i < n; ++i) Put(x + i, y, s[i], attr);
    }
    // Текст-ссылка: рисует и регистрирует кликабельную область (OSC 8).
    void LinkText(int x, int y, const std::wstring& s, WORD attr,
                  const std::wstring& url) {
        Text(x, y, s, attr);
        links.push_back({x, y, static_cast<int>(s.size()), url});
    }
    void Fill(int x, int y, int w, int h, WORD attr) {
        for (int j = 0; j < h; ++j)
            for (int i = 0; i < w; ++i) Put(x + i, y + j, L' ', attr);
    }
    // Двойная рамка (референс TUI: double-line, акцентный цвет).
    void Box(int x, int y, int w, int h, WORD attr) {
        Put(x, y, L'╔', attr);
        Put(x + w - 1, y, L'╗', attr);
        Put(x, y + h - 1, L'╚', attr);
        Put(x + w - 1, y + h - 1, L'╝', attr);
        for (int i = 1; i < w - 1; ++i) {
            Put(x + i, y, L'═', attr);
            Put(x + i, y + h - 1, L'═', attr);
        }
        for (int j = 1; j < h - 1; ++j) {
            Put(x, y + j, L'║', attr);
            Put(x + w - 1, y + j, L'║', attr);
        }
    }
};

std::wstring Pad(const std::wstring& s, int width) {
    int n = static_cast<int>(s.size());
    if (n >= width) {
        if (width <= 1) return s.substr(0, width);
        return s.substr(0, width - 1) + L"…";
    }
    return s + std::wstring(width - n, L' ');
}

// --- Модель данных ----------------------------------------------------------
struct Tok {
    std::wstring title;   // "Rutoken Lite"
    std::wstring sub;     // считыватель/модель
    bool hardware = false;  // ключи в чипе - копировать нельзя
    std::vector<int> certIdx;  // индексы в общем списке контейнеров
};

std::wstring FriendlyToken(const ContainerInfo& c) {
    std::wstring r = c.reader;
    auto has = [&](const wchar_t* s) { return r.find(s) != std::wstring::npos; };
    if (c.medium == KeyMedium::DiskFile) return L"Диск (FAT12)";
    if (c.medium == KeyMedium::Registry) return L"Реестр Windows";
    if (has(L"ecp") && c.medium == KeyMedium::HardWare) return L"Rutoken ЭЦП 2.0";
    if (has(L"ecp")) return L"Rutoken ЭЦП";
    if (has(L"lt") || has(L"lite")) return L"Rutoken Lite";
    return r;
}

std::vector<Tok> BuildTokens(const std::vector<ContainerInfo>& items) {
    std::vector<Tok> toks;
    for (int i = 0; i < static_cast<int>(items.size()); ++i) {
        const ContainerInfo& c = items[i];
        int found = -1;
        for (int t = 0; t < static_cast<int>(toks.size()); ++t)
            if (toks[t].sub == c.reader) { found = t; break; }
        if (found < 0) {
            Tok t;
            t.title = FriendlyToken(c);
            t.sub = c.reader;
            t.hardware = true;  // уточним ниже
            toks.push_back(t);
            found = static_cast<int>(toks.size()) - 1;
        }
        toks[found].certIdx.push_back(i);
        if (c.medium != KeyMedium::HardWare) toks[found].hardware = false;
    }
    return toks;
}

std::wstring OwnerOf(const ContainerInfo& c) {
    if (!c.surname.empty() || !c.given.empty())
        return c.surname + L" " + c.given;
    return c.subjectCN;
}

// Название юрлица (или ИП) - организация из сертификата. Для парка КЭП это
// главная идентичность, а не физлицо-держатель.
std::wstring OrgName(const ContainerInfo& c) {
    if (!c.subjectO.empty()) return c.subjectO;
    if (!c.subjectCN.empty()) return c.subjectCN;
    return OwnerOf(c);
}

// ИНН юрлица (даже для ИП), с откатом на физлицо, если юрлица нет.
std::wstring LegalInn(const ContainerInfo& c) {
    if (!c.innLe.empty()) return c.innLe;
    if (!c.inn.empty()) return c.inn;
    return L"—";
}

// --- Состояние --------------------------------------------------------------
enum class Screen { Tokens, Certs };
enum class Modal { None, Dest, Blocked, Info, Exit, Result, Overwrite };

enum DestKind { DEST_FOLDER, DEST_REGISTRY, DEST_CPSTORE, DEST_TODO };
struct DestOpt {
    std::wstring label;
    std::wstring path;      // куда (для папок)
    int kind;               // DestKind
};

struct LogRow {
    std::wstring ts, org, inn, dest, status;
    bool ok;
};

struct State {
    std::vector<ContainerInfo> items;
    std::vector<Tok> toks;
    std::vector<bool> guidName;  // у контейнера сейчас GUID-образное имя
    std::vector<int> copyLayout;  // раскладка копии: см. CopyLayout (0..3)

    Screen screen = Screen::Tokens;
    Modal modal = Modal::None;

    // Курсор назначения по умолчанию - "Папка рядом с приложением" (индекс 2).
    int tokCursor = 0, certCursor = 0, destCursor = 2, exitCursor = 0;
    int overwriteCursor = 0;  // 0 = перезаписать, 1 = отмена
    bool eatDbl = false;      // проглотить двойной клик после перехода экрана
    int selTok = 0;
    int cspMajor = 0;         // мажор версии CSP: снятие флага показываем
                              // только для 4.x (в 5.x контроль заголовка)
    bool flagClear = false;   // чекбокс "снять признак неэкспортируемости"
    std::wstring resultMsg;
    int resultKind = 0;       // 0 ok, 1 пропуск, 2 ошибка
    std::vector<LogRow> log;

    std::vector<DestOpt> dests = {
        {L"Диск D:\\", L"D:\\Сертификаты", DEST_FOLDER},
        {L"Реестр Windows", L"", DEST_REGISTRY},
        {L"Папка рядом с приложением", DefaultBackupDir(), DEST_FOLDER},
        {L"Папка КриптоПро", CryptoProStoreDir(), DEST_CPSTORE},
    };
};

// --- Отрисовка экранов ------------------------------------------------------
void DrawFooter(Canvas& cv, const std::wstring& keys) {
    cv.Fill(0, H - 1, W, 1, A_DIM);
    cv.Text(2, H - 1, keys, A_DIM);
    // Версия справа - кликабельная ссылка на репозиторий.
    std::wstring ver = std::wstring(L"CertBuckUp ") + kVersion;
    cv.LinkText(W - static_cast<int>(ver.size()) - 2, H - 1, ver, A_DIM,
                kRepoUrlFull);
}

void DrawWindow(Canvas& cv, const std::wstring& crumb, const std::wstring& right) {
    cv.Box(0, 0, W, H - 1, A_BORDER);
    cv.Text(2, 0, L" " + crumb + L" ", A_ACC);
    if (!right.empty())
        cv.Text(W - static_cast<int>(right.size()) - 3, 0, L" " + right + L" ",
                A_DIM);
}

void RenderTokens(Canvas& cv, const State& s) {
    cv.Clear(A_BG);
    DrawWindow(cv, L"Токены",
               L"● устройств: " + std::to_wstring(s.toks.size()));
    int y = 2;
    for (int i = 0; i < static_cast<int>(s.toks.size()); ++i) {
        const Tok& t = s.toks[i];
        bool sel = (i == s.tokCursor);
        WORD a = sel ? A_SEL : A_BG;
        cv.Fill(2, y, W - 4, 2, a);
        cv.Text(4, y, L"▣ " + t.title, sel ? A_SEL : A_ACC, W - 30);
        cv.Text(4, y + 1,
                L"  " + t.sub + L" · сертификатов: " +
                    std::to_wstring(t.certIdx.size()),
                sel ? A_SEL : A_DIM, W - 30);
        if (t.hardware) {
            std::wstring tag = L" только чтение ";
            cv.Text(W - static_cast<int>(tag.size()) - 4, y, tag, A_TAG);
        }
        y += 3;
    }
    DrawFooter(cv,
               L"↑↓/колесо   Enter или клик — открыть   F3 инфо   F10 выход");
}

void RenderCerts(Canvas& cv, const State& s) {
    cv.Clear(A_BG);
    const Tok& t = s.toks[s.selTok];
    DrawWindow(cv, L"Токены › " + t.title, L"");
    if (t.certIdx.empty()) {
        cv.Text(W / 2 - 20, H / 2, L"На этом носителе нет сертификатов.", A_DIM);
        DrawFooter(cv, L"Esc назад   F10 выход");
        return;
    }
    int y = 2;
    for (int k = 0; k < static_cast<int>(t.certIdx.size()); ++k) {
        const ContainerInfo& c = s.items[t.certIdx[k]];
        bool sel = (k == s.certCursor);
        WORD a = sel ? A_SEL : A_BG;
        bool copyable = (c.medium == KeyMedium::FileToken ||
                         c.medium == KeyMedium::DiskFile);
        cv.Fill(2, y, W - 4, 2, a);
        std::wstring icon = copyable ? L"▤ " : L"⚿ ";
        // Главная строка - юрлицо (или ИП); физлицо-держатель в информации F3.
        cv.Text(4, y, icon + OrgName(c), sel ? A_SEL : A_ACC, W - 30);
        // ИНН юрлица первым: организации различаются именно им (ТЗ 2.1).
        std::wstring meta = L"ИНН " + LegalInn(c) + L" · до " +
                            FormatDate(c.notAfter) + L" · " +
                            (c.thumbprint.size() >= 8 ? c.thumbprint.substr(0, 8)
                                                      : c.thumbprint);
        cv.Text(4, y + 1, L"  " + meta, sel ? A_SEL : A_DIM, W - 30);
        int gi = t.certIdx[k];
        bool broken = gi < static_cast<int>(s.copyLayout.size()) &&
                      s.copyLayout[gi] ==
                          static_cast<int>(CopyLayout::Swapped);
        bool guid = gi < static_cast<int>(s.guidName.size()) && s.guidName[gi];
        std::wstring tag;
        WORD tagAttr = A_TAG;
        if (broken) {  // важнее прочего: копия не даст рабочий ключ, пока не чинить
            tag = L" битая копия · F7 починить ";
            tagAttr = A_WARNTAG;
        } else if (c.medium == KeyMedium::HardWare) {
            tag = L" устройство: только чтение ";
        } else if (guid) {
            tag = L" имя-GUID: F6 переименовать ";
        } else if (c.exportable == Exportable::No) {
            tag = L" ключ неэкспортируемый ";
        }
        if (!tag.empty())
            cv.Text(W - static_cast<int>(tag.size()) - 4, y, tag, tagAttr);
        y += 3;
    }
    DrawFooter(cv,
               L"↑↓   F5 копировать   F6 переименовать   F7 починить   "
               L"F3 инфо   Esc назад   F10 выход");
}

void DrawDialog(Canvas& cv, int x, int y, int w, int h,
                const std::wstring& title) {
    cv.Fill(x, y, w, h, A_SURF);
    cv.Box(x, y, w, h, A_SURFACC);
    cv.Text(x + 3, y, L" " + title + L" ", A_SURFACC);
}

void RenderDest(Canvas& cv, const State& s) {
    const ContainerInfo& c = s.items[s.toks[s.selTok].certIdx[s.certCursor]];
    // Широкий диалог, чтобы путь помещался целиком; каждый вариант - две
    // строки (название + полный путь), путь не обрезается.
    int w = W - 8 > 96 ? 96 : W - 8;
    int h = 20, x = (W - w) / 2, y = (H - h) / 2;
    DrawDialog(cv, x, y, w, h, L"Куда скопировать контейнер");
    cv.Text(x + 3, y + 2, OrgName(c) + L"  ·  ИНН " + LegalInn(c), A_SURFACC,
            w - 6);

    int ry = y + 4;
    for (int i = 0; i < static_cast<int>(s.dests.size()); ++i) {
        const DestOpt& d = s.dests[i];
        bool sel = (i == s.destCursor);
        cv.Fill(x + 2, ry, w - 4, 2, A_SURF);
        std::wstring radio = sel ? L"(●) " : L"( ) ";
        std::wstring line = radio + d.label;
        if (d.kind == DEST_TODO) line += L"  (в разработке)";
        cv.Text(x + 4, ry, line, sel ? A_SURFACC : A_SURF, w - 8);
        std::wstring path =
            d.kind == DEST_FOLDER || d.kind == DEST_CPSTORE ? d.path
            : d.kind == DEST_REGISTRY
                ? L"HKLM\\...\\Crypto Pro\\...\\Keys (нужен админ)"
                : L"—";
        cv.Text(x + 8, ry + 1, path, sel ? A_SURF : A_SURFDIM, w - 12);
        ry += 2;
    }
    ry += 1;
    // Чекбокс снятия признака - только для CSP 4.x. В 5.x заголовок под
    // контролем целостности, флип его ломает, поэтому там не предлагаем.
    if (c.exportable == Exportable::No && s.cspMajor > 0 && s.cspMajor <= 4) {
        std::wstring cb = s.flagClear ? L"[✓] " : L"[ ] ";
        cv.Text(x + 4, ry, cb + L"Снять признак неэкспортируемости (пробел)",
                A_SURF, w - 8);
    }
    cv.Text(x + 3, y + h - 2, L"↑↓ выбор · Enter копировать · Esc отмена",
            A_SURFDIM, w - 6);
}

void RenderOverwrite(Canvas& cv, const State& s) {
    int w = 60, h = 9, x = (W - w) / 2, y = (H - h) / 2;
    DrawDialog(cv, x, y, w, h, L"Папка уже существует");
    cv.Text(x + 3, y + 2, L"Копия этого контейнера уже есть в этой папке.",
            A_SURF, w - 6);
    const wchar_t* opts[2] = {L"Перезаписать", L"Отмена"};
    for (int i = 0; i < 2; ++i) {
        bool sel = (i == s.overwriteCursor);
        cv.Text(x + 6, y + 4 + i, (sel ? L"► " : L"  ") + std::wstring(opts[i]),
                sel ? A_SURFACC : A_SURF);
    }
}

void RenderBlocked(Canvas& cv, const State& s) {
    int w = 62, h = 9, x = (W - w) / 2, y = (H - h) / 2;
    DrawDialog(cv, x, y, w, h, L"Копирование невозможно");
    const Tok& t = s.toks[s.selTok];
    cv.Text(x + 3, y + 3, L"Токен «" + t.title + L"» хранит ключ в чипе.",
            A_SURF, w - 6);
    cv.Text(x + 3, y + 4, L"Контейнер экспорту не поддаётся (аппаратный ключ).",
            A_SURF, w - 6);
    cv.Text(x + 3, y + h - 2, L"Enter / Esc — закрыть", A_SURFDIM);
}

void RenderInfo(Canvas& cv, const State& s) {
    int w = 70, h = 18, x = (W - w) / 2, y = (H - h) / 2;
    std::vector<std::pair<std::wstring, std::wstring>> rows;
    std::wstring title;
    if (s.screen == Screen::Tokens) {
        const Tok& t = s.toks[s.tokCursor];
        title = t.title;
        rows = {{L"Считыватель", t.sub},
                {L"Сертификатов", std::to_wstring(t.certIdx.size())},
                {L"Экспорт с устройства", t.hardware ? L"запрещён" : L"разрешён"}};
    } else {
        const ContainerInfo& c =
            s.items[s.toks[s.selTok].certIdx[s.certCursor]];
        title = OrgName(c);
        rows = {{L"ИНН юрлица", c.innLe.empty() ? L"—" : c.innLe},
                {L"Держатель (ФИО)", OwnerOf(c)},
                {L"ИНН физлица", c.inn.empty() ? L"—" : c.inn},
                {L"СНИЛС", c.snils},
                {L"Действует с", FormatDate(c.notBefore)},
                {L"Действует по", FormatDate(c.notAfter)},
                {L"Отпечаток", c.thumbprint},
                {L"Ключ экспортируемый",
                 c.exportable == Exportable::No ? L"нет" : L"да"}};
    }
    DrawDialog(cv, x, y, w, h, L"Информация");
    cv.Text(x + 3, y + 2, title, A_SURFACC, w - 6);
    int ry = y + 4;
    for (auto& r : rows) {
        cv.Text(x + 4, ry, Pad(r.first, 22), A_SURFDIM);
        cv.Text(x + 26, ry, r.second, A_SURF, w - 30);
        ry += 1;
    }
    cv.Text(x + 3, y + h - 2, L"Esc — закрыть", A_SURFDIM);
}

void RenderResult(Canvas& cv, const State& s) {
    cv.Clear(A_BG);
    DrawWindow(cv, L"Результат операции", L"");

    // Статус-плашка: рамка на поверхности, крупная иконка + сообщение.
    int tileW = W - 6;
    cv.Fill(3, 2, tileW, 3, A_SURF);
    WORD markAttr = s.resultKind == 0 ? A_SURFACC : A_SURFDIM;
    std::wstring mark = s.resultKind == 0   ? L"[ OK ]"
                        : s.resultKind == 1 ? L"[ • ]"
                                            : L"[ !! ]";
    cv.Text(5, 3, mark, markAttr);
    cv.Text(14, 3, s.resultMsg, A_SURF, tileW - 14);

    // Таблица журнала за сеанс.
    const int cT = 4, cOrg = 16, cInn = 42, cDest = 60;
    int hy = 7;
    cv.Text(cT, hy, L"Журнал операций за сеанс", A_ACC);
    hy += 1;
    cv.Text(cT, hy, L"Время", A_DIM);
    cv.Text(cOrg, hy, L"Организация", A_DIM);
    cv.Text(cInn, hy, L"ИНН", A_DIM);
    cv.Text(cDest, hy, L"Назначение", A_DIM);
    cv.Text(cDest + 24, hy, L"Статус", A_DIM);
    hy += 1;
    cv.Text(cT, hy, std::wstring(W - 8, L'─'), A_DIM);
    hy += 1;

    int y = hy;
    for (int i = static_cast<int>(s.log.size()) - 1; i >= 0 && y < H - 3; --i) {
        const LogRow& r = s.log[i];
        WORD a = r.ok ? A_BG : A_DIM;
        cv.Text(cT, y, r.ts, a);
        cv.Text(cOrg, y, r.org, a, cInn - cOrg - 1);
        cv.Text(cInn, y, r.inn, a, cDest - cInn - 1);
        cv.Text(cDest, y, r.dest, a, 22);
        cv.Text(cDest + 24, y, r.status, r.ok ? A_ACC : A_DIM);
        y += 1;
    }
    DrawFooter(cv, L"Enter / Esc — к списку сертификатов   F10 выход");
}

void RenderExit(Canvas& cv, const State& s) {
    int w = 46, h = 9, x = (W - w) / 2, y = (H - h) / 2;
    DrawDialog(cv, x, y, w, h, L"Завершить работу?");
    const wchar_t* opts[2] = {L"Да, выйти", L"Нет, остаться"};
    for (int i = 0; i < 2; ++i) {
        bool sel = (i == s.exitCursor);
        cv.Text(x + 6, y + 3 + i, (sel ? L"► " : L"  ") + std::wstring(opts[i]),
                sel ? A_SURFACC : A_SURF);
    }
}

// Экран окружения - показывается, пока идёт скан контейнеров. Если чего-то
// не хватает, прямо тут написано, что и откуда скачать (ТЗ 3).
void RenderEnvironment(Canvas& cv, const Environment& env,
                       const std::wstring& status) {
    cv.Clear(A_BG);
    cv.Box(0, 0, W, H, A_BORDER);
    cv.Text(2, 0, L" Окружение ", A_ACC);
    // Репозиторий (кликабельно) и версия - в правой части шапки.
    std::wstring url = kRepoUrl;
    std::wstring ver = std::wstring(L"  ·  v") + kVersion + L" ";
    int x0 = W - static_cast<int>(url.size() + ver.size()) - 3;
    cv.LinkText(x0, 0, url, A_ACC, kRepoUrlFull);
    cv.Text(x0 + static_cast<int>(url.size()), 0, ver, A_DIM);
    int y = 2;
    for (const Capability& c : env.caps) {
        std::wstring mark = c.state == CapState::Present   ? L"[+]"
                            : c.state == CapState::Partial ? L"[~]"
                                                           : L"[-]";
        WORD a = c.state == CapState::Present ? A_ACC : A_DIM;
        cv.Text(3, y, mark + L" " + c.name +
                          (c.detail.empty() ? L"" : L"  " + c.detail),
                a, W - 6);
        if (c.state != CapState::Present && !c.hint.empty()) {
            cv.Text(7, y + 1, L"↓ " + c.hint, A_DIM, W - 10);
            y += 2;
        } else {
            y += 1;
        }
    }
    y += 1;
    cv.Text(3, y, L"Способы копирования:", A_DIM);
    y += 1;
    for (const CopyBackend& b : env.backends) {
        std::wstring mark = b.available ? L"[+]" : L"[-]";
        cv.Text(3, y, mark + L" " + b.name, b.available ? A_ACC : A_DIM, W - 6);
        y += 1;
    }
    cv.Fill(2, H - 2, W - 4, 1, A_BG);
    cv.Text(3, H - 2, status, A_ACC, W - 6);
}

void Render(Canvas& cv, const State& s) {
    if (s.modal == Modal::Result) { RenderResult(cv, s); return; }
    if (s.screen == Screen::Tokens) RenderTokens(cv, s);
    else RenderCerts(cv, s);
    switch (s.modal) {
        case Modal::Dest: RenderDest(cv, s); break;
        case Modal::Overwrite: RenderDest(cv, s); RenderOverwrite(cv, s); break;
        case Modal::Blocked: RenderBlocked(cv, s); break;
        case Modal::Info: RenderInfo(cv, s); break;
        case Modal::Exit: RenderExit(cv, s); break;
        default: break;
    }
}

// --- Консоль ----------------------------------------------------------------
// Два пути вывода:
//   VT (Windows Terminal / Win10+): alt-screen буфер + truecolor-escape'ы.
//     Единственный надёжный способ на Windows Terminal: палитру консоли он
//     игнорирует, а legacy WriteConsoleOutput не покрывает окно (артефакты,
//     "просвечивание" приглашения). VT даёт точные цвета Nocturne и чистую
//     очистку экрана.
//   Legacy (Win7, где VT нет): ремап палитры + WriteConsoleOutput CHAR_INFO.
struct Console {
    HANDLE out, in;
    DWORD savedOutMode = 0, savedInMode = 0;
    CONSOLE_SCREEN_BUFFER_INFOEX savedInfo{};
    CONSOLE_CURSOR_INFO savedCursor{};
    bool vt = false, ok = false;

    void WriteVT(const std::wstring& s) {
        DWORD w = 0;
        WriteConsoleW(out, s.c_str(), static_cast<DWORD>(s.size()), &w, nullptr);
    }

    void Init() {
        InitPalette();
        out = GetStdHandle(STD_OUTPUT_HANDLE);
        in = GetStdHandle(STD_INPUT_HANDLE);
        if (out == INVALID_HANDLE_VALUE || in == INVALID_HANDLE_VALUE) return;

        savedInfo.cbSize = sizeof(savedInfo);
        if (!GetConsoleScreenBufferInfoEx(out, &savedInfo)) return;  // нет консоли
        GetConsoleMode(out, &savedOutMode);
        GetConsoleMode(in, &savedInMode);
        GetConsoleCursorInfo(out, &savedCursor);

        int cols = savedInfo.srWindow.Right - savedInfo.srWindow.Left + 1;
        int rows = savedInfo.srWindow.Bottom - savedInfo.srWindow.Top + 1;
        W = cols < 40 ? 40 : (cols > 200 ? 200 : cols);
        H = rows < 12 ? 12 : (rows > 60 ? 60 : rows);

        // Пробуем включить VT.
        DWORD om = savedOutMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                   DISABLE_NEWLINE_AUTO_RETURN;
        vt = SetConsoleMode(out, om) != 0;
        // Мышь + события окна; ENABLE_EXTENDED_FLAGS выключает quick-edit
        // (иначе клики уходят на выделение текста, а не в приложение).
        SetConsoleMode(in, ENABLE_EXTENDED_FLAGS | ENABLE_MOUSE_INPUT |
                               ENABLE_WINDOW_INPUT);

        if (vt) {
            WriteVT(L"\x1b[?1049h");  // альтернативный экран (сохраняет консоль)
            WriteVT(L"\x1b[?25l");    // спрятать курсор
        } else {
            // Legacy: ремап палитры + буфер под окно.
            CONSOLE_SCREEN_BUFFER_INFOEX info = savedInfo;
            info.ColorTable[C_BG] = g_pal[C_BG];
            info.ColorTable[C_SURFACE] = g_pal[C_SURFACE];
            info.ColorTable[C_NEUTRAL] = g_pal[C_NEUTRAL];
            info.ColorTable[C_WARN] = g_pal[C_WARN];
            info.ColorTable[C_ACCENT] = g_pal[C_ACCENT];
            info.ColorTable[C_ACCENTHI] = g_pal[C_ACCENTHI];
            info.ColorTable[C_DIM] = g_pal[C_DIM];
            info.ColorTable[C_TEXT] = g_pal[C_TEXT];
            info.ColorTable[C_WHITE] = g_pal[C_WHITE];
            info.wAttributes = A_BG;
            info.dwSize.X = static_cast<SHORT>(W);
            info.dwSize.Y = static_cast<SHORT>(H);
            info.srWindow.Left = 0;
            info.srWindow.Top = 0;
            info.srWindow.Right = static_cast<SHORT>(W - 1);
            info.srWindow.Bottom = static_cast<SHORT>(H - 1);
            SetConsoleScreenBufferInfoEx(out, &info);
            CONSOLE_CURSOR_INFO cur = savedCursor;
            cur.bVisible = FALSE;
            SetConsoleCursorInfo(out, &cur);
        }
        ok = true;
    }

    void PresentVT(const Canvas& cv) {
        std::wstring o;
        o.reserve(W * H * 2);
        WORD cur = 0xFFFF;
        for (int y = 0; y < H; ++y) {
            wchar_t pos[16];
            swprintf(pos, 16, L"\x1b[%d;1H", y + 1);
            o += pos;
            bool inLink = false;
            int linkEnd = -1;
            for (int x = 0; x < W; ++x) {
                // Закрыть/открыть кликабельную ссылку (OSC 8).
                if (inLink && x == linkEnd) {
                    o += L"\x1b]8;;\x1b\\";
                    inLink = false;
                }
                if (!inLink) {
                    for (const Hyperlink& lk : cv.links) {
                        if (lk.y == y && lk.x == x) {
                            o += L"\x1b]8;;" + lk.url + L"\x1b\\";
                            inLink = true;
                            linkEnd = x + lk.len;
                            break;
                        }
                    }
                }
                const CHAR_INFO& ci = cv.cells[y * W + x];
                if (ci.Attributes != cur) {
                    cur = ci.Attributes;
                    COLORREF fg = g_pal[cur & 0x0F];
                    COLORREF bg = g_pal[(cur >> 4) & 0x0F];
                    wchar_t seq[48];
                    swprintf(seq, 48, L"\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dm",
                             Rd(fg), Gr(fg), Bl(fg), Rd(bg), Gr(bg), Bl(bg));
                    o += seq;
                }
                wchar_t ch = ci.Char.UnicodeChar;
                o += (ch ? ch : L' ');
            }
            if (inLink) o += L"\x1b]8;;\x1b\\";  // закрыть в конце строки
        }
        o += L"\x1b[0m";
        WriteVT(o);
    }

    void PresentLegacy(const Canvas& cv) {
        COORD size = {static_cast<SHORT>(W), static_cast<SHORT>(H)};
        COORD org = {0, 0};
        SMALL_RECT region = {0, 0, static_cast<SHORT>(W - 1),
                             static_cast<SHORT>(H - 1)};
        WriteConsoleOutputW(out, cv.cells.data(), size, org, &region);
    }

    void Present(const Canvas& cv) {
        if (vt) PresentVT(cv);
        else PresentLegacy(cv);
    }

    // Перечитать размер окна (после ресайза). Возвращает true, если изменился.
    bool Resize() {
        CONSOLE_SCREEN_BUFFER_INFO bi;
        if (!GetConsoleScreenBufferInfo(out, &bi)) return false;
        int cols = bi.srWindow.Right - bi.srWindow.Left + 1;
        int rows = bi.srWindow.Bottom - bi.srWindow.Top + 1;
        int nw = cols < 40 ? 40 : (cols > 200 ? 200 : cols);
        int nh = rows < 12 ? 12 : (rows > 60 ? 60 : rows);
        if (nw == W && nh == H) return false;
        W = nw;
        H = nh;
        return true;
    }

    void Restore() {
        if (!ok) return;
        if (vt) {
            WriteVT(L"\x1b[0m\x1b[?25h\x1b[?1049l");  // курсор, основной экран
            SetConsoleMode(out, savedOutMode);
        } else {
            SetConsoleScreenBufferInfoEx(out, &savedInfo);
            SetConsoleCursorInfo(out, &savedCursor);
        }
        SetConsoleMode(in, savedInMode);
    }
};

// Фоновый скан: инвентаризация выполняется в отдельном потоке, чтобы главный
// поток мог крутить индикатор "идёт работа". COM (rtComLite) инициализируется
// внутри ScanToken на том потоке, где вызван, - на рабочем потоке это штатно.
struct ScanJob {
    std::mutex mtx;
    std::vector<ContainerInfo> items;  // наполняется прогрессивно
};
DWORD WINAPI ScanThreadProc(LPVOID p) {
    ScanJob* j = static_cast<ScanJob*>(p);
    // Контейнеры добавляются по мере чтения - список наполняется на глазах.
    EnumerateContainersProgressive([j](const ContainerInfo& c) {
        std::lock_guard<std::mutex> lk(j->mtx);
        j->items.push_back(c);
    });
    // Уточнение типа носителя - после (нужен полный набор).
    std::lock_guard<std::mutex> lk(j->mtx);
    RefineMediumByScan(&j->items);
    return 0;
}

std::wstring NowHHMM() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[8];
    swprintf(buf, 8, L"%02u:%02u", st.wHour, st.wMinute);
    return buf;
}

// Выполнить копирование выбранного контейнера в выбранное назначение.
void DoCopy(State& s, bool overwrite) {
    const Tok& t = s.toks[s.selTok];
    const ContainerInfo& c = s.items[t.certIdx[s.certCursor]];
    const DestOpt& d = s.dests[s.destCursor];

    LogRow row;
    row.ts = NowHHMM();
    row.org = OrgName(c);
    row.inn = LegalInn(c);
    row.dest = d.label;

    if (d.kind == DEST_TODO) {
        s.resultKind = 2;
        s.resultMsg = L"Назначение «" + d.label + L"» ещё в разработке.";
        row.ok = false;
        row.status = L"в разработке";
    } else {
        // Снятие флага - только если чекбокс доступен (CSP 4.x) и отмечен.
        bool clr = s.flagClear && s.cspMajor > 0 && s.cspMajor <= 4;
        BackupResult br =
            d.kind == DEST_REGISTRY  ? BackupToRegistry(c, overwrite, clr)
            : d.kind == DEST_CPSTORE ? BackupToCryptoProStore(c, overwrite, clr)
                                     : BackupToFolder(c, d.path, overwrite, clr);
        s.resultKind = br.ok ? 0 : br.skipped ? 1 : 2;
        s.resultMsg = OrgName(c) + L" · ИНН " + LegalInn(c) + L"  —  " + br.message;
        row.ok = br.ok;
        row.status = br.ok ? L"Успешно" : br.skipped ? L"Пропущено" : L"Ошибка";
        if (br.ok && clr) s.resultMsg += L"  (признак снят)";
    }
    s.log.push_back(row);
    s.modal = Modal::Result;
}

// Проверить, не занята ли папка назначения; при занятости - спросить о
// перезаписи, иначе сразу копировать.
void RequestCopy(State& s) {
    const ContainerInfo& c = s.items[s.toks[s.selTok].certIdx[s.certCursor]];
    const DestOpt& d = s.dests[s.destCursor];
    bool exists = false;
    if (d.kind == DEST_FOLDER)
        exists = GetFileAttributesW(BackupTargetPath(c, d.path).c_str()) !=
                 INVALID_FILE_ATTRIBUTES;
    else if (d.kind == DEST_REGISTRY)
        exists = RegistryContainerExists(c);
    else if (d.kind == DEST_CPSTORE)
        exists = CryptoProStoreExists(c);
    if (exists) {
        s.overwriteCursor = 1;  // по умолчанию - отмена (безопаснее)
        s.modal = Modal::Overwrite;
        return;
    }
    DoCopy(s, false);
}

// Индекс строки списка по координате Y. Строки: baseY + i*stride, каждая
// занимает 2 текстовые линии.
int HitRow(int y, int baseY, int stride, int count) {
    for (int i = 0; i < count; ++i)
        if (y == baseY + i * stride || y == baseY + i * stride + 1) return i;
    return -1;
}

// Колесо мыши - навигация по текущему списку.
void HandleWheel(State& s, bool up) {
    if (s.modal == Modal::Dest) {
        int n = static_cast<int>(s.dests.size());
        s.destCursor = up ? (s.destCursor + n - 1) % n : (s.destCursor + 1) % n;
        return;
    }
    if (s.modal != Modal::None) return;
    if (s.screen == Screen::Tokens) {
        int n = static_cast<int>(s.toks.size());
        if (n) s.tokCursor = up ? (s.tokCursor + n - 1) % n : (s.tokCursor + 1) % n;
    } else {
        int n = static_cast<int>(s.toks[s.selTok].certIdx.size());
        if (n) s.certCursor = up ? (s.certCursor + n - 1) % n : (s.certCursor + 1) % n;
    }
}

// Левый клик (dbl - двойной). Действует как соответствующая клавиша.
void HandleClick(State& s, int mx, int my, bool dbl, bool& running) {
    // Простые модалки закрываются кликом.
    if (s.modal == Modal::Info || s.modal == Modal::Blocked) {
        s.modal = Modal::None;
        return;
    }
    if (s.modal == Modal::Result) {
        s.modal = Modal::None;
        s.screen = Screen::Certs;
        return;
    }
    if (s.modal == Modal::Exit) {
        int w = 46, h = 9, x = (W - w) / 2, y = (H - h) / 2;
        for (int i = 0; i < 2; ++i)
            if (my == y + 3 + i && mx >= x && mx < x + w) {
                if (i == 0) running = false;
                else s.modal = Modal::None;
                return;
            }
        return;
    }
    if (s.modal == Modal::Overwrite) {
        int w = 60, h = 9, x = (W - w) / 2, y = (H - h) / 2;
        for (int i = 0; i < 2; ++i)
            if (my == y + 4 + i && mx >= x && mx < x + w) {
                if (i == 0) DoCopy(s, true);
                else s.modal = Modal::Dest;
                return;
            }
        return;
    }
    if (s.modal == Modal::Dest) {
        const ContainerInfo& c = s.items[s.toks[s.selTok].certIdx[s.certCursor]];
        int w = W - 8 > 96 ? 96 : W - 8, h = 20, x = (W - w) / 2, y = (H - h) / 2;
        int nd = static_cast<int>(s.dests.size());
        for (int i = 0; i < nd; ++i)
            if ((my == y + 4 + 2 * i || my == y + 4 + 2 * i + 1) && mx >= x &&
                mx < x + w) {
                s.destCursor = i;   // клик по назначению сразу подтверждает
                RequestCopy(s);
                return;
            }
        if (c.exportable == Exportable::No && s.cspMajor > 0 &&
            s.cspMajor <= 4 && my == y + 13 && mx >= x && mx < x + w) {
            s.flagClear = !s.flagClear;
        }
        return;
    }

    // Основные экраны.
    if (s.screen == Screen::Tokens) {
        int i = HitRow(my, 2, 3, static_cast<int>(s.toks.size()));
        if (i >= 0) {
            s.tokCursor = i;
            s.selTok = i;
            s.certCursor = 0;
            s.screen = Screen::Certs;
            s.eatDbl = true;  // не дать двойному клику скопировать сразу
        }
        return;
    }
    const Tok& t = s.toks[s.selTok];
    int k = HitRow(my, 2, 3, static_cast<int>(t.certIdx.size()));
    if (k >= 0) {
        s.certCursor = k;
        if (dbl) {  // двойной клик по сертификату - копировать
            if (t.hardware) s.modal = Modal::Blocked;
            else { s.modal = Modal::Dest; s.destCursor = 2; s.flagClear = false; }
        }
    }
}

}  // namespace

int RunTui() {
    Console con;
    con.Init();
    if (!con.ok) return 1;

    Canvas cv;

    // Пока идёт долгий скан токенов - показываем окружение (ТЗ 3): что
    // установлено, а чего не хватает и где скачать. Проба окружения быстрая
    // (реестр/файлы), инвентаризация - медленная (rtComLite), поэтому сначала
    // рисуем окружение, потом сканируем.
    Environment env = ProbeEnvironment();

    // Если rtComLite нет - без него не читать/копировать Рутокен. Показываем
    // окружение и предлагаем скачать+установить (ТЗ 3).
    auto rtMissing = [&]() {
        for (const Capability& c : env.caps)
            if (c.name.find(L"rtComLite") != std::wstring::npos)
                return c.state == CapState::Missing;
        return false;
    };
    while (rtMissing()) {
        RenderEnvironment(cv, env,
                          L"rtComLite не установлен.  [D] скачать и установить "
                          L"·  [Enter] продолжить без него  ·  [F10] выход");
        con.Present(cv);
        INPUT_RECORD rec;
        DWORD rd = 0;
        if (!ReadConsoleInputW(con.in, &rec, 1, &rd) || rd == 0) continue;
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
        WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
        if (vk == VK_F10) { con.Restore(); return 0; }
        if (vk == VK_RETURN) break;
        if (vk == 'D') {
            std::wstring st;
            RenderEnvironment(cv, env, L"Скачиваю и запускаю установщик…");
            con.Present(cv);
            InstallRtComLite(&st);
            RenderEnvironment(cv, env,
                              st + L"   [Enter] продолжить · [F10] выход");
            con.Present(cv);
            // Ждём реакции; повторная проба окружения после установки.
            for (;;) {
                if (!ReadConsoleInputW(con.in, &rec, 1, &rd) || rd == 0) continue;
                if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown)
                    continue;
                WORD k = rec.Event.KeyEvent.wVirtualKeyCode;
                if (k == VK_F10) { con.Restore(); return 0; }
                if (k == VK_RETURN) break;
            }
            env = ProbeEnvironment();  // вдруг уже установили
        }
    }

    // Скан в фоне, индикатор с живым счётчиком найденного в главном потоке.
    ScanJob job;
    HANDLE th = CreateThread(nullptr, 0, ScanThreadProc, &job, 0, nullptr);
    if (th) {
        const wchar_t spin[] = L"|/-\\";
        int frame = 0;
        while (WaitForSingleObject(th, 0) == WAIT_TIMEOUT) {
            size_t n;
            {
                std::lock_guard<std::mutex> lk(job.mtx);
                n = job.items.size();
            }
            std::wstring status = std::wstring(1, spin[frame % 4]) +
                                  L" Чтение контейнеров — найдено: " +
                                  std::to_wstring(n) +
                                  std::wstring(frame % 4, L'.');
            RenderEnvironment(cv, env, status);
            con.Present(cv);
            Sleep(90);
            ++frame;
        }
        CloseHandle(th);
    } else {
        RenderEnvironment(cv, env, L"Опрос токенов и чтение контейнеров…");
        con.Present(cv);
        job.items = EnumerateContainers();
    }

    State s;
    {
        std::lock_guard<std::mutex> lk(job.mtx);
        s.items = std::move(job.items);
    }
    s.toks = BuildTokens(s.items);
    s.cspMajor = _wtoi(DetectCsp().version.c_str());  // "5.0" -> 5
    // Пометить контейнеры с GUID-именем (на носителях, где умеем переименовать).
    for (const ContainerInfo& it : s.items)
        s.guidName.push_back(RenameSupported(it) &&
                             NameLooksLikeGuid(ReadCurrentFriendlyName(it)));
    // Пометить копии с перепутанной раскладкой primary/masks (битые до 0.2.0).
    for (const ContainerInfo& it : s.items)
        s.copyLayout.push_back(static_cast<int>(DetectCopyLayout(it)));
    if (s.toks.empty()) {
        // Показать окружение и подсказку, дать прочитать, выйти по клавише.
        RenderEnvironment(cv, env,
                          L"Контейнеров не найдено. Проверьте носитель. "
                          L"Любая клавиша — выход.");
        con.Present(cv);
        INPUT_RECORD rec;
        DWORD rd = 0;
        while (ReadConsoleInputW(con.in, &rec, 1, &rd))
            if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) break;
        con.Restore();
        return 0;
    }

    bool running = true;
    DWORD prevBtns = 0;
    while (running) {
        Render(cv, s);
        con.Present(cv);

        INPUT_RECORD rec;
        DWORD read = 0;
        // Ошибка чтения (нет консоли) - выходим, а не крутим busy-loop.
        if (!ReadConsoleInputW(con.in, &rec, 1, &read)) break;
        if (read == 0) continue;
        // Ресайз окна: пересоздать холст под новый размер, иначе по краям
        // остаются артефакты от старого кадра.
        if (rec.EventType == WINDOW_BUFFER_SIZE_EVENT) {
            if (con.Resize()) cv = Canvas();
            continue;
        }
        if (rec.EventType == MOUSE_EVENT) {
            const MOUSE_EVENT_RECORD& m = rec.Event.MouseEvent;
            if (m.dwEventFlags & MOUSE_WHEELED) {
                HandleWheel(s, static_cast<short>(HIWORD(m.dwButtonState)) > 0);
                prevBtns = m.dwButtonState;
                continue;
            }
            bool leftNow = (m.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) != 0;
            bool leftEdge = leftNow && !(prevBtns & FROM_LEFT_1ST_BUTTON_PRESSED);
            bool dbl = (m.dwEventFlags & DOUBLE_CLICK) != 0;
            prevBtns = m.dwButtonState;
            if (dbl && s.eatDbl) { s.eatDbl = false; continue; }
            if (leftEdge) s.eatDbl = false;
            if (leftEdge || dbl)
                HandleClick(s, m.dwMousePosition.X, m.dwMousePosition.Y, dbl,
                            running);
            continue;
        }
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
        WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;

        // Модальные окна перехватывают ввод.
        if (s.modal == Modal::Blocked) {
            if (vk == VK_RETURN || vk == VK_ESCAPE) s.modal = Modal::None;
            continue;
        }
        if (s.modal == Modal::Info) {
            if (vk == VK_ESCAPE || vk == VK_RETURN) s.modal = Modal::None;
            continue;
        }
        if (s.modal == Modal::Exit) {
            if (vk == VK_UP || vk == VK_DOWN)
                s.exitCursor = 1 - s.exitCursor;
            else if (vk == VK_ESCAPE)
                s.modal = Modal::None;
            else if (vk == VK_RETURN)
                { if (s.exitCursor == 0) running = false; else s.modal = Modal::None; }
            continue;
        }
        if (s.modal == Modal::Result) {
            if (vk == VK_RETURN || vk == VK_ESCAPE) {
                s.modal = Modal::None;
                s.screen = Screen::Certs;
            } else if (vk == VK_F10) { s.modal = Modal::Exit; s.exitCursor = 0; }
            continue;
        }
        if (s.modal == Modal::Dest) {
            const ContainerInfo& c =
                s.items[s.toks[s.selTok].certIdx[s.certCursor]];
            int n = static_cast<int>(s.dests.size());
            if (vk == VK_UP) s.destCursor = (s.destCursor + n - 1) % n;
            else if (vk == VK_DOWN) s.destCursor = (s.destCursor + 1) % n;
            else if (vk == VK_SPACE && c.exportable == Exportable::No &&
                     s.cspMajor > 0 && s.cspMajor <= 4)
                s.flagClear = !s.flagClear;
            else if (vk == VK_ESCAPE) s.modal = Modal::None;
            else if (vk == VK_RETURN) RequestCopy(s);
            continue;
        }
        if (s.modal == Modal::Overwrite) {
            if (vk == VK_UP || vk == VK_DOWN)
                s.overwriteCursor = 1 - s.overwriteCursor;
            else if (vk == VK_ESCAPE)
                s.modal = Modal::Dest;
            else if (vk == VK_RETURN) {
                if (s.overwriteCursor == 0) DoCopy(s, true);
                else s.modal = Modal::Dest;
            }
            continue;
        }

        // F10 - выход из любого основного экрана.
        if (vk == VK_F10) { s.modal = Modal::Exit; s.exitCursor = 0; continue; }
        if (vk == VK_F3) { s.modal = Modal::Info; continue; }

        if (s.screen == Screen::Tokens) {
            int n = static_cast<int>(s.toks.size());
            if (vk == VK_UP) s.tokCursor = (s.tokCursor + n - 1) % n;
            else if (vk == VK_DOWN) s.tokCursor = (s.tokCursor + 1) % n;
            else if (vk == VK_RETURN) {
                s.selTok = s.tokCursor;
                s.certCursor = 0;
                s.screen = Screen::Certs;
            }
        } else {  // Certs
            const Tok& t = s.toks[s.selTok];
            int n = static_cast<int>(t.certIdx.size());
            if (vk == VK_ESCAPE || vk == VK_BACK) s.screen = Screen::Tokens;
            else if (n == 0) { /* нет сертификатов */ }
            else if (vk == VK_UP) s.certCursor = (s.certCursor + n - 1) % n;
            else if (vk == VK_DOWN) s.certCursor = (s.certCursor + 1) % n;
            else if (vk == VK_F5) {
                if (t.hardware) s.modal = Modal::Blocked;
                else { s.modal = Modal::Dest; s.destCursor = 2; s.flagClear = false; }
            }
            else if (vk == VK_F6 && n > 0) {
                // Переименовать контейнер на месте (реестр/папка КриптоПро).
                int gi = t.certIdx[s.certCursor];
                const ContainerInfo& cc = s.items[gi];
                LogRow row;
                row.ts = NowHHMM();
                row.org = OrgName(cc);
                row.inn = LegalInn(cc);
                row.dest = L"имя контейнера";
                if (!RenameSupported(cc)) {
                    s.resultKind = 2;
                    s.resultMsg = L"Переименование этого носителя пока не "
                                  L"поддерживается (реестр и папка КриптоПро — да).";
                    row.ok = false;
                    row.status = L"не поддерж.";
                } else {
                    RenameResult rr =
                        RenameContainerInPlace(cc, ReadableName(cc));
                    s.resultKind = rr.ok ? 0 : 2;
                    s.resultMsg = OrgName(cc) + L"  —  " + rr.message;
                    row.ok = rr.ok;
                    row.status = rr.ok ? L"Переименовано" : L"Ошибка";
                    if (rr.ok && gi < static_cast<int>(s.guidName.size()))
                        s.guidName[gi] = false;
                }
                s.log.push_back(row);
                s.modal = Modal::Result;
            }
            else if (vk == VK_F7 && n > 0) {
                // Починить битую копию: переставить primary/masks на месте.
                int gi = t.certIdx[s.certCursor];
                const ContainerInfo& cc = s.items[gi];
                LogRow row;
                row.ts = NowHHMM();
                row.org = OrgName(cc);
                row.inn = LegalInn(cc);
                row.dest = L"починка копии";
                bool broken = gi < static_cast<int>(s.copyLayout.size()) &&
                              s.copyLayout[gi] ==
                                  static_cast<int>(CopyLayout::Swapped);
                if (!broken) {
                    s.resultKind = 1;
                    s.resultMsg =
                        OrgName(cc) + L"  —  контейнер не помечен как битый.";
                    row.ok = false;
                    row.status = L"не требуется";
                } else {
                    RepairResult rr = RepairContainerLayout(cc);
                    s.resultKind = rr.ok ? 0 : 2;
                    s.resultMsg = OrgName(cc) + L"  —  " + rr.message;
                    row.ok = rr.ok;
                    row.status = rr.ok ? L"Починено" : L"Ошибка";
                    if (rr.ok)
                        s.copyLayout[gi] = static_cast<int>(CopyLayout::Ok);
                }
                s.log.push_back(row);
                s.modal = Modal::Result;
            }
        }
    }

    con.Restore();
    return 0;
}

// --- Дамп для проверки вёрстки ----------------------------------------------
namespace {
void DumpCanvas(const Canvas& cv) {
    for (int y = 0; y < H; ++y) {
        std::wstring line;
        for (int x = 0; x < W; ++x) line.push_back(cv.cells[y * W + x].Char.UnicodeChar);
        // trailing spaces trim
        while (!line.empty() && line.back() == L' ') line.pop_back();
        int need = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0,
                                       nullptr, nullptr);
        std::string u(need > 0 ? need - 1 : 0, '\0');
        if (need > 0)
            WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, &u[0], need,
                                nullptr, nullptr);
        fwrite(u.data(), 1, u.size(), stdout);
        fputc('\n', stdout);
    }
}
}  // namespace

int RunTuiDump() {
    State s;
    s.items = EnumerateContainers();
    s.toks = BuildTokens(s.items);
    for (const ContainerInfo& it : s.items)
        s.copyLayout.push_back(static_cast<int>(DetectCopyLayout(it)));
    Canvas cv;

    fputs("===== ЭКРАН: Токены =====\n", stdout);
    RenderTokens(cv, s);
    DumpCanvas(cv);

    if (!s.toks.empty()) {
        fputs("\n===== ЭКРАН: Сертификаты =====\n", stdout);
        // Показать носитель, где есть битая копия (для проверки бейджа), иначе 0.
        s.selTok = 0;
        for (int ti = 0; ti < static_cast<int>(s.toks.size()); ++ti)
            for (int gi : s.toks[ti].certIdx)
                if (gi < static_cast<int>(s.copyLayout.size()) &&
                    s.copyLayout[gi] == static_cast<int>(CopyLayout::Swapped)) {
                    s.selTok = ti;
                }
        RenderCerts(cv, s);
        DumpCanvas(cv);

        fputs("\n===== ДИАЛОГ: Куда скопировать =====\n", stdout);
        s.screen = Screen::Certs;
        RenderCerts(cv, s);
        RenderDest(cv, s);
        DumpCanvas(cv);
    }
    return 0;
}

}  // namespace certmig
