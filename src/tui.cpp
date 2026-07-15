#include "tui.h"

#include <windows.h>

#include <string>
#include <vector>

#include "backup.h"
#include "resolver.h"

namespace certmig {

namespace {

// --- Палитра Nocturne: ремап 16-цветной таблицы консоли ---------------------
// Индексы, которыми пользуемся (остальные не трогаем).
enum {
    C_BG = 0,       // фон #161826
    C_SURFACE = 1,  // поверхность окна/диалога #232532
    C_NEUTRAL = 2,  // нейтраль-900 #292b31
    C_ACCENT = 5,   // акцент #9184d9
    C_DIM = 8,      // приглушённый текст
    C_TEXT = 7,     // основной текст #e9e9ed
    C_ACCENTHI = 13,// светлый акцент #d2cefd
    C_WHITE = 15,
};

COLORREF Rgb(int r, int g, int b) {
    return static_cast<COLORREF>((b << 16) | (g << 8) | r);
}

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

// Размер холста. Не константы: подстраиваются под фактическое окно консоли
// в Console::Init. По умолчанию - на случай дампа без консоли.
int W = 104, H = 32;

// --- Холст ------------------------------------------------------------------
struct Canvas {
    std::vector<CHAR_INFO> cells;
    Canvas() : cells(W * H) { Clear(A_BG); }

    void Clear(WORD attr) {
        for (CHAR_INFO& ci : cells) {
            ci.Char.UnicodeChar = L' ';
            ci.Attributes = attr;
        }
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

// --- Состояние --------------------------------------------------------------
enum class Screen { Tokens, Certs };
enum class Modal { None, Dest, Blocked, Info, Exit, Result };

struct DestOpt {
    std::wstring label;
    std::wstring path;      // куда (для реализованных)
    bool implemented;
};

struct LogRow {
    std::wstring ts, token, owner, dest, status;
    bool ok;
};

struct State {
    std::vector<ContainerInfo> items;
    std::vector<Tok> toks;

    Screen screen = Screen::Tokens;
    Modal modal = Modal::None;

    int tokCursor = 0, certCursor = 0, destCursor = 0, exitCursor = 0;
    int selTok = 0;
    bool flagClear = false;   // чекбокс "снять признак неэкспортируемости"
    std::wstring resultMsg;
    bool resultOk = false;
    std::vector<LogRow> log;

    std::vector<DestOpt> dests = {
        {L"Диск D:\\", L"D:\\Сертификаты", true},
        {L"Реестр Windows", L"", false},
        {L"Папка рядом с приложением", DefaultBackupDir(), true},
        {L"Папка КриптоПро", L"", false},
    };
};

// --- Отрисовка экранов ------------------------------------------------------
void DrawFooter(Canvas& cv, const std::wstring& keys) {
    cv.Fill(0, H - 1, W, 1, A_DIM);
    cv.Text(2, H - 1, keys, A_DIM);
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
    DrawFooter(cv, L"↑↓ выбор   Enter открыть   F3 инфо   F10 выход");
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
        cv.Text(4, y, icon + OwnerOf(c), sel ? A_SEL : A_ACC, W - 30);
        std::wstring meta = c.subjectO + L" · до " + FormatDate(c.notAfter) +
                            L" · " + (c.thumbprint.size() >= 8
                                          ? c.thumbprint.substr(0, 8)
                                          : c.thumbprint);
        cv.Text(4, y + 1, L"  " + meta, sel ? A_SEL : A_DIM, W - 30);
        std::wstring tag;
        if (c.medium == KeyMedium::HardWare) tag = L" устройство: только чтение ";
        else if (c.exportable == Exportable::No) tag = L" ключ неэкспортируемый ";
        if (!tag.empty())
            cv.Text(W - static_cast<int>(tag.size()) - 4, y, tag, A_TAG);
        y += 3;
    }
    DrawFooter(cv,
               L"↑↓ выбор   F5 копировать   F3 инфо   Esc назад   F10 выход");
}

void DrawDialog(Canvas& cv, int x, int y, int w, int h,
                const std::wstring& title) {
    cv.Fill(x, y, w, h, A_SURF);
    cv.Box(x, y, w, h, A_SURFACC);
    cv.Text(x + 3, y, L" " + title + L" ", A_SURFACC);
}

void RenderDest(Canvas& cv, const State& s) {
    const ContainerInfo& c = s.items[s.toks[s.selTok].certIdx[s.certCursor]];
    int w = 66, h = 16, x = (W - w) / 2, y = (H - h) / 2;
    DrawDialog(cv, x, y, w, h, L"Куда скопировать контейнер");
    cv.Text(x + 3, y + 2, OwnerOf(c), A_SURFACC, w - 6);
    int ry = y + 4;
    for (int i = 0; i < static_cast<int>(s.dests.size()); ++i) {
        const DestOpt& d = s.dests[i];
        bool sel = (i == s.destCursor);
        WORD a = sel ? A_SEL : A_SURF;
        cv.Fill(x + 2, ry, w - 4, 1, a);
        std::wstring radio = sel ? L"(●) " : L"( ) ";
        std::wstring line = radio + d.label;
        if (!d.implemented) line += L"  (в разработке)";
        cv.Text(x + 4, ry, line, a, w - 8);
        if (!d.path.empty())
            cv.Text(x + 4, ry, radio + Pad(d.label, 34) + d.path,
                    sel ? A_SEL : A_SURFDIM, w - 8);
        ry += 1;
    }
    // Чекбокс снятия признака (показываем, если ключ неэкспортируемый).
    ry += 1;
    if (c.exportable == Exportable::No) {
        std::wstring cb = s.flagClear ? L"[✓] " : L"[ ] ";
        cv.Text(x + 4, ry, cb + L"Снять признак неэкспортируемости (пробел)",
                A_SURF, w - 8);
    }
    cv.Text(x + 3, y + h - 2, L"↑↓ выбор · Enter копировать · Esc отмена",
            A_SURFDIM, w - 6);
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
        title = OwnerOf(c);
        rows = {{L"Организация", c.subjectO},
                {L"ИНН", c.Inn()},
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
    std::wstring mark = s.resultOk ? L"✓ " : L"✗ ";
    cv.Fill(2, 2, W - 4, 2, Attr(C_TEXT, C_NEUTRAL));
    cv.Text(4, 2, mark + s.resultMsg, s.resultOk ? A_ACC : A_DIM, W - 8);

    cv.Text(4, 5, L"Журнал операций за сеанс:", A_DIM);
    cv.Text(4, 6, Pad(L"Время", 10) + Pad(L"Токен", 20) + Pad(L"Владелец", 30) +
                      Pad(L"Статус", 12), A_DIM);
    int y = 7;
    for (int i = static_cast<int>(s.log.size()) - 1; i >= 0 && y < H - 3; --i) {
        const LogRow& r = s.log[i];
        cv.Text(4, y,
                Pad(r.ts, 10) + Pad(r.token, 20) + Pad(r.owner, 30) +
                    Pad(r.status, 12),
                r.ok ? A_BG : A_DIM);
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

void Render(Canvas& cv, const State& s) {
    if (s.modal == Modal::Result) { RenderResult(cv, s); return; }
    if (s.screen == Screen::Tokens) RenderTokens(cv, s);
    else RenderCerts(cv, s);
    switch (s.modal) {
        case Modal::Dest: RenderDest(cv, s); break;
        case Modal::Blocked: RenderBlocked(cv, s); break;
        case Modal::Info: RenderInfo(cv, s); break;
        case Modal::Exit: RenderExit(cv, s); break;
        default: break;
    }
}

// --- Консоль ----------------------------------------------------------------
struct Console {
    HANDLE out, in;
    CONSOLE_SCREEN_BUFFER_INFOEX savedInfo{};
    DWORD savedInMode = 0;
    CONSOLE_CURSOR_INFO savedCursor{};
    bool ok = false;

    void Init() {
        out = GetStdHandle(STD_OUTPUT_HANDLE);
        in = GetStdHandle(STD_INPUT_HANDLE);
        if (out == INVALID_HANDLE_VALUE || in == INVALID_HANDLE_VALUE) return;

        savedInfo.cbSize = sizeof(savedInfo);
        // Нет настоящей консоли (перенаправление) - в TUI идти нельзя.
        if (!GetConsoleScreenBufferInfoEx(out, &savedInfo)) return;
        GetConsoleMode(in, &savedInMode);
        GetConsoleCursorInfo(out, &savedCursor);

        // Подстраиваемся под фактическое окно, а не навязываем свой размер.
        // Так работает и в классическом conhost, и в Windows Terminal, где
        // приложение окно не ресайзит.
        int cols = savedInfo.srWindow.Right - savedInfo.srWindow.Left + 1;
        int rows = savedInfo.srWindow.Bottom - savedInfo.srWindow.Top + 1;
        W = cols < 40 ? 40 : (cols > 200 ? 200 : cols);
        H = rows < 12 ? 12 : (rows > 60 ? 60 : rows);

        // Палитра Nocturne + буфер под размер окна (без прокрутки).
        CONSOLE_SCREEN_BUFFER_INFOEX info = savedInfo;
        info.ColorTable[C_BG] = Rgb(0x16, 0x18, 0x26);
        info.ColorTable[C_SURFACE] = Rgb(0x23, 0x25, 0x32);
        info.ColorTable[C_NEUTRAL] = Rgb(0x29, 0x2b, 0x31);
        info.ColorTable[C_ACCENT] = Rgb(0x91, 0x84, 0xd9);
        info.ColorTable[C_ACCENTHI] = Rgb(0xd2, 0xce, 0xfd);
        info.ColorTable[C_DIM] = Rgb(0x8a, 0x87, 0x94);
        info.ColorTable[C_TEXT] = Rgb(0xe9, 0xe9, 0xed);
        info.ColorTable[C_WHITE] = Rgb(0xff, 0xff, 0xff);
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
        SetConsoleMode(in, ENABLE_EXTENDED_FLAGS);  // без quick-edit/эха
        ok = true;
    }

    void Present(const Canvas& cv) {
        COORD size = {static_cast<SHORT>(W), static_cast<SHORT>(H)};
        COORD org = {0, 0};
        SMALL_RECT region = {0, 0, static_cast<SHORT>(W - 1),
                             static_cast<SHORT>(H - 1)};
        WriteConsoleOutputW(out, cv.cells.data(), size, org, &region);
    }

    void Restore() {
        if (!ok) return;
        SetConsoleScreenBufferInfoEx(out, &savedInfo);
        SetConsoleMode(in, savedInMode);
        SetConsoleCursorInfo(out, &savedCursor);
    }
};

std::wstring NowHHMM() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[8];
    swprintf(buf, 8, L"%02u:%02u", st.wHour, st.wMinute);
    return buf;
}

// Выполнить копирование выбранного контейнера в выбранное назначение.
void DoCopy(State& s) {
    const Tok& t = s.toks[s.selTok];
    const ContainerInfo& c = s.items[t.certIdx[s.certCursor]];
    const DestOpt& d = s.dests[s.destCursor];

    LogRow row;
    row.ts = NowHHMM();
    row.token = t.title;
    row.owner = OwnerOf(c);
    row.dest = d.label;

    if (!d.implemented) {
        s.resultOk = false;
        s.resultMsg = L"Назначение «" + d.label + L"» ещё в разработке.";
        row.ok = false;
        row.status = L"в разработке";
    } else {
        BackupResult br = BackupToFolder(c, d.path);
        s.resultOk = br.ok;
        s.resultMsg = br.message;
        row.ok = br.ok;
        row.status = br.ok ? L"Успешно" : L"Ошибка";
        if (br.ok && s.flagClear)
            s.resultMsg += L"  (снятие признака — следующий этап)";
    }
    s.log.push_back(row);
    s.modal = Modal::Result;
}

}  // namespace

int RunTui() {
    Console con;
    con.Init();
    if (!con.ok) return 1;

    Canvas cv;

    // Экран загрузки: инвентаризация сканирует токены через rtComLite и может
    // занять несколько секунд. Показываем сообщение сразу, чтобы не выглядело
    // зависшим.
    cv.Clear(A_BG);
    cv.Box(0, 0, W, H, A_BORDER);
    cv.Text(W / 2 - 20, H / 2 - 1, L"Чтение контейнеров и опрос токенов…", A_ACC);
    cv.Text(W / 2 - 20, H / 2 + 1, L"Это может занять несколько секунд.", A_DIM);
    con.Present(cv);

    State s;
    s.items = EnumerateContainers();
    s.toks = BuildTokens(s.items);
    if (s.toks.empty()) {
        con.Restore();
        return 0;
    }

    bool running = true;
    while (running) {
        Render(cv, s);
        con.Present(cv);

        INPUT_RECORD rec;
        DWORD read = 0;
        // Ошибка чтения (нет консоли) - выходим, а не крутим busy-loop.
        if (!ReadConsoleInputW(con.in, &rec, 1, &read)) break;
        if (read == 0) continue;
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
            else if (vk == VK_SPACE && c.exportable == Exportable::No)
                s.flagClear = !s.flagClear;
            else if (vk == VK_ESCAPE) s.modal = Modal::None;
            else if (vk == VK_RETURN) DoCopy(s);
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
                else { s.modal = Modal::Dest; s.destCursor = 0; s.flagClear = false; }
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
    Canvas cv;

    fputs("===== ЭКРАН: Токены =====\n", stdout);
    RenderTokens(cv, s);
    DumpCanvas(cv);

    if (!s.toks.empty()) {
        fputs("\n===== ЭКРАН: Сертификаты =====\n", stdout);
        s.selTok = 0;
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
