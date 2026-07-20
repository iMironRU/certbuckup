// Доступ к Рутокену через COM-компонент rtComLite (rtCOMLite.rtContext).
//
// Тот же путь, что у разобранной утилиты Контура (docs/kontur-tokens-3.4.2.hta):
// чтение файловой системы токена напрямую, без КриптоПро. Приватный ключ не
// расшифровывается - копируются зашифрованные файлы контейнера как есть,
// поэтому неэкспортируемость не мешает.
//
// Компонент 32-битный, поэтому и наш бинарь 32-битный (иначе in-proc COM не
// загрузится - см. capabilities).
//
// Даёт две вещи:
//   1. Определение аппаратный/файловый контейнер (ТЗ 7.2, 1): файловый
//      контейнер виден как папка на токене с шестью файлами base+1..base+6.
//      Нет такой папки - ключ внутри чипа, копировать нечего.
//   2. Резервное копирование: чтение этих шести файлов для записи в папку
//      (ТЗ 2.2). Реализуется поверх того же обхода.
#pragma once

#include <windows.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace certmig {

// Смещение файла внутри папки-контейнера задаёт его тип. Проверено на живых
// Rutoken Lite: база 0x0A00/0x0B00/0x0C00, файлы база+1..база+6.
//   +1 masks.key (60)     +2 primary.key (70)  +3 header.key (с сертификатом)
//   +4 masks2.key (60)    +5 primary2.key (70) +6 name.key (имя контейнера)
// (раскладку primary/masks выверяли побайтово против рабочей копии Контура —
//  см. комментарий в ContainerFileName в rutoken.cpp)
const wchar_t* ContainerFileName(int offset);  // 1..6 -> "primary.key" и т.д.

// Один файл контейнера, прочитанный с токена.
struct ContainerFile {
    std::wstring name;         // канонический: header.key, primary.key, ...
    std::vector<BYTE> data;
};

// Результат обхода токена: какие ID папок оказались файловыми контейнерами.
// Ключ set - ID папки (он же "база"), совпадает с 3-м сегментом FQCN в hex.
struct TokenScan {
    bool ok = false;
    std::wstring error;
    std::set<int> containerFolders;  // папки с валидной 6-файловой структурой
};

// Список ридеров, которые видит rtComLite. Пусто, если компонент недоступен.
std::vector<std::wstring> EnumReaders();

// Обходит файловую систему токена и находит папки-контейнеры. Ничего не
// пишет. Авторизация: если PIN дефолтный (12345678) - входит сам, как
// утилита Контура; иначе помечает ошибкой (запрос PIN у оператора - отдельный
// шаг, здесь его нет).
TokenScan ScanToken(const std::wstring& readerName);

// Читает шесть файлов контейнера из папки folderId. Для резервного
// копирования (ТЗ 2.2). Пишет только в out; на диск ничего не выводит.
bool ReadContainer(const std::wstring& readerName, int folderId,
                   std::vector<ContainerFile>* out, std::wstring* error);

}  // namespace certmig
