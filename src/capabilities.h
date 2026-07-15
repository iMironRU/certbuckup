// Проба окружения (ТЗ 3, расширенная).
//
// Идея: инструмент не привязан к одному способу копирования. Он смотрит, что
// установлено на машине, выводит из этого доступные бэкенды, а для
// недостающего показывает, где взять. Один бинарь подстраивается и под
// машину с КриптоПро, и под машину с одним rtComLite, и под голую.
//
// Разбор утилиты Контура (Tokens.exe -> tokens.hta) показал, что копировать
// контейнер можно двумя независимыми путями: штатным keycopy КриптоПро и
// сырым чтением файлов контейнера через COM-компонент Рутокена rtComLite.
// Модуль определяет, какой из них доступен здесь и сейчас.
#pragma once

#include <string>
#include <vector>

namespace certmig {

enum class CapState {
    Present,  // есть и готово к использованию
    Missing,  // нет
    Partial,  // есть, но с оговоркой (напр. компонент не той разрядности)
};

// Одна проверяемая возможность окружения.
struct Capability {
    std::wstring name;     // "КриптоПро CSP"
    CapState state = CapState::Missing;
    std::wstring detail;   // версия / путь / CLSID
    std::wstring enables;  // что даёт
    std::wstring hint;     // где скачать, если нет
};

// Способ копирования контейнера, выведенный из набора возможностей.
struct CopyBackend {
    std::wstring name;      // "КриптоПро keycopy"
    bool available = false;
    std::wstring scope;     // какие носители покрывает
    std::wstring reason;    // почему недоступен, если available == false
};

struct Environment {
    std::vector<Capability> caps;
    std::vector<CopyBackend> backends;
    // Путь к найденному csptest.exe, пусто если не найден.
    std::wstring csptestPath;
};

Environment ProbeEnvironment();

}  // namespace certmig
