// Журнал операций (ТЗ 6).
//
// Инструмент снятия неэкспортируемости и копирования в чужих руках - механизм
// кражи подписи. Поэтому журнал встроен в ядро: любое копирование/пересборка
// пишется строкой с меткой времени, откуда, куда и Thumbprint. Файл только
// дополняется (append-only), лежит рядом с exe.
#pragma once

#include <string>

namespace certmig {

// Дописывает одну запись об операции. Поля не должны содержать переводов
// строк - запись однострочная, чтобы журнал оставался разборчивым.
//   op      - что сделано (напр. "backup", "keycopy", "unexport")
//   subject - владелец/ИНН для человекочитаемости
//   thumb   - SHA1 сертификата
//   from    - источник (контейнер/носитель)
//   to      - назначение (путь/носитель)
//   result  - "OK" или текст ошибки
void JournalOp(const std::wstring& op, const std::wstring& subject,
               const std::wstring& thumb, const std::wstring& from,
               const std::wstring& to, const std::wstring& result);

// Путь к файлу журнала (рядом с exe). Для показа оператору.
std::wstring JournalPath();

}  // namespace certmig
