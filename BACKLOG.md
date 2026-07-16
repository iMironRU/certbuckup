# Дорожная карта

Активные задачи ведутся в **[Issues](https://github.com/iMironRU/certbuckup/issues)**:

- [#1 Запись на токен и копирование токен → токен](https://github.com/iMironRU/certbuckup/issues/1) — разбор в `docs/design/token-write.md`
- [#2 Снятие признака неэкспортируемости на CSP 5.x](https://github.com/iMironRU/certbuckup/issues/2)
- [#3 Перепривязка сертификата (ТЗ 2.4)](https://github.com/iMironRU/certbuckup/issues/3)
- [#4 Установщик (ТЗ 7.8)](https://github.com/iMironRU/certbuckup/issues/4)
- [#5 Экспорт инвентаризации в CSV](https://github.com/iMironRU/certbuckup/issues/5)
- [#6 TUI: частичный список во время загрузки + live-ресайз](https://github.com/iMironRU/certbuckup/issues/6)

## Сознательно не делаем

- **Массовые операции** (копировать пачкой) — опасно, риск оператора.
- **Переименование на токене** — не трогаем токен-носитель; переименование
  только для реестра и папки КриптоПро.
