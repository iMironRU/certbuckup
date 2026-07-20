<div align="center">

<img src="assets/icon-256.png" width="128" alt="CertBuckUp"/>

# CertBuckUp

**Резервное копирование ключевых контейнеров КриптоПро —
с человекочитаемым выбором контейнера.**

[![build](https://github.com/iMironRU/certbuckup/actions/workflows/build.yml/badge.svg)](https://github.com/iMironRU/certbuckup/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/iMironRU/certbuckup?include_prereleases)](https://github.com/iMironRU/certbuckup/releases)
[![license: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
![platform](https://img.shields.io/badge/Windows-7%2B-0078D6)

</div>

---

## Зачем

Штатные инструменты показывают контейнеры обезличенным GUID
(`he-8f3a1c2d.000`) — по нему не понять, чей это ключ. **CertBuckUp показывает
владельца, ИНН и срок действия**, чтобы при резервировании десятков КЭП было
видно, что́ копируешь.

Главная задача — **резервное копирование** контейнеров: снять копию до
переустановки системы, замены токена или истечения срока; собрать архив парка
КЭП. Один `.exe`, ничего ставить не нужно (Windows 7+).

```text
╔═ Токены › Rutoken Lite ══════════════════════════════════════════════╗
║   ▤ ООО «Ромашка»                              ключ неэкспортируемый ║
║     ИНН 7701234567 · до 2027-07-15 · A1B2C3D4                        ║
║   ▤ ИП Иванов И.И.                             ключ неэкспортируемый ║
║     ИНН 7701987654 · до 2027-01-24 · C9D0E1F2                        ║
╚══════════════════════════════════════════════════════════════════════╝
  ↑↓  F5/2×клик копировать  F6 переименовать  F3 инфо  F10 выход
```

## Как пользоваться

1. Скачать `CertBuckUp.exe` со страницы [Releases](https://github.com/iMironRU/certbuckup/releases).
2. Запустить без параметров:
   ```
   CertBuckUp.exe
   ```
3. Выбрать токен → сертификат → **`F5`** → выбрать, куда скопировать
   (папка рядом · диск `D:` · реестр · папка КриптоПро).

| Клавиша / мышь | Действие |
|---|---|
| `↑↓` / колесо | навигация |
| `Enter` / клик | открыть токен |
| `F5` / двойной клик | копировать сертификат |
| `F6` | переименовать контейнер (убрать GUID) |
| `F7` | починить битую копию (перепутанные primary/masks) |
| `F3` | информация |
| `F2` | высококонтрастные цвета (если тема нечитаема, напр. по RDP) |
| `F10` | выход |

## Ссылки

- 📦 **Скачать:** [Releases](https://github.com/iMironRU/certbuckup/releases)
- 📖 **Подробное руководство:** [docs/GUIDE.md](docs/GUIDE.md) —
  возможности, границы, архитектура, сборка, безопасность
- 🌐 **Сайт:** [imiron.ru/certbuckup](https://imiron.ru/certbuckup/)
- 🗺️ **Планы и задачи:** [Issues](https://github.com/iMironRU/certbuckup/issues)

## Лицензия

[GNU GPL v3](LICENSE).
