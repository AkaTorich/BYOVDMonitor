# BYOVD Monitor Service (server edition)

Безынтерфейсная служба Windows, которая делает то же, что и GUI-версия
([BYOVDMonitor](../BYOVDMonitor/README.md)), но без окна, лампы и звука:
наблюдает за настроенными папками, сверяет SHA-256 файлов с локальной базой
loldrivers и (опционально) Team Cymru MHR, и отправляет оповещения в
**журнал событий Windows** и/или на **webhook** для SIEM.

Движок обнаружения переиспользуется один-в-один из GUI-проекта.

## Сборка

    dotnet build BYOVDMonitor.Service\Service.csproj -c Release

Готовый файл: `BYOVDMonitor.Service\bin\Release\net48\BYOVDMonitorService.exe`.

## Установка (на сервере, из админского терминала)

    BYOVDMonitorService.exe install

Что делает `install`:

- Создаёт `C:\ProgramData\BYOVDMonitor\` и **жёстко** ограничивает права
  доступа (только `SYSTEM` и `Administrators` — `icacls /inheritance:r /grant:r`).
  Это блокирует «отравление» локальной базы папок пользователем без прав.
- Регистрирует источник журнала событий `BYOVDMonitor` в `Application`.
- Записывает шаблон `config.json` (если ещё нет).
- Регистрирует службу `BYOVDMonitor` через `sc.exe`, тип запуска — `auto`,
  владелец — `LocalSystem`. Перезапуск при сбое: каждые 60 секунд.
- Стартует службу.

После установки отредактируй `C:\ProgramData\BYOVDMonitor\config.json`
(см. ниже) и перезапусти:

    BYOVDMonitorService.exe stop
    BYOVDMonitorService.exe start

## Управление

| Команда     | Действие                                            |
|-------------|-----------------------------------------------------|
| `install`   | Зарегистрировать и запустить службу (нужны права администратора) |
| `uninstall` | Остановить и удалить службу (нужны права администратора)         |
| `start`     | Запустить службу                                    |
| `stop`      | Остановить службу                                   |
| `status`    | Показать состояние (`sc query`)                     |
| `console`   | Запустить ядро службы в текущей консоли (отладка)   |
| `config`    | Показать путь к `config.json`                       |

## config.json

```json
{
  "Folders": [
    { "Path": "C:\\Windows\\System32\\drivers", "IncludeSubdirectories": false },
    { "Path": "C:\\inetpub",                    "IncludeSubdirectories": true  }
  ],
  "HashListUrl": "https://www.loldrivers.io/api/drivers.json",
  "MaxFileSizeMb": 64,
  "IncludeAllExtensions": true,
  "RescanIntervalMinutes": 15,
  "MhrEnabled": false,
  "WebhookUrl": "https://siem.example.com/byovd"
}
```

- `Folders` — список наблюдаемых папок. На сервере обычно `System32\drivers`
  и каталоги, где обычные программы могут что-то писать на диск.
- `MhrEnabled` — дополнительная проверка новых файлов в Team Cymru MHR
  (DNS, без ключа). Шлёт SHA-1 файла во внешний DNS. По умолчанию выключено.
- `WebhookUrl` — адрес для отправки оповещений (`HTTP POST application/json`).
  Пусто — webhook выключен. Формат:

```json
{
  "event": "byovd_detection",
  "time": "2026-06-21T12:37:05.9Z",
  "host": "WEBSRV01",
  "file": "C:\\inetpub\\evil.sys",
  "sha256": "77D89944...",
  "match": "Известное_имя.sys",
  "source": "loldrivers"
}
```

## Журнал событий Windows

Источник: `BYOVDMonitor`, журнал: `Application`.

| EventID | Что                                            |
|---------|------------------------------------------------|
| 1000    | Информация (старт/стоп/обновление базы)        |
| 2000    | **Тревога: обнаружен уязвимый драйвер**        |
| 3000    | Предупреждение (ошибка обхода, сбой обновления)|
| 4000    | Ошибка (сбой запуска)                          |

Просмотр последних тревог:

    Get-WinEvent -FilterHashtable @{ LogName="Application"; ProviderName="BYOVDMonitor"; Id=2000 } -MaxEvents 20

## Файлы данных

`C:\ProgramData\BYOVDMonitor\`:

- `config.json`     — настройки службы.
- `hashes.json`     — локальная база loldrivers (~2000 SHA-256). По сети
                      обновляется раз в час условным запросом по ETag.
- `baseline\*.json` — локальная база чистых файлов на каждую корневую папку
                      (хеши уже проверенных файлов, чтобы не перепроверять).

После `uninstall` каталог данных НЕ удаляется — на случай ремонтной
переустановки. Чтобы удалить полностью: `Remove-Item -Recurse -Force
"C:\ProgramData\BYOVDMonitor"`.

## Отладка

Если служба не стартует, удобнее всего запустить ядро в консоли с теми
же шагами и увидеть исключение сразу:

    BYOVDMonitorService.exe console

(не требует прав администратора, если каталог данных уже создан и
доступен на запись).
