<p align="center">
  <img src="Assets/AppIcon.png" width="160" alt="LANA Scanner">
</p>

<h1 align="center">LANA Scanner</h1>
<p align="center"><b>LAN Advanced Scanner для macOS</b></p>
<p align="center"><a href="README.md">English version</a></p>

---

Нативный (SwiftUI) сканер локальной сети в стиле **Advanced IP Scanner** с функциями из **nmap**:
обнаружение устройств, MAC и производитель, имена хостов, TCP-сканирование портов,
определение сервисов по баннерам и быстрые действия с хостом. Root не нужен, внешних зависимостей нет.

## Возможности

| Функция | Как сделано | Аналог в nmap |
|---|---|---|
| Обнаружение хостов | ARP-кэш + ICMP echo + TCP-ping на 9 портов (ответ RST тоже считается «жив») | `-sn -PE -PS22,80,…` |
| MAC и производитель | `arp -an` + база IEEE OUI (скачивается при первом запуске) | — |
| Имена | обратный DNS, mDNS (unicast к :5353), NetBIOS NBSTAT (:137) | `-R`, `nbstat.nse` |
| Порты | неблокирующий `connect()` + `poll()`, до 4096 соединений одновременно | `-sT --top-ports N` |
| Сервисы | баннеры (SSH/FTP/SMTP/POP3/IMAP/VNC/MySQL) + HTTP `HEAD` → заголовок `Server` | `-sV` (упрощённо) |
| Действия | HTTP/HTTPS, SSH, SMB (Finder), RDP, VNC, FTP, Ping, Traceroute, Wake-on-LAN, копирование | — |

Наборы портов: **Top 100 / Top 1000** (те же порты, что у `nmap --top-ports`, взяты из `nmap-services`), 1–1024, все 65535, свой список (`22,80,443,8000-8100`).
Форматы целей: `192.168.1.0/24`, `10.0.0.1-10.0.0.50`, `10.0.0.1-50`, одиночные IP; через запятую.

## Архитектура

```
┌───────────── SwiftUI (MainActor) ─────────────┐
│ ContentView ─ Table ─ HostDetailView ─ Settings│
│        ▲  опрос snapshot() каждые 300 мс       │
└────────┼───────────────────────────────────────┘
         │ ResultStore (NSLock, versioned)
┌────────┴──────────── ScanJob (GCD) ────────────┐
│ 1. Discovery:  ARP poke ║ ICMP sweep ║ TCP ping│──► arp -an → MAC
│ 2. Enrichment: OUI · DNS · mDNS · NetBIOS      │   (параллельно с п.3)
│ 3. Ports:      ConnectScanner (1 поток, poll)  │──► ServiceProbe (баннеры)
└────────────────────────────────────────────────┘
```

Ключевые решения:
- **Без root.** ICMP идёт через `SOCK_DGRAM/IPPROTO_ICMP` (разрешено macOS непривилегированным процессам), порты — через `connect()`. Поэтому SYN-scan, UDP-сканирование и OS-fingerprinting сознательно не реализованы.
- **Один поток на тысячи сокетов.** `ConnectScanner` держит окно неблокирующих сокетов и мультиплексирует их через `poll()`, вместо «поток на соединение». Сокеты закрываются с `SO_LINGER=0` (RST), чтобы не копить `TIME_WAIT`.
- **Лимит дескрипторов.** По умолчанию soft-лимит у macOS — 256 fd; при старте поднимается до 10240 (`setrlimit`), а параллельность ограничивается значением `лимит − 128`.
- **UI не захлёбывается.** Воркеры пишут в `ResultStore` под замком, UI забирает снимок только при изменении версии.

## Установка готовой версии

1. Скачайте `LANA-Scanner-<версия>-macOS.zip` со страницы [Releases](../../releases) и распакуйте.
2. Перенесите **LANA Scanner.app** в «Программы».
3. Приложение подписано ad-hoc и не нотаризовано, поэтому при первом запуске Gatekeeper его заблокирует. Откройте через ПКМ → «Открыть», или через *Системные настройки → Конфиденциальность и безопасность → «Всё равно открыть»*, или командой:
   ```bash
   xattr -dr com.apple.quarantine "/Applications/LANA Scanner.app"
   ```
4. Разрешите доступ к локальной сети, когда macOS спросит.

## Сборка из исходников

Нужны macOS 13+ и Xcode Command Line Tools (`xcode-select --install`) — Swift 5.9 или новее.

```bash
git clone <url-репозитория> LANA-scanner && cd LANA-scanner
./scripts/build-app.sh            # → "build/LANA Scanner.app" (ad-hoc подпись)
./scripts/build-app.sh --install  # + установка в /Applications (INSTALL_DIR=~/Applications — только для себя)
open "build/LANA Scanner.app"
```

Для разработки: `swift run` (запустится без .app-бандла, права на локальную сеть возьмёт у Терминала).
Universal-бинарь (`--universal`) собирается только с полным Xcode.

## Важно знать (ограничения и подводные камни)

1. **Local Network Privacy (macOS 15 Sequoia+).** При первом сканировании macOS спросит разрешение на доступ к локальной сети — согласитесь. Если ответили «Не разрешать» или устройств не находится вовсе: *Системные настройки → Конфиденциальность и безопасность → Локальная сеть → LANA Scanner*. После пересборки с другой подписью разрешение может слететь — переключите его заново.
2. **Gatekeeper.** Подпись ad-hoc: собранное у себя приложение запускается без проблем. Если переносите `.app` на другой Mac, снимите карантин: `xattr -dr com.apple.quarantine "LANA Scanner.app"`.
3. **Статус «Только ARP» (жёлтая точка)** значит, что устройство не ответило ни на ICMP, ни на TCP, но есть в ARP-кэше. Это либо хост с файрволом (типично для Windows), либо **устаревшая запись** — macOS хранит ARP-записи около 20 минут (`net.link.ether.inet.max_age`). Очистить кэш: `sudo arp -a -d`.
4. **MAC-адрес** виден только для хостов в одном L2-сегменте с вашим Mac. За маршрутизатором/VPN показываются только IP, имена и порты (иногда MAC через NetBIOS).
5. **«Случайный MAC»** — iPhone, Android и macOS используют приватные Wi-Fi-адреса; у таких производитель не определяется в принципе.
6. **Нагрузка на сеть.** `Все 1–65535` × /24 — это миллионы соединений: IDS/IPS могут поднять тревогу, домашние роутеры — подвиснуть (переполнение таблицы conntrack/NAT). Для широких диапазонов используйте Top 100/1000, а параллельность на Wi-Fi держите в районе 256–512.
7. **Таймаут.** По умолчанию 800 мс — хорошо для проводной LAN. На Wi-Fi со спящими устройствами (телефоны, IoT) ставьте 1500–2000 мс, иначе часть хостов будет пропущена.
8. **Юридически:** сканируйте только сети, на которые у вас есть права.

## Проверка

```bash
swift test                         # парсеры: CIDR/диапазоны, порты, ARP, DNS PTR, NetBIOS, баннеры, OUI
                                   # (XCTest есть в полном Xcode; с одними CLT может не запуститься)

# Сравнение с nmap на той же сети (brew install nmap):
nmap -sn 192.168.1.0/24 | grep -c "Host is up"     # число хостов ≈ «Устройств» в статус-баре
nmap -sT --top-ports 100 192.168.1.1               # открытые порты шлюза = панель деталей в LANA Scanner

# Проверка лимита дескрипторов работающего процесса:
lsof -p "$(pgrep -x NetScanner)" | wc -l   # процесс называется по бинарю внутри бандла; во время скана ≈ параллельность
```

Ручной сценарий: «Сканировать» → в списке есть строка «Этот Mac» (синяя) и шлюз (оранжевый) →
двойной клик по роутеру открывает его веб-интерфейс → ПКМ → Ping показывает живой вывод → «Стоп» печатает статистику.

## Эксплуатация

- **Откат:** приложение не хранит ничего критичного. Удалить: `/Applications/LANA Scanner.app`, `~/Library/Application Support/NetScanner/` (база OUI), настройки — `defaults delete com.github.lanascanner`.
- **База производителей** обновляется из меню «Сканирование → Обновить базу производителей» (источник — IEEE, запасной — `nmap-mac-prefixes`). Если при сборке база уже скачана, `build-app.sh` вложит её в бандл, и приложение будет работать офлайн с первого запуска.
- **Обновление Top-портов** из свежего nmap:
  ```bash
  curl -fsSLo /tmp/nmap-services https://raw.githubusercontent.com/nmap/nmap/master/nmap-services
  python3 scripts/gen-portdata.py /tmp/nmap-services
  ```

## Структура

```
Sources/NetScanner/
  App/     NetScannerApp.swift        — @main, меню, AppDelegate (rlimit, SIGPIPE)
  Model/   IPv4, TargetParser (цели/порты/сервисы), Models, ScanSettings, PortData (генерируется)
  Net/     Sockets, Interfaces, ConnectScanner, ICMPPinger (+ARP), NameResolver (DNS/mDNS/NetBIOS),
           ServiceProbe (+Wake-on-LAN), OUIDatabase
  Engine/  ScanJob (пайплайн), ResultStore, ScanViewModel, ToolRunner (ping/traceroute)
  UI/      ContentView, HostTableView, HostDetailView, HostActions, SettingsView
Tests/NetScannerTests/ParsingTests.swift
Assets/                      иконка (исходник SVG + .icns)
scripts/build-app.sh, scripts/gen-portdata.py
.github/workflows/           CI (тесты + сборка) и релиз (опубликованный релиз → zip с .app)
```

## Релиз

Откройте **Releases → Draft a new release**, создайте тег, например `v1.0.0`, нажмите **Generate release notes** и **Publish**. Через несколько минут GitHub Actions соберёт universal-приложение и прикрепит к релизу `LANA-Scanner-<версия>-macOS.zip` с контрольной суммой SHA-256.

## Благодарности

- Рейтинг популярности портов и названия сервисов взяты из [`nmap-services`](https://github.com/nmap/nmap/blob/master/nmap-services) (Nmap Project). Сам nmap не входит в проект и не требуется.
- Данные о производителях — [реестр IEEE OUI](https://standards-oui.ieee.org/), скачиваются во время работы и не распространяются с проектом.

## Лицензия

[MIT](LICENSE) © 2026 Vianor Gvazbaya
