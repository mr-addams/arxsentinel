# Кулинарная книга FreeBSD

> 🌐 [English](CookBook.md) | [Українська](CookBook.uk.md)

## Обзор

ArxSentinel поставляется с собственным бинарником для FreeBSD (`freebsd/{386,amd64,arm,arm64}`)
через goreleaser, плюс выделенный инсталлятор и rc.d-скрипт сервиса. Рекомендуемая
архитектура — **ArxSentinel работает нативно на хосте FreeBSD** — он не контейнеризирован.
Если ваш веб-сервер (nginx, Caddy, Traefik, HAProxy, Apache, LiteSpeed...) работает в контейнере
`podman` на том же хосте FreeBSD, ArxSentinel читает логи доступа контейнера через смонтированный
путь на хосте или через сетевой источник (syslog/HTTP), ровно как в любом другом рецепте этой книги.

Почему нативно, а не в контейнере: FreeBSD не имеет контейнерного рантайма, совместимого с
Linux-ядром — `podman` на FreeBSD запускает Linux-контейнеры через экспериментальный слой
эмуляции Linux-совместимости (`ocijail` + `linprocfs`/`linsysfs`). Этот слой эмуляции
достаточно хорош для запуска веб-сервера, но запуск самого ArxSentinel там ничего не даёт
и добавляет слой трансляции между бинарником и ОС, которую ему нужно анализировать
(просмотр файлов, обработка сигналов). Нативный запуск полностью избегает этого — это также
точная архитектура, которую проверяет собственный FreeBSD CI-набор этого проекта
(`tests/integration-freebsd/`).

## Быстрый старт

Загрузите архив `freebsd_<arch>` со страницы
[релизов](https://github.com/mr-addams/arxsentinel/releases),
распакуйте его и запустите инсталлятор от root:

```sh
fetch https://github.com/mr-addams/arxsentinel/releases/latest/download/arxsentinel_<version>_freebsd_<arch>.tar.gz
tar xzf arxsentinel_<version>_freebsd_<arch>.tar.gz
cd arxsentinel_<version>_freebsd_<arch>
sudo sh install.sh
```

Инсталлятор (`packaging/freebsd/install.sh` в исходном дереве) идемпотентен — безопасно
переиспользовать при обновлении. Он:

1. Создаёт выделенного системного пользователя/группу `arxsentinel` (без shell для входа)
2. Подготавливает `/var/log/arxsentinel` (0750, принадлежит пользователю сервиса)
3. Устанавливает бинарник в `/usr/local/bin/arxsentinel` (0555, защищен от записи)
4. Устанавливает rc.d-скрипт в `/usr/local/etc/rc.d/arxsentinel`
5. Копирует `config.yaml.example` + `config.reference.yaml` в
   `/usr/local/etc/arxsentinel/`
6. Инициализирует `config.yaml` из примера **только если его нет** — переиспользование
   инсталлятора никогда не перезатрёт вашу настройку

Он **не** запускает сервис автоматически — сначала проверьте конфигурацию
(executor'ы могут обращаться к реальным бэкэндам WAF/Cloudflare/MikroTik при первом запуске).

### Расположение файлов на FreeBSD

Отличается от Linux-паковки (`/etc/arxsentinel/`,
systemd `RuntimeDirectory=`) — FreeBSD следует соглашению для программ третьих сторон (`/usr/local/`):

| Назначение | Путь |
|---|---|
| Бинарник | `/usr/local/bin/arxsentinel` |
| rc.d-скрипт | `/usr/local/etc/rc.d/arxsentinel` |
| Директория конфигурации | `/usr/local/etc/arxsentinel/` |
| Активная конфигурация | `/usr/local/etc/arxsentinel/config.yaml` |
| Директория состояния (домашняя папка пользователя сервиса) | `/var/db/arxsentinel/` |
| Логи | `/var/log/arxsentinel/` |
| Pidfile | `/var/run/arxsentinel/arxsentinel.pid` |

**Важно знать, если вы вручную собираете/запускаете бинарник** (не через инсталлятор):
скомпилированный дефолтный путь конфигурации демона (`cmd/arxsentinel/main.go`)
— это `/etc/arxsentinel/config.yaml` — специфичный для Linux дефолт. На FreeBSD вы всегда
должны явно передать `-config=` (или `--config=`, оба приняты). rc.d-скрипт инсталлятора
уже делает это за вас через `command_args`.

### Управление сервисом

```sh
sysrc arxsentinel_enable=YES       # сохранить при перезагрузке (/etc/rc.conf)
service arxsentinel start
service arxsentinel status
service arxsentinel stop
```

Стандартная сантехника `rc.subr` — `arxsentinel_user`/`arxsentinel_group` предустановлены
в rc.d-скрипте (снижение привилегий для пользователя `arxsentinel` перед exec), и хук
`start_precmd` создаёт `/var/run/arxsentinel/` при первом старте (в FreeBSD's rc.d нет
эквивалента systemd `RuntimeDirectory=`).

### Удаление (ручное — `pkg`/uninstaller ещё нет)

```sh
service arxsentinel stop
sysrc arxsentinel_enable=NO
rm /usr/local/bin/arxsentinel /usr/local/etc/rc.d/arxsentinel
rm -rf /usr/local/etc/arxsentinel /var/log/arxsentinel
pw userdel arxsentinel
```

---

## Запуск веб-серверов в podman на FreeBSD

Если ваш веб-сервер работает в контейнере `podman` на том же хосте FreeBSD
(вместо нативного, или на отдельном хосте Linux/Docker),
`sysutils/podman` на FreeBSD имеет настоящие, острые отличия от Docker/Linux podman.
Этот раздел — курируемое, сконцентрированное на развёртывании подмножество того, что
пришлось решать собственному FreeBSD CI-набору этого проекта (`tests/integration-freebsd/`)
за ~130 запусков CI на живых серверах — полный список внутренних "граблей" (включая
CI-специфичный материал) живёт в `DECISIONS.md` файлах этого набора, если вам нужно
больше деталей, чем ниже.

### Однократная настройка podman

```sh
pkg install sysutils/podman
```

1. **Storage driver — переключить `zfs` → `vfs`.** Дефолтный драйвер `storage.conf`
   в `sysutils/podman` — это `zfs`, который не работает из коробки на большинстве
   FreeBSD-установок (нет zpool, настроенного под хранилище podman). Отредактируйте
   `/usr/local/etc/containers/storage.conf`:
   ```
   [storage]
   driver = "vfs"
   ```
2. **Firewall pf — обязателен для любой podman-сети.** CNI-сетевой мост podman требует
   активного `pf` с включённой фильтрацией локального трафика:
   ```sh
   kldload pf
   sysrc pf_enable=YES
   echo 'pass all' >> /etc/pf.conf   # или реальный набор правил
   service pf start
   sysctl net.pf.filter_local=1
   ```
3. **Linux-слой совместимости** (лучший случай, требуется для любого Linux-контейнера):
   ```sh
   sysrc linux_enable=YES
   service linux start
   ```

### Загрузка и запуск Linux-образов

- **Всегда используйте полные имена образов.** `nginx:alpine` падает с ошибкой
  *"did not resolve to an alias and no unqualified-search registries are defined"* —
  дефолтный `registries.conf` FreeBSD podman не имеет записи
  `unqualified-search-registries`. Используйте вместо этого `docker.io/library/nginx:alpine`.
- **`--os=linux` при каждом `podman run`/`pull` Linux-образа.** Без этого podman ищет
  вариант ОС `freebsd` в индексе образов и падает с ошибкой *"no image found in image index for
  architecture amd64 ... OS freebsd"*.
- **`--platform linux/amd64` при `podman build`** (другой флаг, чем два выше —
  `build` не принимает `--os`).
- **Без DNS-разрешения имён контейнеров.** Пакет FreeBSD `containernetworking-plugins`
  поставляется только с базовым CNI-плагином моста — нет плагина `dnsname` (то, что даёт
  Docker/Linux podman "разрешение других контейнеров по `--name`" бесплатно через
  netavark+aardvark-dns). Если одному контейнеру нужно достичь другого по имени,
  разрешите его CNI-назначенный IP явно:
  ```sh
  podman inspect <container> --format '{{(index .NetworkSettings.Networks "<network>").IPAddress}}'
  ```
  (Используйте функцию `index` Go-шаблонов для имён сетей, содержащих дефис — точечная
  нотация вроде `.Networks.my-net` парсит дефис как вычитание и падает.)

### `podman pod` / `podman-compose` — не используйте

**Мульти-контейнерная оркестрация через `podman pod` (и следовательно,
`podman-compose`, что использует pods как подлежащий механизм) не работает надёжно
на FreeBSD podman + `ocijail`.** Контейнер, который работает стабильно самостоятельно
(`podman run --network X --os=linux ...`), ломается, когда помещён в pod
(`podman run --pod <name> ...`) с идентичной командой — подтверждено прямым A/B-тестированием:
тот же образ nginx крашится при старте с `io_setup() failed (38: Function not implemented)`
только при pod-обёртке, никогда самостоятельно. Это лимитация апстрима в текущей реализации
pod на podman-на-FreeBSD/ocijail, не ошибка конфигурации — `podman` на FreeBSD явно
помечен экспериментальным его собственными мейнтейнерами.

**Практическое следствие:** если вам нужны несколько контейнеров в одной сети
(например, обратный прокси + бэкэнд), запустите каждый простой самостоятельной
командой `podman run --network <shared-network> ...` — никогда `podman pod create` + `--pod`,
и не тянитесь к `podman-compose` на FreeBSD вообще. Собственный мульти-контейнерный
FreeBSD-тесты этого проекта (сценарии цепочки обратных прокси) используют точно этот
паттерн самостоятельных контейнеров.

### Если вывод логов контейнера молча исчезает

Две независимые причины, легко спутать:

1. **Bind-монтирование директории логов скрывает дефолтный симлинк `error_log -> /dev/stderr`
   образа.** Большинство официальных образов веб-серверов симлинкуют свой логе ошибок на
   `/dev/stderr`, чтобы `podman logs` их захватывал. Bind-монтирование вашей собственной
   директории на этот путь лога (например, `-v $HOST_DIR:/var/log/nginx`) заменяет симлинк
   реальным файлом — `podman logs <container>` тогда не показывает ничего, хотя сервер
   запустился нормально и пишет логи в смонтированный файл сам. Исправление: явно перенаправьте
   вывод ошибок обратно на stderr в вашей конфигурации (например, `error_log /dev/stderr;`
   в nginx, `ErrorLog /dev/stderr` в Apache) — не полагайтесь на то, что дефолтный
   симлинк образа пережив монтирование над его родительской директорией.
2. **`/proc/1/fd/N` procfs-симлинк-на-stdout трюки ломаются полностью.** Некоторые
   официальные образы настраивают логирование через симлинк через `/proc/1/fd/1` или
   `/proc/1/fd/2` вместо простого узла устройства `/dev/stdout`. FreeBSD's `linprocfs`
   (эмуляция Linux `/proc`) не заполняет `/proc/1/fd/` так, как нативное Linux-ядро —
   контейнер падает на своей собственной проверке конфигурации при старте с ошибкой
   вроде *"Cannot access directory '/proc/1/fd/' for main error log"*. Направьте директивы
   логирования прямо на `/dev/stderr`/`/dev/stdout` вместо этого.

### Построение пользовательского образа (например, Caddy с нестандартным плагином)

Если вам нужен пользовательский образ (сборка Caddy с плагином
`transform-encoder` для логов в формате Apache-CLF, например), **собирайте его на
нативном хосте Linux/Docker, а не через `podman build` на самом хосте FreeBSD.**
`podman build` под эмуляцией Linux FreeBSD попадает в кластер сбоев, специфичных
для toolchain — статически слинкованный Go-бинарник не может самоопределить `GOROOT`
через `readlink /proc/self/exe` под `linprocfs`, и DNS-разрешение до прокси модулей
(`proxy.golang.org` и т.д.) может таймаутить изнутри контейнера сборки, хотя тот же
сетевой путь работает нормально для простого `podman pull`. Собирайте образ где-нибудь
ещё, `docker save` его в tar, скопируйте tar на хост FreeBSD, и `podman load -i`
его там — чистый локальный импорт без сетевых/toolchain зависимостей.

### Обратный прокси real-IP: проверьте механизм по бэкэнду, не предполагайте переносимость

Если ваш веб-сервер находится за обратным прокси и вы хотите, чтобы
*логи самого бэкэнда* (не просто логи ArxSentinel [Обратный прокси /
Real-IP](../CookBook.ru.md#обратный-прокси--real-ip)) показывали реальный IP клиента
вместо IP прокси, точный механизм зависит от бэкэнда — не предполагайте, что паттерн
nginx `real_ip_module` (`set_real_ip_from` + `real_ip_header`) переносится на каждый другой
сервер. Caddy особенно ловушка: `trusted_proxies` **не** переписывает сырое значение
`{request>remote_ip}`, которое логирует плагин `transform-encoder` — вам нужно изменить
*сам строку формата логирования* на выражение fallback:
`{request>headers>X-Forwarded-For>[0]:request>remote_ip}` ("использовать XFF если есть,
иначе remote_ip"). Traefik, с другой стороны, `forwardedHeaders.trustedIPs` действительно
работает как ожидается. Apache's `mod_remoteip` (`RemoteIPHeader` + `RemoteIPInternalProxy`)
также работает как ожидается и поставляется в stock образе `httpd:latest` (пользовательская
сборка не требуется). При проводке этого проверьте фактический вывод логирования —
не предполагайте, что принятие конфигурации означает поведенческую корректность.

---

## Смотрите также

- [config.reference.yaml](../config.reference.yaml) — полный справочник конфигурации
- [Обратный прокси / Real-IP](../CookBook.ru.md#обратный-прокси--real-ip) — рецепты real-IP на стороне ArxSentinel (nginx/Caddy/HAProxy/Traefik впереди nginx)
- [Конфигурации серверов](../CookBook.ru.md#конфигурации-серверов) — фрагменты формата лога для каждого веб-сервера
