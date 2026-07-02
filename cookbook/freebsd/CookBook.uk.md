# Кулінарна книга FreeBSD

> 🌐 [English](CookBook.md) | [Русский](CookBook.ru.md)

## Огляд

ArxSentinel поставляється з рідною бінарниці для FreeBSD (`freebsd/{386,amd64,arm,arm64}`)
через goreleaser, плюс виділений інсталятор та rc.d-скрипт сервісу. Рекомендована
архітектура — **ArxSentinel працює нативно на хосту FreeBSD** — він не контейнеризований.
Якщо ваш веб-сервер (nginx, Caddy, Traefik, HAProxy, Apache, LiteSpeed...) працює в контейнері
`podman` на тому ж хосту FreeBSD, ArxSentinel читає логи доступу контейнера через змонтований
шлях на хосту або через мережеве джерело (syslog/HTTP), точно як у будь-якому іншому рецепті
цієї книги.

Чому нативно, а не в контейнері: FreeBSD не має контейнерного рантайму, сумісного з
Linux-ядром — `podman` на FreeBSD запускає Linux-контейнери через експериментальний шар
емуляції Linux-сумісності (`ocijail` + `linprocfs`/`linsysfs`). Цей шар емуляції
достатньо добрий для запуску веб-сервера, але запуск самого ArxSentinel там нічого не дає
та додає шар трансляції між бінарником та ОС, яку йому потрібно аналізувати
(спостереження файлів, обробка сигналів). Нативний запуск повністю уникає цього — це також
точна архітектура, яку перевіряє власний FreeBSD CI-набір цього проекту
(`tests/integration-freebsd/`).

## Швидкий старт

Завантажте архів `freebsd_<arch>` зі сторінки
[релізів](https://github.com/mr-addams/arxsentinel/releases),
розпакуйте його та запустіть інсталятор від root:

```sh
fetch https://github.com/mr-addams/arxsentinel/releases/latest/download/arxsentinel_<version>_freebsd_<arch>.tar.gz
tar xzf arxsentinel_<version>_freebsd_<arch>.tar.gz
cd arxsentinel_<version>_freebsd_<arch>
sudo sh install.sh
```

Інсталятор (`packaging/freebsd/install.sh` у вихідному дереві) ідемпотентний — безпечно
повторно використовувати при оновленні. Він:

1. Створює виділеного системного користувача/групу `arxsentinel` (без shell для входу)
2. Готує `/var/log/arxsentinel` (0750, належить користувачу сервісу)
3. Встановлює бінарник у `/usr/local/bin/arxsentinel` (0555, захищено від запису)
4. Встановлює rc.d-скрипт у `/usr/local/etc/rc.d/arxsentinel`
5. Копіює `config.yaml.example` + `config.reference.yaml` у
   `/usr/local/etc/arxsentinel/`
6. Ініціалізує `config.yaml` з прикладу **лише якщо його немає** — повторне використання
   інсталятора ніколи не перезапише вашу конфігурацію

Він **не** запускає сервіс автоматично — спочатку перевірте конфігурацію
(executor'и можуть звертатися до реальних бэкендів WAF/Cloudflare/MikroTik при першому запуску).

### Розташування файлів на FreeBSD

Відрізняється від Linux-паковки (`/etc/arxsentinel/`,
systemd `RuntimeDirectory=`) — FreeBSD слідує конвенції для програм третіх сторін (`/usr/local/`):

| Призначення | Шлях |
|---|---|
| Бінарник | `/usr/local/bin/arxsentinel` |
| rc.d-скрипт | `/usr/local/etc/rc.d/arxsentinel` |
| Директорія конфігурації | `/usr/local/etc/arxsentinel/` |
| Активна конфігурація | `/usr/local/etc/arxsentinel/config.yaml` |
| Директорія стану (домашня папка користувача сервісу) | `/var/db/arxsentinel/` |
| Логи | `/var/log/arxsentinel/` |
| Pidfile | `/var/run/arxsentinel/arxsentinel.pid` |

**Важливо знати, якщо ви вручну збираєте/запускаєте бінарник** (не через інсталятор):
скомпільований за замовчуванням шлях конфігурації демона (`cmd/arxsentinel/main.go`)
— це `/etc/arxsentinel/config.yaml` — специфічний для Linux дефолт. На FreeBSD ви завжди
повинні явно передати `-config=` (або `--config=`, обидва прийняті). rc.d-скрипт інсталятора
вже робить це за вас через `command_args`.

### Управління сервісом

```sh
sysrc arxsentinel_enable=YES       # зберегти при перезавантаженні (/etc/rc.conf)
service arxsentinel start
service arxsentinel status
service arxsentinel stop
```

Стандартна сантехніка `rc.subr` — `arxsentinel_user`/`arxsentinel_group` попередньо встановлені
у rc.d-скрипті (зниження привілеїв для користувача `arxsentinel` перед exec), та хук
`start_precmd` створює `/var/run/arxsentinel/` при першому старті (у FreeBSD's rc.d немає
еквіваленту systemd `RuntimeDirectory=`).

### Видалення (ручне — `pkg`/uninstaller ще немає)

```sh
service arxsentinel stop
sysrc arxsentinel_enable=NO
rm /usr/local/bin/arxsentinel /usr/local/etc/rc.d/arxsentinel
rm -rf /usr/local/etc/arxsentinel /var/log/arxsentinel
pw userdel arxsentinel
```

---

## Запуск веб-серверів у podman на FreeBSD

Якщо ваш веб-сервер працює в контейнері `podman` на тому ж хосту FreeBSD
(замість нативного, або на окремому хосту Linux/Docker),
`sysutils/podman` на FreeBSD має справжні, гострі відмінності від Docker/Linux podman.
Цей розділ — кураційний, сконцентрований на розгортанні підмножина того, що
довелося вирішувати власному FreeBSD CI-набору цього проекту (`tests/integration-freebsd/`)
за ~130 запусків CI на живих серверах — повний список внутрішніх "граблей" (включаючи
CI-специфічний матеріал) живе у `DECISIONS.md` файлах цього набору, якщо вам потрібно
більше деталей, ніж нижче.

### Однократне налаштування podman

```sh
pkg install sysutils/podman
```

1. **Storage driver — перемкнути `zfs` → `vfs`.** Дефолтний драйвер `storage.conf`
   у `sysutils/podman` — це `zfs`, який не працює з коробки на більшості
   FreeBSD-встановлень (немає zpool, налаштованого під сховище podman). Відредагуйте
   `/usr/local/etc/containers/storage.conf`:
   ```
   [storage]
   driver = "vfs"
   ```
2. **Firewall pf — обов'язковий для будь-якої podman-мережі.** CNI-мережевий міст podman
   вимагає активного `pf` з увімкненою фільтрацією локального трафіку:
   ```sh
   kldload pf
   sysrc pf_enable=YES
   echo 'pass all' >> /etc/pf.conf   # або реальний набір правил
   service pf start
   sysctl net.pf.filter_local=1
   ```
3. **Linux-шар сумісності** (найкращий випадок, потрібен для будь-якого Linux-контейнера):
   ```sh
   sysrc linux_enable=YES
   service linux start
   ```

### Завантаження та запуск Linux-образів

- **Завжди використовуйте повні імена образів.** `nginx:alpine` падає з помилкою
  *"did not resolve to an alias and no unqualified-search registries are defined"* —
  дефолтний `registries.conf` FreeBSD podman не має запису
  `unqualified-search-registries`. Використовуйте замість цього `docker.io/library/nginx:alpine`.
- **`--os=linux` при кожному `podman run`/`pull` Linux-образу.** Без цього podman шукає
  варіант ОС `freebsd` в індексі образів та падає з помилкою *"no image found in image index for
  architecture amd64 ... OS freebsd"*.
- **`--platform linux/amd64` при `podman build`** (інший прапор, ніж два вище —
  `build` не приймає `--os`).
- **Без DNS-розрізнення імен контейнерів.** Пакет FreeBSD `containernetworking-plugins`
  поставляється лише з базовим CNI-плагіном моста — немає плагіна `dnsname` (те, що дає
  Docker/Linux podman "розрізнення інших контейнерів по `--name`" безкоштовно через
  netavark+aardvark-dns). Якщо одному контейнеру потрібно досягти іншого за ім'ям,
  розрізніть його CNI-назначений IP явно:
  ```sh
  podman inspect <container> --format '{{(index .NetworkSettings.Networks "<network>").IPAddress}}'
  ```
  (Використовуйте функцію `index` Go-шаблонів для імен мереж, що містять дефіс — точкова
  нотація вроді `.Networks.my-net` парсить дефіс як віднімання та падає.)

### `podman pod` / `podman-compose` — не використовуйте

**Мульти-контейнерна оркестрація через `podman pod` (і отже,
`podman-compose`, що використовує pods як підлягаючий механізм) не працює надійно
на FreeBSD podman + `ocijail`.** Контейнер, який працює стабільно самостійно
(`podman run --network X --os=linux ...`), ломається, коли помісцений у pod
(`podman run --pod <name> ...`) з ідентичною командою — підтверджено прямим A/B-тестуванням:
той же образ nginx крашується при старті з `io_setup() failed (38: Function not implemented)`
лише при pod-обгортці, ніколи самостійно. Це обмеження апстриму в поточній реалізації
pod на podman-на-FreeBSD/ocijail, не помилка конфігурації — `podman` на FreeBSD явно
позначено експериментальним його власними мейнтейнерами.

**Практичне наслідок:** якщо вам потрібні кілька контейнерів в одній мережі
(наприклад, зворотний проксі + бэкенд), запустіть кожного простою самостійною
командою `podman run --network <shared-network> ...` — ніколи `podman pod create` + `--pod`,
та не тягніться до `podman-compose` на FreeBSD взагалі. Власний мульти-контейнерний
FreeBSD-тест цього проекту (сценарії ланцюга зворотних проксі) використовує точно цей
паттерн самостійних контейнерів.

### Якщо вивід логів контейнера мовчки зникає

Два незалежні причини, легко сплутати:

1. **Bind-змонтування директорії логів скриває дефолтний симлінк `error_log -> /dev/stderr`
   образу.** Більшість офіційних образів веб-серверів симлінкують свій логе помилок на
   `/dev/stderr`, щоб `podman logs` їх захоплював. Bind-змонтування вашої власної
   директорії на цей шлях логу (наприклад, `-v $HOST_DIR:/var/log/nginx`) заміняє симлінк
   реальним файлом — `podman logs <container>` тоді не показує нічого, хоча сервер
   запустився нормально та пише логи у змонтований файл сам. Виправлення: явно перенаправте
   вивід помилок назад на stderr у вашій конфігурації (наприклад, `error_log /dev/stderr;`
   у nginx, `ErrorLog /dev/stderr` в Apache) — не покладайтесь на те, що дефолтний
   симлінк образу пережив змонтування над його батьківською директорією.
2. **`/proc/1/fd/N` procfs-симлінк-на-stdout трюки ломаються повністю.** Деякі
   офіційні образи налаштовують логування через симлінк через `/proc/1/fd/1` або
   `/proc/1/fd/2` замість простого вузла пристрою `/dev/stdout`. FreeBSD's `linprocfs`
   (емуляція Linux `/proc`) не заповнює `/proc/1/fd/` так, як нативне Linux-ядро —
   контейнер падає на своїй власній перевірці конфігурації при старті з помилкою
   вроді *"Cannot access directory '/proc/1/fd/' for main error log"*. Спрямуйте директиви
   логування прямо на `/dev/stderr`/`/dev/stdout` замість цього.

### Побудова користувацького образу (наприклад, Caddy з нестандартним плагіном)

Якщо вам потрібен користувацький образ (збірка Caddy з плагіном
`transform-encoder` для логів у форматі Apache-CLF, наприклад), **збирайте його на
нативному хосту Linux/Docker, а не через `podman build` на самому хосту FreeBSD.**
`podman build` під емуляцією Linux FreeBSD потрапляє у кластер збоїв, специфічних
для toolchain — статично зв'язаний Go-бінарник не може самовизначити `GOROOT`
через `readlink /proc/self/exe` під `linprocfs`, та DNS-розрізнення до прокси модулів
(`proxy.golang.org` і т.д.) може таймаутити всередині контейнера збірки, хоча той же
мережевий шлях працює нормально для простого `podman pull`. Збирайте образ де-небудь
ще, `docker save` його у tar, скопіюйте tar на хост FreeBSD, та `podman load -i`
його там — чистий локальний імпорт без мережевих/toolchain залежностей.

### Зворотний проксі real-IP: перевірте механізм по бэкенду, не припускайте переносимість

Якщо ваш веб-сервер перебуває за зворотним проксі та ви хочете, щоб
*логи самого бэкенда* (не просто логи ArxSentinel [Зворотній проксі /
Real-IP](../CookBook.uk.md#зворотній-проксі--real-ip)) показували реальну IP адресу клієнта
замість IP проксі, точний механізм залежить від бэкенда — не припускайте, що паттерн
nginx `real_ip_module` (`set_real_ip_from` + `real_ip_header`) переносится на кожен інший
сервер. Caddy особливо пастка: `trusted_proxies` **не** переписує сире значення
`{request>remote_ip}`, яке логує плагін `transform-encoder` — вам потрібно змінити
*саму рядок формату логування* на вираз fallback:
`{request>headers>X-Forwarded-For>[0]:request>remote_ip}` ("використовувати XFF якщо є,
інакше remote_ip"). Traefik, з іншого боку, `forwardedHeaders.trustedIPs` дійсно
працює як очікується. Apache's `mod_remoteip` (`RemoteIPHeader` + `RemoteIPInternalProxy`)
також працює як очікується та поставляється у stock образі `httpd:latest` (користувацька
збірка не потрібна). При проводці цього перевірте фактичний вивід логування —
не припускайте, що прийняття конфігурації означає поведінкову коректність.

---

## Див. також

- [config.reference.yaml](../config.reference.yaml) — повний довідник конфігурації
- [Зворотній проксі / Real-IP](../CookBook.uk.md#зворотній-проксі--real-ip) — рецепти real-IP на стороні ArxSentinel (nginx/Caddy/HAProxy/Traefik впереді nginx)
- [Конфігурації серверів](../CookBook.uk.md#конфігурації-серверів) — фрагменти формату логу для кожного веб-сервера
