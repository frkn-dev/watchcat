# Журнал изменений маршрутизации (route audit)

Требование: **все** изменения маршрутизации трафика должны логироваться
отдельно от прочего шума. Поэтому у демона два независимых стока:

| Сток | Куда | Что пишет | Объём |
|---|---|---|---|
| application log | stdout → journald | пробы, тики, ошибки, метрики | десятки строк в минуту |
| **route audit** | `logging.audit_path` (JSONL, append-only) | только то, что меняет (или пытается изменить) выход трафика | единицы строк в сутки |

Отдельный файл нужен, чтобы на вопрос «кто переключил трафик в 03:14 и почему»
можно было ответить без grep по журналу из миллионов строк проб.

## 1. Формат

Одна строка = одно событие = один `write()` в файл. JSON Lines, UTF-8, без
вложенных объектов. Файл только дописывается: демон никогда не перезаписывает и
не удаляет записи (ротация — снаружи, см. §5).

```json
{"ts":"2026-10-21T23:01:42.385Z","unix_ms":1792623702385,"pid":43925,"version":"0.1.0","event":"quarantine_enter","selector":"main-outbound","to":"node-01-fr-vless","reason":"failed","fails":2,"quarantine_ms":5000}
{"ts":"2026-10-21T23:01:42.385Z","unix_ms":1792623702385,"pid":43925,"version":"0.1.0","event":"route_switch","selector":"main-outbound","from":"node-01-fr-vless","to":"node-02-de-hysteria","reason":"active_failed","latency_ms":25,"fails":2,"api_ok":true,"api_roundtrip_ms":0,"trigger":"probe"}
```

## 2. Поля

| Поле | Тип | Всегда | Смысл |
|---|---|---|---|
| `ts` | string | да | RFC3339, UTC, миллисекунды |
| `unix_ms` | u64 | да | то же в миллисекундах эпохи — удобно для `jq`/БД |
| `pid` | u32 | да | PID демона (после рестарта меняется — так видно границу жизни процесса) |
| `version` | string | да | версия watchcat |
| `event` | string | да | тип события, см. §3 |
| `selector` | string | да | тег управляемой группы (`main-outbound`) |
| `from` | string? | нет | откуда ушёл трафик (для `route_switch`, `active_adopted`) |
| `to` | string? | нет | куда пришёл / кого касается событие (нода) |
| `reason` | string | нет | причина: `active_failed`, `active_blocked`, `active_degraded`, `better_candidate`, `no_active`, `active_missing`, `failed`, `blocked`, `manual`, `external_change`, `initial_sync`, `all_members_unusable` |
| `latency_ms` | u32? | нет | EWMA выбранной ноды на момент решения |
| `fails` | u32? | нет | сколько подряд провалов у виновника |
| `quarantine_ms` | u64? | нет | длительность карантина |
| `api_ok` | bool? | нет | принял ли sing-box команду `PUT` |
| `api_roundtrip_ms` | u64? | нет | сколько занял `PUT` (loopback обычно 0 ms) |
| `trigger` | string? | нет | `probe` (обычный цикл) или `dry_run` (`--dry-run`) |

Поля с `null`/отсутствием просто не сериализуются — строка остаётся компактной.

## 3. Типы событий

| `event` | Когда | Ключевые поля |
|---|---|---|
| `route_switch` | отправлен `PUT /proxies/{selector}` (или был бы отправлен в dry-run) | `from`, `to`, `reason`, `latency_ms`, `fails`, `api_ok`, `trigger` |
| `quarantine_enter` | нода переведена в карантин (ровно один раз за эпизод) | `to`, `reason`, `fails`, `quarantine_ms` |
| `quarantine_exit` | нода снова стала кандидатом после `recovery_probes` успехов | `to` |
| `active_adopted` | текущая нода взята из API: первый синк (`initial_sync`) или оператор переключил руками (`external_change`) | `from`, `to`, `reason` |
| `no_healthy_node` | кандидатов нет; трафик оставлен на текущей ноде | `from`, `reason` |
| `intercept_failure` | Clash delay ок, а end-to-end проба через локальный прокси — нет (сломан перехват, а не нода) | `from`, `reason` |

События `degraded`, `geo_blocked`, `member_added/removed` в audit **не**
попадают: это наблюдения, а не изменения маршрута. Они есть в обычном логе
(WARN/INFO) и в метриках.

## 4. Гарантии и их границы

* **Атомарность записи.** Строка формируется в памяти и пишется одним
  `write` (плюс `flush`), поэтому при падении процесса в файле не остаётся
  половины JSON. `logging.fsync_audit: true` дополнительно делает `fdatasync` —
  запись переживёт потерю питания, но каждый свитч станет дороже на ~ms.
* **Порядок = причинность.** Внутри одного тика события пишутся в порядке
  возникновения: сначала `quarantine_enter`, затем `route_switch`. По `unix_ms`
  видно, что переключение произошло в том же тике.
* **`api_ok: false` — тоже история.** Если sing-box отклонил `PUT`, запись
  остаётся: важно знать, что демон *пытался* переключить и получил отказ. На
  следующем тике состояние сверяется с API, и появляется `active_adopted`.
* **dry-run пишет.** `--dry-run` создаёт `route_switch` c `trigger: dry_run` и
  `api_ok: true` (в смысле «решение было бы применено»), но `PUT` не уходит —
  это видно по `trigger`.
* **Отказ диска не останавливает роутинг.** Если запись не удалась, демон
  пишет один ERROR, отключает audit-сток и продолжает работу. Молча — нет;
  молчаливая потеря аудита хуже, чем остановка записи.
* **Секретов в журнале нет.** Ни `api.secret`, ни Telegram-токен, ни UUID нод
  не пишутся: только теги и числа.

## 5. Ротация и хранение

Демон не ротирует файл сам (переоткрытие по SIGHUP не поддерживается — это
лишний код и лишний режим отказа). Используется `logrotate` с `copytruncate`,
чтобы демон продолжал писать в тот же inode:

```
/var/log/watchcat/routes.jsonl {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

Готовый файл: `deploy/logrotate.conf`. Для централизованного хранения —
`rsync`/`vector`/`promtail` по этому же файлу; формат JSONL специально
дружелюбен к построчным шипперам.

Аудит-журнал — единственное место, где история переключений живёт дольше
journald. 90 дней дневной ротации при реальном объёме (единицы строк в сутки,
десятки при инциденте) — это килобайты.

## 6. Рецепты `jq`

Все переключения за сутки, по времени:

```bash
jq -r 'select(.event=="route_switch") | "\(.ts) \(.from // "-") -> \(.to) [\(.reason)] lat=\(.latency_ms)ms fails=\(.fails)"' \
   /var/log/watchcat/routes.jsonl | tail -50
```

Кто виноват чаще всех (по событиям карантина):

```bash
jq -r 'select(.event=="quarantine_enter") | .to' /var/log/watchcat/routes.jsonl \
  | sort | uniq -c | sort -rn
```

Сколько переключений за последний час (флаппинг-детектор):

```bash
jq -r --argjson since "$(( ($(date +%s) - 3600) * 1000 ))" \
   'select(.event=="route_switch" and .unix_ms > $since) | .to' \
   /var/log/watchcat/routes.jsonl | wc -l
```

Задержка «обнаружили → переключили» (в пределах одного тика):

```bash
jq -s '
  [ .[] | select(.event=="quarantine_enter" or .event=="route_switch") ]
  | group_by(.unix_ms)
  | map(select(any(.[]; .event=="quarantine_enter") and any(.[]; .event=="route_switch")))
  | length
' /var/log/watchcat/routes.jsonl
```

Отказы `PUT` (проблемы с API/селектором):

```bash
jq -r 'select(.event=="route_switch" and .api_ok==false) | "\(.ts) \(.to) api_ok=false"' \
   /var/log/watchcat/routes.jsonl
```

Все вмешательства оператора (ручные переключения):

```bash
jq -r 'select(.event=="active_adopted" and .reason=="external_change") | "\(.ts) \(.from // "-") -> \(.to)"' \
   /var/log/watchcat/routes.jsonl
```

Сломанный перехват (не нода):

```bash
jq -r 'select(.event=="intercept_failure") | "\(.ts) \(.from) \(.reason)"' \
   /var/log/watchcat/routes.jsonl
```

## 7. SLO, которые считаются из журнала

| Показатель | Формула |
|---|---|
| доступность маршрута | доля времени без `no_healthy_node` |
| MTTR на инцидент | `route_switch.unix_ms - quarantine_enter.unix_ms` для одного эпизода |
| частота переключений | `route_switch` за час (норма: < 3) |
| доля ручных вмешательств | `active_adopted(external_change)` / все `route_switch` |
| здоровье управления | `route_switch(api_ok=false)` = 0 |

## 8. Проверка, что журнал живой (без ожидания инцидента)

```bash
# один тик «на сухую» с принудительным свитчем на заведомо живой тег
watchcat --config /etc/watchcat/config.yaml --set node-02-de-hysteria
jq -r 'select(.event=="route_switch")' /var/log/watchcat/routes.jsonl | tail -1
```

E2E-проверка журнала на mock-стенде — `OPERATIONS.md` §5: там же показан
реальный вывод трёх записей (initial_sync → quarantine_enter → route_switch).
