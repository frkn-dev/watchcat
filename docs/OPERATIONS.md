# Эксплуатация

## 1. Требования к sing-box

Нужны две вещи в `/opt/sing-box/config.json`:

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "<секрет>"
    }
  },
  "outbounds": [
    {
      "type": "selector",
      "tag": "main-outbound",
      "outbounds": ["node-01-fr-vless", "node-02-de-hysteria", "…"],
      "default": "node-01-fr-vless"
    }
  ]
}
```

Правила:

* `external_controller` — **только loopback**. У Clash API нет TLS и нет
  разграничения прав: выставленный наружу порт = удалённое управление вашим
  трафиком. `watchcat` откажется стартовать с `https://` базой, чтобы не
  создавать иллюзию защищённого канала.
* `secret` в sing-box и `api.secret` в конфиге watchcat должны совпадать.
* Тег селектора (`selector.tag`) — тот, что выше. Все ноды, между которыми
  можно переключаться, обязаны быть в `outbounds` этого селектора: `PUT` с
  тегом, которого нет в списке, sing-box отвергнет (400).
* `selector` — не `urltest`. `urltest` управляется сам и не принимает `PUT`.
* Роутинг (`route.rules`, `final`) должен указывать на селектор, а не на
  конкретную ноду, иначе переключение ничего не изменит.
* Полный пример — `docs/sing-box.example.json`.

Проверка до запуска демона:

```bash
SECRET='<секрет>'
curl -s -H "Authorization: Bearer $SECRET" http://127.0.0.1:9090/proxies/main-outbound | jq .
# ожидаем: {"type":"Selector","now":"node-01-fr-vless","all":[…10 тегов…]}

curl -s -o /dev/null -w '%{http_code}\n' -X PUT http://127.0.0.1:9090/proxies/main-outbound \
  -H "Authorization: Bearer $SECRET" -H 'Content-Type: application/json' \
  -d '{"name":"node-02-de-hysteria"}'
# ожидаем: 204
```

Если `curl` не работает — демон тоже не будет; не начинайте с демона.

## 2. Установка

```bash
install -d -o root -g root /opt/watchcat /etc/watchcat /var/log/watchcat
install -m 0755 target/release/watchcat /opt/watchcat/watchcat
install -m 0644 config.example.yaml /etc/watchcat/config.yaml
$EDITOR /etc/watchcat/config.yaml        # selector.tag, api.secret, e2e_proxy
install -m 0644 deploy/watchcat.service /etc/systemd/system/
install -m 0644 deploy/logrotate.conf /etc/logrotate.d/watchcat
systemctl daemon-reload && systemctl enable --now watchcat
systemctl status watchcat --no-pager
journalctl -u watchcat -n 20 --no-pager
```

Секрет лучше держать не в YAML, а в env-файле с правами 0600:

```bash
install -d -m 0750 /etc/watchcat
printf 'WATCHCAT_API_SECRET=%s\n' "$SECRET" > /etc/watchcat/env
chmod 0600 /etc/watchcat/env
# в юните: EnvironmentFile=/etc/watchcat/env
```

Проверка конфига без сети и без сайд-эффектов:

```bash
/opt/watchcat/watchcat --config /etc/watchcat/config.yaml --check
/opt/watchcat/watchcat --config /etc/watchcat/config.yaml --nodes
/opt/watchcat/watchcat --config /etc/watchcat/config.yaml --print-config   # секреты redacted
```

## 3. Метрики

`metrics.path` перезаписывается атомарно раз в тик. Для node_exporter:

```
--collector.textfile.directory=/var/log/watchcat
```

Основные серии: `watchcat_up`, `watchcat_active{tag}`, `watchcat_switches_total`,
`watchcat_node_ewma_ms{tag,protocol}`, `watchcat_node_fails_total{tag}`,
`watchcat_node_quarantined{tag}`, `watchcat_node_geo_blocked{tag}`,
`watchcat_loop_duration_ms`, `watchcat_api_errors_total`,
`watchcat_switch_failures_total`, `watchcat_intercept_failures_total`,
`watchcat_last_switch_timestamp_seconds`.

Алерты, которые имеет смысл поставить сразу:

| Условие | Смысл |
|---|---|
| `up{job="watchcat"} == 0` или `watchcat_up == 0` дольше 2 мин | демон/API недоступны |
| `rate(watchcat_switches_total[10m]) > 0.3` | флаппинг (>3 свитча за 10 мин) |
| `sum(watchcat_node_quarantined) == count(watchcat_node_ewma_ms)` | весь пул в карантине |
| `increase(watchcat_switch_failures_total[5m]) > 0` | sing-box отвергает `PUT` |
| `increase(watchcat_intercept_failures_total[5m]) > 0` | сломан локальный перехват, не ноды |

## 4. Перевод ноды с `urltest` на `selector` (наш кейс relay-a)

Сейчас на `relay-a` (и `relay-b`) выход во Францию — это `urltest`:

```json
{ "type": "urltest", "tag": "fr-exit", "outbounds": ["fr-a","fr-b","fr-c"],
  "url": "https://www.gstatic.com/generate_204", "interval": "15s", "tolerance": 50 }
```

`urltest` сам меряет задержку, но не умеет карантин, не различает блокировку и
смерть, не пишет причин переключения и не проверяет локальный перехват.
Эквивалент на watchcat:

```json
{
  "type": "selector",
  "tag": "fr-exit",
  "outbounds": ["fr-a", "fr-b", "fr-c"],
  "default": "fr-b"
}
```

и в `/etc/watchcat/config.yaml`:

```yaml
selector:
  tag: fr-exit
  nodes:
    - tag: fr-a
      protocol: vless-reality
    - tag: fr-b
      protocol: vless-reality
    - tag: fr-c
      protocol: vless-reality
```

Порядок действий (без простоя):

1. В `config.json` добавить `experimental.clash_api` (loopback + secret).
2. **Не трогая** `fr-exit`, перезапустить sing-box и убедиться, что `GET
   /proxies/fr-exit` отвечает (пока это `urltest`, поля `all` может не быть —
   это нормально, шаг проверки только на доступность API).
3. Заменить `urltest` на `selector` с тем же тегом и тем же списком; `default`
   — текущая активная нода, чтобы не было скачка.
4. `sing-box check -c /opt/sing-box/config.json && systemctl restart sing-box`.
   Напоминание: перезапуск sing-box рвёт клиентские сессии; пиры AWG/WG это
   переживают, но `journalctl -u sing-box` стоит посмотреть.
5. Запустить watchcat с `--once` и убедиться, что он видит 3 ноды и ничего не
   переключает.
6. Включить сервис.

Откат — одна строка конфига обратно на `urltest` + `systemctl restart sing-box`.
Демон при этом продолжает работать, но `PUT` будет получать 400 (`not a
selector`) — это видно в логе и метрике `switch_failures_total`, так что откат
не остаётся незамеченным.

Эквивалентность порогов: `urltest` с `interval: 15s` / `tolerance: 50`
приблизительно соответствует `probe.interval_ms: 5000`,
`switch_margin_pct: 25`. Если хочется строго как было — поставьте
`probe.interval_ms: 15000`, `switch_margin_pct: 20`.

## 5. Проверка на стенде без sing-box (`mock-clash`)

`mock-clash` — фейковый Clash API + SOCKS5-инбаунд. Позволяет увидеть весь цикл
за 10 секунд, в том числе на ноутбуке.

```bash
# 1) стенд: 10 нод, node-01 «мертва» (504 по delay)
target/release/mock-clash --api 127.0.0.1:19555 --socks 127.0.0.1:19580 \
    --secret demo-secret --fail node-01-fr-vless > /tmp/mock.log 2>&1 &

# 2) конфиг: config.yaml из репозитория, поправить base_url/e2e_proxy на 19555/19580
#    и audit_path в /tmp, затем:
target/release/watchcat --config /tmp/wcdemo/config.yaml

# 3) смотрим
cat /tmp/wcdemo/routes.jsonl
grep MOCK_SWITCH /tmp/mock.log
```

Реальный вывод такого прогона (интервал 1 s, `fail_threshold: 2`):

```
{"event":"active_adopted","selector":"main-outbound","to":"node-01-fr-vless","reason":"initial_sync"}
{"event":"quarantine_enter","selector":"main-outbound","to":"node-01-fr-vless","reason":"failed","fails":2,"quarantine_ms":5000}
{"event":"route_switch","selector":"main-outbound","from":"node-01-fr-vless","to":"node-02-de-hysteria",
 "reason":"active_failed","latency_ms":25,"fails":2,"api_ok":true,"api_roundtrip_ms":0,"trigger":"probe"}
```

```
MOCK_SWITCH node-01-fr-vless -> node-02-de-hysteria (total 1)
```

Что это доказывает: два провала подряд → карантин → выбор лучшего кандидата
(25 ms) → `PUT` принят → трафик на `node-02`. Всё без перезапуска и без
участия sing-box. RSS демона на этом прогоне — 2.5–3.5 MiB, CPU ≈ 0.1 %.

Полезные флаги стенда:

| Флаг | Что делает |
|---|---|
| `--fail TAG` | нода не отвечает на delay (504) |
| `--fail-after N` | нода начинает падать после N успешных проб |
| `--slow TAG:MS` | нода отвечает, но медленно (деградация/гистерезис) |
| `--block TAG` | end-to-end проба получает 403, когда TAG активна (гео-блок) |
| `--secret S` | требовать `Authorization` |
| `--no-socks` | отключить SOCKS-стенд (пробы только через delay) |

Автотесты того же сценария (4 теста, живые бинари):

```bash
cargo test --test failover
```

## 6. Ручные операции

```bash
# посмотреть, что видит демон
watchcat --config /etc/watchcat/config.yaml --once --log-level debug

# принудительно переключить (в обход политики, через Clash API)
watchcat --config /etc/watchcat/config.yaml --set node-05-se-vless

# проверить решение, ничего не переключая
watchcat --config /etc/watchcat/config.yaml --dry-run --once

# остановить
systemctl stop watchcat
```

`--set` соответствует `PUT` из ТЗ и не требует остановки демона: следующий тик
увидит новое `now` и запишет `active_adopted` с `reason: external_change`.

## 7. Обновление

```bash
install -m 0755 watchcat-new /opt/watchcat/watchcat
systemctl restart watchcat
journalctl -u watchcat -n 5 --no-pager     # ждём "event":"start" и первый "tick"
```

Состояние (карантины, EWMA) при рестарте сбрасывается — это осознанно: после
перезапуска мы не знаем, что было с сетью, и начинаем с чистых измерений.
Максимум, что произойдёт, — одна лишняя проба-цикл до первого решения.

## 8. Диагностика

| Симптом | Что проверить |
|---|---|
| `clash_api_unavailable` | `systemctl status sing-box`; совпадает ли `secret`; `curl` из §1 |
| `selector_missing` (404) | тег в конфиге vs `type=selector` в config.json |
| `not a selector` в тексте ошибки | в конфиге всё ещё `urltest` |
| `configured_node_not_in_selector` | `selector.outbounds` не содержит тег из конфига |
| `route_switch_failed` (400) | `PUT` с тегом, которого нет в `all`; смотрим `--once --log-level debug` |
| `no_healthy_node` | все ноды в карантине: смотреть `watchcat_node_fails_total`, `last_seen`; проверить `all` |
| `intercept_probe_failed` | не нода: `journalctl -u sing-box`, `ip rule`, `ip route show table 100`, `sysctl net.ipv4.conf.awg0.rp_filter` (см. `env/dev/servers/ROUTING.md` §2.1) |
| пробы идут, но всегда `Inconclusive` | критический URL отдаёт 5xx; сменить `critical_url`/`accept_status` |
| демон ест CPU | проверить `probe.fast_interval_ms` и не залип ли он в fast-mode (`watchcat_node_quarantined`) |

Логи читаются глазами без парсера (`format: text`) или `jq` (`format: json`):

```bash
journalctl -u watchcat -f -o cat | jq -c 'select(.level!="debug")'
```

## 9. Справочник конфигурации

Полный список с комментариями — `config.example.yaml`. Ключевые ручки:

| Ключ | Дефолт | Зачем |
|---|---|---|
| `api.base_url` | `http://127.0.0.1:9090` | адрес Clash API |
| `api.secret` | — | секрет из `experimental.clash_api` (или `WATCHCAT_API_SECRET`) |
| `api.timeout_ms` | 1500 | таймаут запроса к API |
| `selector.tag` | `main-outbound` | управляемая группа |
| `selector.nodes` | `[]` | явный пул; пусто = из `all` API |
| `selector.adopt_external_changes` | true | принимать ручные переключения |
| `probe.interval_ms` | 5000 | обычный период |
| `probe.fast_interval_ms` | 1000 | период, пока активная нода больна |
| `probe.timeout_ms` | 2000 | таймаут пробы |
| `probe.concurrency` | 10 | параллельных проб |
| `probe.method` | `both` | `clash_delay` / `end_to_end` / `both` |
| `probe.base_url` | `https://1.1.1.1/cdn-cgi/trace` | базовая связность |
| `probe.critical_url` | `https://api.openai.com/v1/models` | проверка блокировок |
| `probe.critical_every_ticks` | 3 | как часто проверять критический URL |
| `probe.e2e_proxy` | `socks5://127.0.0.1:10808` | локальный инбаунд для e2e |
| `policy.fail_threshold` | 2 | провалов до карантина |
| `policy.quarantine_ms` | 300000 | длительность карантина |
| `policy.recovery_probes` | 2 | успехов для возврата в пул |
| `policy.switch_margin_pct` | 20 | гистерезис |
| `policy.min_switch_interval_ms` | 1500 | cooldown |
| `policy.degrade_ms` / `degrade_factor_pct` | 1200 / 250 | порог деградации |
| `logging.audit_path` | `/var/log/watchcat/routes.jsonl` | журнал изменений маршрутов |
| `logging.fsync_audit` | false | durability аудита |
| `metrics.path` | `/var/log/watchcat/metrics.prom` | textfile для node_exporter |
| `telegram.*` | disabled | уведомления (токен лучше через env) |

Правила приоритета: `env (WATCHCAT_*)` → `.env` (`WATCHCAT_ENV_FILE`, по
умолчанию `./.env`) → YAML → дефолты. YAML строгий: неизвестный ключ — ошибка
запуска (опечатка в `quarantine_ms` не должна молча оставить дефолт).
