# watchcat

Watchdog для выходных нод sing-box: следит за здоровьем пула и переключает
`selector` через Clash API за миллисекунды, без перезапуска ядра.

```
клиенты → AWG/WG → sing-box (route.rules) → selector main-outbound → нода
                                                    ↑
                                          watchcat (PUT /proxies/main-outbound)
```

## Что делает

* каждые N секунд (по умолчанию 5 s) меряет задержку **всех** нод пула через
  `GET /proxies/{tag}/delay` (sing-box сам дозванивается — лишних сокетов нет);
* различает «нода умерла» и «нода жива, но заблокирована для сервиса»: второй
  сигнал — 403/406/451 на критическом эндпоинте (`api.openai.com/v1/models`);
* подтверждает активную ноду end-to-end пробой через локальный SOCKS-инбаунд —
  это ловит поломку перехвата, которую не видно по Clash API;
* после `fail_threshold` провалов подряд отправляет ноду в карантин на 5 минут
  и переключает трафик на лучшего живого кандидата (гистерезис 20 %, cooldown
  1.5 s против флаппинга);
* пишет **отдельный audit-журнал** всех изменений маршрутизации (JSONL) и
  метрики Prometheus textfile;
* ничего не перезапускает и не трогает iptables — только `PUT /proxies/…`.

## Быстрый старт

```bash
cargo build --release
./target/release/watchcat --config config.example.yaml --check   # проверить конфиг
./target/release/watchcat --config config.example.yaml           # запустить
```

Требования к sing-box (Clash API + `selector`) — `docs/OPERATIONS.md` §1,
готовый пример — `docs/sing-box.example.json`.

## Стенд без sing-box

`mock-clash` — фейковый Clash API + SOCKS5, чтобы увидеть весь цикл за 10 секунд:

```bash
./target/release/mock-clash --api 127.0.0.1:19555 --socks 127.0.0.1:19580 \
    --secret demo-secret --fail node-01-fr-vless
./target/release/watchcat --config /tmp/wcdemo/config.yaml
cat /tmp/wcdemo/routes.jsonl
```

Реальный вывод и пошаговая инструкция — `docs/OPERATIONS.md` §5.

## Тесты

```bash
cargo test              # 95 unit + 5 e2e (живые бинари, реальные сокеты)
cargo test --test failover
cargo test --lib -- --ignored          # opt-in: настоящий TLS-handshake к 1.1.1.1
```

Покрыто: парсеры (nom, включая битые ответы), HTTP/SOCKS/TLS клиенты, машина
состояний (карантин, восстановление, гистерезис, cooldown, гео-блоки, «все
мертвы»), конфиг, аудит, метрики, полный цикл failover и dry-run.

## Характеристики

| Метрика | Значение |
|---|---|
| бинарь (release, LTO, strip) | 1.7 MB |
| RSS, 10 нод, 1 s интервал, обе пробы | 2.5–3.5 MiB |
| CPU | ≈ 0.1 % ядра |
| тик (10 delay + 1 e2e) | 2 ms |
| переключение (`PUT` по loopback) | < 1 ms |
| время реакции (дефолт 5 s / 2 провала) | 1–6 s |

Зависимости: `tokio`, `nom`, `serde`, `serde_json`, `serde_yaml`, `rustls`,
`tokio-rustls`, `webpki-roots`. Ни regexp, ни hyper/reqwest.

## Документация

| Документ | Для кого |
|---|---|
| `REPORT.md` / `REPORT.pdf` | отчёт о выполнении ТЗ для заказчика (12 стр., сборка: `./report/build.sh`) |
| `README.md` | краткий обзор и запуск за 3 команды |
| `docs/ARCHITECTURE.md` | устройство, один тик, модель состояния, перф-решения, границы |
| `docs/DETECTION.md` | **паттерны детекта** деградации/блокировок, пороги, ложные срабатывания |
| `docs/ROUTING-AUDIT.md` | схема журнала изменений маршрутов, гарантии, `jq`-рецепты, SLO |
| `docs/OPERATIONS.md` | sing-box, миграция с `urltest`, установка, проверки, диагностика, справочник конфига |
| `config.example.yaml` | все ключи с комментариями |
| `HUMANS.md` | статус работы |

## Структура

```
src/supervisor.rs   цикл reconcile → probe → decide → apply
src/state.rs        чистая машина состояний (без I/O) + выбор кандидата
src/health.rs       пробы и классификация исходов
src/clash.rs        Clash API клиент
src/net/            свой HTTP/1.1, SOCKS5, TLS
src/parse.rs        все парсеры на nom
src/log.rs          JSON-лог + audit-журнал
src/config.rs       YAML + .env + env
src/metrics.rs      Prometheus textfile
src/notify.rs       Telegram
src/bin/mock_clash.rs  стенд для тестов и демо
deploy/             systemd unit, logrotate
```

## Ограничения

Не поднимает sing-box, не правит iptables/TPROXY, не добавляет ноды в конфиг,
не балансирует клиентов между нодами и не заменяет rollback-guard перехвата
(`eu-watchdog.sh`) — он про другой отказ. Подробно: `docs/ARCHITECTURE.md` §9.

## Лицензия

GPL-3.0-only, см. [LICENSE](LICENSE). © 2026 FRKN.
