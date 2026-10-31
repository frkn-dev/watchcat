#!/usr/bin/env bash
# Локальный смоук: 2 группы, одна ломается, вторая стоит.
set -u
cd "$(dirname "$0")/.."
DIR=$(mktemp -d /tmp/wc-multi.XXXXXX)
MOCK=./target/release/mock-clash
WC=./target/release/watchcat

$MOCK --api 127.0.0.1:19190 --socks 127.0.0.1:19180 \
      --selectors fr-exit,bt-exit \
      --fail node-01-fr-vless \
      --pool bt-exit=node-05-fr-vless,node-06-fr-vless \
      > "$DIR/mock.log" 2>&1 &
MOCK_PID=$!
sleep 1

cat > "$DIR/config.yaml" <<EOF
api:
  base_url: "http://127.0.0.1:19190"
  secret: ""
  connect_timeout_ms: 300
  timeout_ms: 1000
selectors:
  - tag: fr-exit
  - tag: bt-exit
probe:
  interval_ms: 300
  fast_interval_ms: 200
  timeout_ms: 400
  concurrency: 10
  method: clash_delay
  base_url: "http://1.1.1.1/cdn-cgi/trace"
  critical_url: ""
  critical_every_ticks: 0
  e2e_enabled: false
policy:
  fail_threshold: 2
  quarantine_ms: 1500
  min_switch_interval_ms: 0
  recovery_probes: 1
  stale_ms: 5000
logging:
  level: info
  format: json
  stdout: true
  audit_path: "$DIR/routes.jsonl"
metrics:
  enabled: true
  path: "$DIR/metrics.prom"
telegram:
  enabled: false
EOF

echo "=== --check"
$WC --config "$DIR/config.yaml" --check
echo
echo "=== --nodes"
$WC --config "$DIR/config.yaml" --nodes
echo
echo "=== боевой прогон 6 с"
$WC --config "$DIR/config.yaml" > "$DIR/wc.log" 2>&1 &
WC_PID=$!
sleep 6
kill $WC_PID 2>/dev/null
wait $WC_PID 2>/dev/null
kill $MOCK_PID 2>/dev/null
wait $MOCK_PID 2>/dev/null

echo
echo "=== переключения в моке:"
grep MOCK_SWITCH "$DIR/mock.log" || echo "  (нет)"
echo
echo "=== audit по группам:"
python3 - "$DIR/routes.jsonl" <<'PY'
import json, sys, collections
c = collections.Counter()
try:
    for line in open(sys.argv[1]):
        r = json.loads(line)
        c[(r.get("selector"), r.get("event"))] += 1
except FileNotFoundError:
    print("  файла нет")
for (sel, ev), n in sorted(c.items()):
    print(f"  {sel:10} {ev:18} {n}")
PY
echo
echo "=== метрики:"
grep -E "watchcat_group_(enabled|switches_total|active)|^watchcat_switches_total|^watchcat_groups" "$DIR/metrics.prom" 2>/dev/null || echo "  нет файла"
echo
echo "=== хвост лога watchcat:"
tail -3 "$DIR/wc.log"
echo
echo "директория: $DIR"
