#!/usr/bin/env bash
# mr-robot — localhost daemon Origin/auth sweep (references/08-local-daemons.md).
#
#   Usage:
#     daemon-sweep.sh [-t TIMEOUT] [-p PORTS] [--ws-path <path>] [--out <file.json>]
#
#   -t TIMEOUT    per-request seconds (default 2, hard cap 5)
#   -p PORTS      comma list/ranges of LOCAL ports instead of enumerating
#                 (digits only, e.g. 9222,8765-8775 — never a hostname)
#   --ws-path P   path for the WebSocket upgrade test (default /)
#   --out FILE    write JSON report (schema mr-robot-daemon-sweep-v1)
#
# WHAT IT TESTS — the hijack conditions between any web page and a local tool:
#   1. WebSocket upgrade accepted with a FORGED foreign Origin → 101 = the
#      browser's same-origin wall is the only thing between an attacker page
#      and the daemon's full duplex API (MCP bridges, sockjs, Jupyter, wds).
#   2. CORS reflecting the foreign Origin (± credentials) — or ACAO: * —
#      = any page can READ the daemon's responses cross-origin.
#   3. Chrome DevTools-style target list on GET / → code-exec surface noted;
#      its WS path is probed too (modern Chrome origin-gates it — we check).
#
# The handshake/reflection IS the evidence — no exploit, no frames, no payload
# is ever sent to any daemon.
#
# Bounds (Phase 0, non-negotiable): loopback ONLY — the connect host is
# hardcoded 127.0.0.1/[::1] and -p accepts digits/ranges only, so a hostname
# cannot enter; direct connection (--noproxy '*', no -L: redirects are never
# followed); ≤40 ports; ≤3 requests per port; 2s default timeout; WS probe is
# handshake-only (upgrade headers, zero frames, connection dropped at once).
#
# Exit: 0 no foreign-origin acceptance · 1 hijackable daemon found (candidate —
#       check whether the daemon's config intends open browser access before
#       reporting) · 2 usage · 3 nothing enumerable (no lsof/ss or no listeners)
set -u

TIMEOUT=2
PORTS=""
WS_PATH="/"
OUT=""

usage_refuse() { echo "REFUSED: $1" >&2; echo "usage: daemon-sweep.sh [-t TIMEOUT] [-p PORTS] [--ws-path <path>] [--out <file.json>]" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -t) TIMEOUT="${2:-}"; shift 2 ;;
    -p) PORTS="${2:-}"; shift 2 ;;
    --ws-path) WS_PATH="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
    -*) usage_refuse "unknown flag $1" ;;
    *)  usage_refuse "unexpected argument '$1' — this tool targets loopback only, it takes no host" ;;
  esac
done
case "$TIMEOUT" in ''|*[!0-9]*) usage_refuse "-t must be an integer" ;; esac
[ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 5 ] || usage_refuse "-t capped at 5s (Phase 0 bound)"
case "$WS_PATH" in /*) ;; *) usage_refuse "--ws-path must start with /" ;; esac
# -p accepts only digits, commas and dashes (ranges) — a host cannot pass this
case "$PORTS" in
  "") ;;
  *[!0-9,-]*) usage_refuse "-p accepts only ports/ranges (e.g. 9222,8765-8775)" ;;
esac
if [ -n "$OUT" ]; then
  command -v python3 >/dev/null 2>&1 || usage_refuse "--out needs python3"
fi
command -v curl >/dev/null 2>&1 || { echo "curl required" >&2; exit 2; }

WORK="$(mktemp -d /tmp/mr-robot-daemon-XXXXXX)" || exit 2
# shellcheck disable=SC2329  # invoked via trap, not by name
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# ------------------------------------------------------------ enumeration
# listeners file: "bindhost|port|cmd" — remote addresses are collected too,
# but the probe always CONNECTS via loopback (see connect_host below).
if [ -n "$PORTS" ]; then
  printf '%s\n' "$PORTS" | tr ',' '\n' | while IFS= read -r spec; do
    [ -n "$spec" ] || continue
    case "$spec" in
      *-*) a="${spec%-*}"; b="${spec#*-}"
           [ "$b" -gt 65535 ] && b=65535
           [ $((b - a)) -gt 999 ] && b=$((a + 999))
           i="$a"
           while [ "$i" -le "$b" ]; do printf '127.0.0.1|%s|(forced)\n' "$i"; i=$((i + 1)); done ;;
      *)   printf '127.0.0.1|%s|(forced)\n' "$spec" ;;
    esac
  done | sort -t'|' -k2,2n | awk -F'|' '!seen[$2]++' | head -40 > "$WORK/listeners"
elif command -v lsof >/dev/null 2>&1; then
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '$NF=="(LISTEN)"{print $(NF-1)"|"$1}' > "$WORK/lsof.raw"
  while IFS='|' read -r addr cmd; do
    case "$addr" in *:*) ;; *) continue ;; esac
    p="${addr##*:}"; h="${addr%:*}"
    case "$p" in ''|*[!0-9]*) continue ;; esac
    printf '%s|%s|%s\n' "$h" "$p" "$cmd"
  done < "$WORK/lsof.raw" | sort -t'|' -k2,2n | awk -F'|' '!seen[$2]++' | head -40 > "$WORK/listeners"
elif command -v ss >/dev/null 2>&1; then
  ss -ltnH 2>/dev/null | awk '{print $4}' | sort -u | while IFS= read -r addr; do
    case "$addr" in *:*) ;; *) continue ;; esac
    p="${addr##*:}"; h="${addr%:*}"
    case "$p" in ''|*[!0-9]*) continue ;; esac
    printf '%s|%s|?\n' "$h" "$p"
  done | sort -t'|' -k2,2n | awk -F'|' '!seen[$2]++' | head -40 > "$WORK/listeners"
else
  echo "REFUSED: neither lsof nor ss available — cannot enumerate local listeners" >&2
  exit 3
fi

N="$(wc -l < "$WORK/listeners" | tr -d '[:space:]')"
if [ "$N" -eq 0 ]; then
  echo "[daemon-sweep] no TCP listeners found on loopback — nothing to sweep."
  exit 3
fi

# loopback connect host for a bind address (wildcards → IPv4 loopback)
connect_host() {
  case "$1" in
    ::1|'[::1]') printf '[::1]' ;;
    localhost) printf '127.0.0.1' ;;
    *) printf '127.0.0.1' ;;
  esac
}

ORIGIN="http://mr-robot-evil.example"
WSKEY="dGhlIHNhbXBsZSBub25jZQ=="   # RFC 6455 sample key (handshake only)

echo "[daemon-sweep] $N loopback listener(s) · ≤3 requests/port · t=${TIMEOUT}s · forged Origin '$ORIGIN'"
: > "$WORK/findings.tsv"
hijack=0
probed=0
unreachable=0
devtools_seen=0

while IFS='|' read -r bh bp cmd; do
  [ -n "$bp" ] || continue
  chost="$(connect_host "$bh")"
  base="http://${chost}:${bp}"
  probed=$((probed + 1))

  # ---- request 1: GET / with the forged Origin (fingerprint + CORS verdict)
  acro="" ; acac="" ; devtools=0
  curl -sS -m "$TIMEOUT" --noproxy '*' -D "$WORK/h1" -o "$WORK/b1" \
       -H "Origin: $ORIGIN" "$base/" 2>/dev/null
  rc1=$?
  if [ "$rc1" -eq 7 ] || [ "$rc1" -eq 28 ] || [ "$rc1" -eq 6 ]; then
    unreachable=$((unreachable + 1))
    continue   # bind not reachable via loopback (LAN-only bind) / no reply
  fi
  acro="$(grep -i '^access-control-allow-origin:' "$WORK/h1" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | head -c 80)"
  acac="$(grep -i '^access-control-allow-credentials:' "$WORK/h1" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | head -c 20)"
  head -c 2048 "$WORK/b1" > "$WORK/b1s" 2>/dev/null || : > "$WORK/b1s"
  if grep -q 'webSocketDebuggerUrl' "$WORK/b1s" 2>/dev/null; then
    devtools=1; devtools_seen=$((devtools_seen + 1))
  fi

  # ---- request 2: WebSocket upgrade with the forged Origin
  curl -sS -m "$TIMEOUT" --noproxy '*' --http1.1 -o /dev/null -D "$WORK/h2" \
       -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
       -H "Sec-WebSocket-Key: $WSKEY" -H 'Sec-WebSocket-Version: 13' \
       -H "Origin: $ORIGIN" "$base${WS_PATH}" 2>/dev/null
  ws="$(head -1 "$WORK/h2" 2>/dev/null | grep -aoE '[0-9]{3}' | head -1)"
  [ -n "${ws:-}" ] || ws="-"

  # ---- request 3 (conditional): same upgrade on the DevTools target path
  ws2=""
  if [ "$devtools" = 1 ]; then
    dpath="$(grep -ao '"/devtools/[a-z]*/[^"]*"' "$WORK/b1s" 2>/dev/null | head -1 | tr -d '"')"
    if [ -n "$dpath" ]; then
      curl -sS -m "$TIMEOUT" --noproxy '*' --http1.1 -o /dev/null -D "$WORK/h3" \
           -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
           -H "Sec-WebSocket-Key: $WSKEY" -H 'Sec-WebSocket-Version: 13' \
           -H "Origin: $ORIGIN" "${base}${dpath}" 2>/dev/null
      ws2="$(head -1 "$WORK/h3" 2>/dev/null | grep -aoE '[0-9]{3}' | head -1)"
      [ -n "${ws2:-}" ] || ws2="-"
    fi
  fi

  # ---- verdict per daemon
  pfind=""
  case "$ws" in
    101) pfind="ws-open-origin"; hijack=1 ;;
  esac
  case "$ws2" in
    101) pfind="ws-open-origin(devtools)"; hijack=1 ;;
  esac
  if [ "$pfind" = "" ]; then
    if [ -n "$acro" ] && { [ "$acro" = "$ORIGIN" ] || [ "$acro" = "*" ]; }; then
      if [ "$acro" = "$ORIGIN" ]; then pfind="cors-origin-reflected"; else pfind="cors-origin-star"; fi
      hijack=1
    fi
  fi
  fflag=""; [ -n "$pfind" ] && fflag="  ← $pfind"
  printf '  :%s  %-10s ws=%s%s cors=%s%s devtools=%s%s\n' \
    "$bp" "${cmd:0:10}" "$ws" "$([ "$ws2" = 101 ] && echo '/devtools-101')" \
    "${acro:-no}" "$([ -n "$acac" ] && echo "+creds:$acac")" \
    "$devtools" "$fflag"
  if [ -n "$pfind" ]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$bp" "$cmd" "$pfind" "$ws" "${acro:-no}" >> "$WORK/findings.tsv"
  fi
done < "$WORK/listeners"

# ------------------------------------------------------------------ report
if [ "$hijack" -eq 1 ]; then
  echo "[daemon-sweep] VERDICT: HIJACKABLE — local daemon(s) accept requests from a FOREIGN origin:"
  while IFS=$'\t' read -r bp cmd f ws _; do
    case "$f" in
      ws-open-origin*)
        echo "         - :$bp  WebSocket upgrade accepted (status $ws) for '$ORIGIN' — any page gets the duplex API" ;;
      cors-origin-reflected)
        echo "         - :$bp  ACAO reflects '$ORIGIN' — cross-origin READ of this daemon's responses" ;;
      cors-origin-star)
        echo "         - :$bp  ACAO: * — any page reads (and simple-POSTs to) this daemon" ;;
    esac
  done < "$WORK/findings.tsv"
  echo "         CANDIDATE — confirm the daemon does not intentionally document open"
  echo "         browser access, then report per references/08 (fix = Origin allowlist"
  echo "         + auth token; never expose a tool's port beyond loopback)."
  [ -n "$OUT" ] && python3 - "$WORK/findings.tsv" "$OUT" "$N" "$probed" "$TIMEOUT" <<'PYEOF'
import json, sys
tsv, out, n, probed, t = sys.argv[1:6]
rows = []
for line in open(tsv):
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 5:
        rows.append({"port": int(parts[0]), "process": parts[1], "finding": parts[2],
                     "ws_status": parts[3], "acao": parts[4]})
json.dump({"schema": "mr-robot-daemon-sweep-v1",
           "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
           "bounds": {"connect": "loopback-only", "ports": int(n), "probed": int(probed),
                      "max_req_per_port": 3, "timeout_s": int(t), "origin": "http://mr-robot-evil.example"},
           "findings": rows}, open(out, "w"), indent=1)
PYEOF
  exit 1
fi

echo "[daemon-sweep] VERDICT: clean — $probed listener(s) probed ($unreachable unreachable), no foreign-Origin acceptance."
echo "               No WS 101, no reflected/'*' CORS. DevTools-style surfaces seen: $devtools_seen (attach itself is"
echo "               process-local + origin-gated on modern Chrome — note it, do not call it safe outright)."
[ -n "$OUT" ] && python3 - "$OUT" "$N" "$probed" "$TIMEOUT" <<'PYEOF'
import json, sys
out, n, probed, t = sys.argv[1:5]
json.dump({"schema": "mr-robot-daemon-sweep-v1",
           "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
           "bounds": {"connect": "loopback-only", "ports": int(n), "probed": int(probed),
                      "max_req_per_port": 3, "timeout_s": int(t), "origin": "http://mr-robot-evil.example"},
           "findings": []}, open(out, "w"), indent=1)
PYEOF
exit 0
