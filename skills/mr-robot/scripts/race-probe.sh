#!/usr/bin/env bash
# mr-robot — bounded TOCTOU / race-condition prober.
#
# Sends one identical HTTP request N times concurrently and compares the
# responses. Divergent responses (different status or body) on an endpoint that
# performs a check-then-act (balance transfer, coupon apply, seat hold, invite
# consume) are the signature of a time-of-check/time-of-use race.
#
#   Usage:
#     race-probe.sh [-n COUNT] [-X METHOD] [-d DATA] [-H 'Header: v']... \
#                   [-t TIMEOUT] <url>
#
#   -n COUNT    concurrent requests (default 10, hard cap 20)
#   -X METHOD   HTTP method (default POST when -d given, else GET)
#   -d DATA     request body (sent with Content-Type: application/json)
#   -H HEADER   extra header, repeatable
#   -t TIMEOUT  per-request timeout seconds (default 10)
#
#   Exit: 0 uniform · 1 divergent (possible race — verify in source) ·
#         2 usage/refused · 3 transport errors dominated
#
# BOUNDS (Phase 0, non-negotiable): localhost ONLY (enforced below), max 1+21
# requests per run, no flood, no retry loops. The caller supplies the request —
# this script crafts no payloads. Use harmless marker requests; a race proof is
# a *divergence observation*, not a double-spend of real data.
set -u

COUNT=10; METHOD=""; DATA=""; TIMEOUT=10
EXTRA_HEADERS=()

usage_refuse() { echo "REFUSED: $1" >&2; echo "usage: race-probe.sh [-n COUNT] [-X METHOD] [-d DATA] [-H 'Hdr: v']... [-t SEC] <url>" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -n) COUNT="${2:-}"; shift 2 ;;
    -X) METHOD="${2:-}"; shift 2 ;;
    -d) DATA="${2:-}"; shift 2 ;;
    -H) EXTRA_HEADERS+=("${2:-}"); shift 2 ;;
    -t) TIMEOUT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    -*) usage_refuse "unknown flag $1" ;;
    *)  URL="$1"; shift ;;
  esac
done

[ -n "${URL:-}" ] || usage_refuse "missing <url>"
case "$COUNT" in ''|*[!0-9]*) usage_refuse "-n must be an integer" ;; esac
[ "$COUNT" -ge 2 ]  || usage_refuse "-n must be >= 2 (a race needs concurrency)"
[ "$COUNT" -le 20 ] || usage_refuse "-n capped at 20 (Phase 0 rate bound)"
[ -n "$DATA" ] && [ -z "$METHOD" ] && METHOD="POST"
METHOD="${METHOD:-GET}"

# ---- authorization guard: this tool only ever talks to loopback ----------------
host="$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://([^:/]+).*#\1#')"
case "$host" in
  localhost|127.0.0.1|::1|0.0.0.0) ;;
  *) usage_refuse "targets must be localhost (got host '$host')" ;;
esac

command -v curl >/dev/null 2>&1 || { echo "curl required" >&2; exit 2; }

WORK="$(mktemp -d /tmp/mr-robot-race-XXXXXX)" || exit 2
# shellcheck disable=SC2329  # invoked via trap, not by name
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

CURL_ARGS=(-s -o /dev/null -w '%{http_code} %{size_download}' --max-time "$TIMEOUT" -X "$METHOD" "${EXTRA_HEADERS[@]+"${EXTRA_HEADERS[@]}"}")
[ -n "$DATA" ] && CURL_ARGS+=(-H 'Content-Type: application/json' --data-raw "$DATA")

echo "[race] $COUNT x $METHOD $URL  (baseline serial + $COUNT concurrent, cap 21 requests)"

# ---- baseline: one serial request ---------------------------------------------
curl "${CURL_ARGS[@]}" "$URL" > "$WORK/base.meta" 2>/dev/null
base_status=$(awk '{print $1}' "$WORK/base.meta")
base_len=$(awk '{print $2}' "$WORK/base.meta")
echo "[race] baseline: status=$base_status len=$base_len"

# ---- the race: N identical requests, all in flight together -------------------
pids=""
i=1
while [ "$i" -le "$COUNT" ]; do
  curl "${CURL_ARGS[@]}" "$URL" > "$WORK/r$i.meta" 2>/dev/null &
  pids="$pids $!"
  i=$((i + 1))
done
for p in $pids; do wait "$p" 2>/dev/null; done

# ---- compare ------------------------------------------------------------------
echo "[race] responses:"
i=1; transport_errs=0
while [ "$i" -le "$COUNT" ]; do
  st=$(awk '{print $1}' "$WORK/r$i.meta" 2>/dev/null)
  ln=$(awk '{print $2}' "$WORK/r$i.meta" 2>/dev/null)
  if [ -z "$st" ] || [ "$st" = "000" ]; then
    transport_errs=$((transport_errs + 1))
    echo "  #$i  transport-error (timeout/refused)"
  else
    echo "  #$i  status=$st len=$ln"
  fi
  i=$((i + 1))
done

distinct_status=$(i=1; while [ "$i" -le "$COUNT" ]; do awk '{print $1}' "$WORK/r$i.meta" 2>/dev/null; i=$((i+1)); done | sort -u | grep -c .)
echo "[race] distinct status codes across responses: $distinct_status"

if [ "$transport_errs" -gt $((COUNT / 2)) ]; then
  echo "[race] VERDICT: transport-dominated — target likely rate-limited or slow; not a race signal."
  exit 3
fi

if [ "$distinct_status" -gt 1 ]; then
  echo "[race] VERDICT: DIVERGENT status codes — possible TOCTOU/race. Verify the check-then-act path in source:"
  echo "       find where the check (read state) and the act (write state) are separated without a lock/transaction,"
  echo "       then re-probe with the endpoint's real precondition (e.g. balance exactly 1 unit) to observe double-apply."
  exit 1
fi

echo "[race] VERDICT: uniform responses — no divergence observed at $COUNT concurrency."
echo "       (Races can need higher concurrency or specific preconditions; a uniform result is NOT proof of safety —"
echo "       if static analysis shows an unlocked check-then-act, record it as a candidate and reason about the window.)"
exit 0
