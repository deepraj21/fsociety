#!/usr/bin/env bash
# mr-robot — bounded HTTP request smuggling / desync prober (references/03i).
#
# Probes CL.TE / TE.CL / CL.0 framing disagreement with harmless marker GETs and
# watches for RESPONSES WE DID NOT ASK FOR. Detection is count-based and
# calibrated against the target's own pipeline behavior:
#
#   b1  benign single request          → transport sanity
#   b2  benign + benign pipelined      → normal responses to a 2-request burst
#                                        (1 = close-after-first server,
#                                         2 = keep-alive server) + the expected
#                                        response-status sequence
#   each family probe: attack + benign → flagged if EITHER
#                                          more responses than b2, OR
#                                          the status sequence is not uniform
#                                          while the baseline's was (both
#                                          requests hit the same path, so a
#                                          clean server answers them with the
#                                          same status — a mixed sequence means
#                                          responses shifted = desync)
#
#   Usage:
#     desync-probe.sh [-t TIMEOUT] [-H 'Header: v']... <url>
#
#   -t TIMEOUT  nc idle timeout seconds (default 3, hard cap 10)
#   -H HEADER   extra header on every request, repeatable (e.g. a session cookie)
#
#   Exit: 0 uniform · 1 possible desync (verify proxy topology per 03i §Verify)
#         2 usage/refused · 3 transport errors dominated
#
# BOUNDS (Phase 0, non-negotiable): localhost ONLY (enforced below), cleartext
# http:// only, 13 requests total (3 baseline + 5 families x 2), GET bodies
# only — no state-changing method ever. The smuggle payload is a marker GET
# (/mr-robot-desync-marker): if a desync fires, grep the target's access log
# for it — attribution without touching data.
#
# Topology note (03i): a single parser cannot desync itself — a POSITIVE here
# means two parsers disagreed somewhere; confirm a proxy/CDN is in the path
# before reporting. Direct-only servers reporting uniform (exit 0) is the
# expected, correct outcome.
set -u

TIMEOUT=3
EXTRA_HEADERS=()

usage_refuse() { echo "REFUSED: $1" >&2; echo "usage: desync-probe.sh [-t TIMEOUT] [-H 'Hdr: v']... <url>" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -t) TIMEOUT="${2:-}"; shift 2 ;;
    -H) EXTRA_HEADERS+=("${2:-}"); shift 2 ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    -*) usage_refuse "unknown flag $1" ;;
    *)  URL="$1"; shift ;;
  esac
done

[ -n "${URL:-}" ] || usage_refuse "missing <url>"
case "$TIMEOUT" in ''|*[!0-9]*) usage_refuse "-t must be an integer" ;; esac
[ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 10 ] || usage_refuse "-t capped at 10s (Phase 0 bound)"

case "$URL" in
  http://*) ;;
  https://*) usage_refuse "cleartext HTTP/1.1 framing only — TLS wraps the stream, so point this at a plain-http listener (for HTTPS interception see references/03l)" ;;
  *://*) usage_refuse "unsupported scheme in '$URL' (http only)" ;;
  *) usage_refuse "missing http:// scheme in '$URL'" ;;
esac

# ---- authorization guard: this tool only ever talks to loopback ----------------
rest="${URL#http://}"
nhost="$(printf '%s' "$rest" | sed -E 's#[/:].*##')"
case "$nhost" in
  localhost|127.0.0.1|::1|0.0.0.0) ;;
  *) usage_refuse "targets must be localhost (got host '$nhost')" ;;
esac
case "$rest" in
  *:*) nport="${rest#*:}"; nport="${nport%%/*}" ;;
  *)   nport=80 ;;
esac
PATH_U="/"
case "$rest" in */*) PATH_U="/${rest#*/}" ;; esac

command -v nc >/dev/null 2>&1 || { echo "nc (netcat) required" >&2; exit 2; }

WORK="$(mktemp -d /tmp/mr-robot-desync-XXXXXX)" || exit 2
# shellcheck disable=SC2329  # invoked via trap, not by name
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

HOST_HDR="$nhost${nport:+}:$nport"; [ "$nport" = 80 ] && HOST_HDR="$nhost"
[ -n "${EXTRA_HEADERS[*]:-}" ] && for h in "${EXTRA_HEADERS[@]}"; do printf '%s\r\n' "$h" >> "$WORK/extra.hdr"; done

# ---- request builders (files — no $() trailing-newline corruption) -------------
benign() { # $1 = outfile, $2 = connection
  {
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: %s\r\n' "$PATH_U" "$HOST_HDR" "$2"
    [ -f "$WORK/extra.hdr" ] && cat "$WORK/extra.hdr"
    printf '\r\n'
  } > "$1"
}

# smuggle body: chunked terminator + a full marker GET (harmless, GET-only)
printf '0\r\n\r\nGET /mr-robot-desync-marker HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n' \
  "$HOST_HDR" > "$WORK/smuggle.body"

# CL.0 body: a marker request as a RAW body (no chunk framing) — sent with
# Content-Length and no Transfer-Encoding; a hop that ignores the CL body on a
# GET would start parsing these bytes as its next request (03i §CL.0)
printf 'GET /mr-robot-desync-marker HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n' \
  "$HOST_HDR" > "$WORK/cl0.body"

attack() { # $1 = outfile, $2 = TE header block (may be empty), $3 = body file (default smuggle)
  _body="${3:-$WORK/smuggle.body}"
  {
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n' "$PATH_U" "$HOST_HDR"
    [ -f "$WORK/extra.hdr" ] && cat "$WORK/extra.hdr"
    [ -n "$2" ] && printf '%s\r\n' "$2"
    printf 'Content-Length: %s\r\n\r\n' "$(wc -c < "$_body" | tr -d '[:space:]')"
    cat "$_body"
  } > "$1"
}

send() { # $1 = payload file, $2 = outfile
  nc -w "$TIMEOUT" "$nhost" "$nport" < "$1" > "$2" 2>/dev/null
}

nresp() { grep -aoE 'HTTP/1\.[01] [0-9]{3}' "$1" 2>/dev/null | wc -l | tr -d '[:space:]'; }
statuses() { grep -aoE 'HTTP/1\.[01] [0-9]{3}' "$1" 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//'; }

echo "[desync] $nhost:$nport$PATH_U  (13 requests: 3 baseline + 5 families x 2, GET marker bodies only)"

# ---- b1: transport sanity -------------------------------------------------------
benign "$WORK/b1.req" close
send "$WORK/b1.req" "$WORK/b1.out"
b1="$(nresp "$WORK/b1.out")"
B1STATUS="$(statuses "$WORK/b1.out")"
echo "[desync] baseline single: $b1 response(s), status $B1STATUS"
if [ "$b1" -lt 1 ]; then
  echo "[desync] VERDICT: transport failure — no response from target (refused/timeout/ TLS?)."
  exit 3
fi

# ---- b2: normal response count for a pipelined benign pair ----------------------
{ cat "$WORK/b1.req"; benign "$WORK/b1b.req" close; cat "$WORK/b1b.req"; } > "$WORK/b2.req"
send "$WORK/b2.req" "$WORK/b2.out"
PAIR="$(nresp "$WORK/b2.out")"
B2STATUSES="$(statuses "$WORK/b2.out")"
echo "[desync] baseline pair: $PAIR response(s), statuses $B2STATUSES (pipeline behavior)"
# baseline trusted only if every benign response carried the benign status —
# otherwise (flaky endpoint) the shifted-response check below is skipped
b2_trusted=1
for _s in $(printf '%s' "$B2STATUSES" | tr ',' ' '); do
  [ "$_s" = "$B1STATUS" ] || b2_trusted=0
done

# ---- families: TE+CL disagreement variants + CL.0 (03i; CL always present) -----
# NOTE: $'...' quoting — command substitution strips a trailing \n, which would
# leave a dangling \r and merge the TE header into the next header line.
V1=$'Transfer-Encoding: chunked'
V2=$'Transfer-Encoding:\tchunked'
V3=$'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity'
V4=$'Transfer-Encoding: xchunked'
i=1
: > "$WORK/flags"
transport_errs=0
while [ "$i" -le 5 ]; do
  te_body="$WORK/smuggle.body"
  case "$i" in
    1) te="$V1"; name="TE chunked (CL.TE/TE.CL)" ;;
    2) te="$V2"; name="TE hidden (leading tab)" ;;
    3) te="$V3"; name="TE doubled (chunked+identity)" ;;
    4) te="$V4"; name="TE x-prefix (xchunked)" ;;
    5) te=""; te_body="$WORK/cl0.body"; name="CL.0 (raw body, no TE)" ;;
  esac
  attack "$WORK/p$i.req" "$te" "$te_body"
  { cat "$WORK/p$i.req"; benign "$WORK/p$i.benign" close; cat "$WORK/p$i.benign"; } > "$WORK/p$i.combined"
  send "$WORK/p$i.combined" "$WORK/p$i.out"
  n="$(nresp "$WORK/p$i.out")"
  st="$(statuses "$WORK/p$i.out")"
  if [ "$n" -eq 0 ]; then
    transport_errs=$((transport_errs + 1))
    echo "  [$i] $name — transport-error (no response)"
  elif [ "$n" -gt "$PAIR" ]; then
    echo "  [$i] $name — EXTRA response(s): got $n ($st), baseline $PAIR ($B2STATUSES)  ← desync signature"
    echo "$name (extra responses: got $n/$st vs baseline $PAIR/$B2STATUSES)" >> "$WORK/flags"
  elif [ "$n" -eq "$PAIR" ] && [ "$PAIR" -ge 2 ] && [ "$b2_trusted" = 1 ] && [ "$st" != "$B2STATUSES" ]; then
    # same count, wrong sequence: the benign follow-up got the MARKER's answer
    # in its slot — the classic shifted-response desync signature
    echo "  [$i] $name — SHIFTED responses: got $st, baseline $B2STATUSES  ← desync signature"
    echo "$name (shifted responses: got $st vs baseline $B2STATUSES)" >> "$WORK/flags"
  else
    echo "  [$i] $name — uniform ($st vs baseline $B2STATUSES)"
  fi
  i=$((i + 1))
done

flagged="$(grep -c . "$WORK/flags" 2>/dev/null)"
[ -n "$flagged" ] || flagged=0

if [ "$transport_errs" -gt 2 ]; then
  echo "[desync] VERDICT: transport-dominated — target unreachable/flaky mid-run; not a framing signal."
  exit 3
fi

if [ "$flagged" -gt 0 ]; then
  echo "[desync] VERDICT: UNSOLICITED RESPONSES — possible request smuggling/desync:"
  sed 's/^/         - /' "$WORK/flags"
  echo "         Verify per references/03i §Verify BEFORE reporting:"
  echo "         1) is a proxy/CDN/reverse-proxy in the path? (a single parser cannot desync itself)"
  echo "         2) check the target's access log for GET /mr-robot-desync-marker arriving as its own request"
  echo "         3) re-run — a repeatable cross-over is a candidate; keep it status=candidate until confirmed"
  exit 1
fi

echo "[desync] VERDICT: uniform — responses match this server's own pipeline behavior at all 5 families."
echo "         Direct-only topology (no proxy in path) is expected to land here (03i §Verify)."
echo "         A uniform result is NOT proof of safety: if the repo shows a proxy with request"
echo "         rewriting (nginx/traefik/envoy/CDN), retry with the proxy in front and re-check."
exit 0
