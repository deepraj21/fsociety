#!/usr/bin/env bash
# mr-robot — end-to-end selftest: proves the installed skill actually works.
#
#   Usage:
#     selftest.sh            full run (~3-4 min: includes live DAST + nuclei)
#     selftest.sh --quick    skip the live-scan gate (~90s)
#
# Runs against a TEMP COPY of the bundled fixture (never touches the repo's
# fixture dir or any .mr-robot artifacts you have), requires python3/node/nc,
# and refuses to start if port 8766 is already taken (stop a running fixture
# first). All gates run even after a failure — you get the full picture — and
# cleanup runs on every exit path (trap).
#
#   Exit: 0 all gates pass · 1 one or more gates failed · 2 environment refusal
#
# Gates:
#   1 syntax        bash -n · node --check · fixture py_compile
#   2 packaging     SKILL.md frontmatter (name, description <=1024) · file map
#   3 fixture       boots on 127.0.0.1:8766 from the temp copy
#   4 lanes         live proofs: SQLi · XSS · SSRF · IDOR · transfer(negative)
#   5 probers       desync-probe exit 0 (direct topology) · race-probe 0|1 · daemon-sweep clean · fuzz-lane crash=1 clean=0 · dangling-dns source >=1 candidate
#   6 scan          scan-all (--live unless --quick) → exit 0
#   7 findings      findings-v1 schema, unique ids, counts add up
#   8 har-audit     synthetic HAR fires >=10 rule families · --append merge sound
#   9 score+report  verdict.json written · REPORT.md has verdict + all 8 sections
#  10 cleanup       fixture stopped, port released, temp workspace removed
set -u

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
PORT=8766
HOST=127.0.0.1

WORK="$(mktemp -d /tmp/mr-robot-selftest-XXXXXX)" || exit 2
FIX_PID=""

# shellcheck disable=SC2329  # invoked via trap, not by name
cleanup() {
  [ -n "$FIX_PID" ] && kill "$FIX_PID" 2>/dev/null
  [ -n "$FIX_PID" ] && wait "$FIX_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

PASSES=0; FAILS=0
pass() { PASSES=$((PASSES + 1)); printf '[selftest] %-4s gate%d/10 %-26s PASS  %s\n' "" "$1" "$2" "${3:-}"; }
fail() { FAILS=$((FAILS + 1));  printf '[selftest] %-4s gate%d/10 %-26s FAIL  %s\n' "" "$1" "$2" "${3:-}"; }
say()  { printf '[selftest] %s\n' "$*"; }

# ---------------------------------------------------------------- environment
for cmd in python3 node nc curl; do
  command -v "$cmd" >/dev/null 2>&1 || { say "environment refusal: '$cmd' required"; exit 2; }
done
if nc -z -w 1 "$HOST" "$PORT" 2>/dev/null; then
  say "environment refusal: port $PORT already in use — stop the running fixture first"
  exit 2
fi
say "workspace: $WORK$([ "$QUICK" = 1 ] && echo '  (quick mode: live-scan gate skipped)')"

# ---------------------------------------------------------------- gate 1: syntax
g1=ok
for f in "$SCRIPT_DIR"/*.sh; do bash -n "$f" 2>"$WORK/g1.err" || { g1="bash -n: $(basename "$f")"; break; }; done
if [ "$g1" = ok ]; then
  for f in "$SCRIPT_DIR"/*.mjs; do node --check "$f" 2>"$WORK/g1.err" || { g1="node --check: $(basename "$f")"; break; }; done
fi
if [ "$g1" = ok ]; then
  python3 -m py_compile "$SKILL_DIR/assets/fixture/app.py" 2>"$WORK/g1.err" || g1="fixture py_compile"
fi
if [ "$g1" = ok ]; then
  pass 1 "syntax" "bash -n + node --check + py_compile"
else
  fail 1 "syntax" "$g1"
fi

# ---------------------------------------------------------------- gate 2: packaging
g2=ok
python3 - "$SKILL_DIR/SKILL.md" <<'PYEOF' || g2="frontmatter"
import re, sys
text = open(sys.argv[1], newline="").read()
if not re.search(r"^---\r?\nname: mr-robot\r?\n", text): sys.exit(1)
m = re.search(r"^description: (.+?)\r?$", text, re.M)
if not m or len(m.group(1)) > 1024: sys.exit(1)
PYEOF
if [ "$g2" = ok ]; then
  for f in SKILL.md references/03a-injection.md references/03m-saml-federation.md \
           references/03l-traffic-interception.md references/03n-known-cves.md \
           references/03o-xs-leaks.md \
           references/08-local-daemons.md references/09-fuzz-binary.md \
           references/04-report-template.md \
           scripts/scan-all.sh scripts/desync-probe.sh scripts/har-audit.mjs \
           scripts/cve-audit.mjs scripts/daemon-sweep.sh scripts/fuzz-lane.mjs \
           scripts/dangling-dns.mjs \
           scripts/score.mjs scripts/report.mjs scripts/retest.sh; do
    [ -f "$SKILL_DIR/$f" ] || { g2="missing $f"; break; }
  done
fi
if [ "$g2" = ok ]; then
  pass 2 "packaging" "frontmatter <=1024 + file map"
else
  fail 2 "packaging" "$g2"
fi

# ---------------------------------------------------------------- gate 3: fixture boots (temp copy)
cp -R "$SKILL_DIR/assets/fixture" "$WORK/fixture" 2>/dev/null
rm -rf "$WORK/fixture/.mr-robot" "$WORK/fixture/.tls" "$WORK/fixture/__pycache__"
python3 "$WORK/fixture/app.py" >"$WORK/fixture.log" 2>&1 &
FIX_PID=$!
booted=0
i=0
while [ "$i" -lt 20 ]; do
  if curl -s --max-time 2 "http://$HOST:$PORT/health" 2>/dev/null | grep -q ok; then booted=1; break; fi
  i=$((i + 1)); sleep 0.5
done
if [ "$booted" = 1 ]; then
  pass 3 "fixture" "threaded http.server on $PORT"
else
  say "  fixture.log tail: $(tail -2 "$WORK/fixture.log" 2>/dev/null | tr '\n' ' ')"
  fail 3 "fixture" "did not boot on http://$HOST:$PORT/health"
fi

# ---------------------------------------------------------------- gate 4: live lane proofs (marker-only)
lanes_failed=""
probe() { # $1 = lane, $2 = url, $3 = expected grep pattern
  curl -s --max-time 5 "$2" 2>/dev/null | grep -q "$3" || lanes_failed="$lanes_failed $1"
}
probe sqli   "http://$HOST:$PORT/search?q=%27%20OR%20%271%27%3D%271" "alice"
probe xss    "http://$HOST:$PORT/echo?name=%3Cscript%3Epoc%3C/script%3E" "<script>poc</script>"
probe ssrf   "http://$HOST:$PORT/fetch?url=http://$HOST:$PORT/health" "ok"
probe idor   "http://$HOST:$PORT/user?id=2" "bob@example.test"
probe xfer   "http://$HOST:$PORT/transfer?to=2&amount=-50" "balance now 150"
if [ -z "$lanes_failed" ]; then
  pass 4 "live lanes" "sqli xss ssrf idor xfer"
else
  fail 4 "live lanes" "failed:$lanes_failed"
fi

# ---------------------------------------------------------------- gate 5: probers
desync_ok=0
if bash "$SCRIPT_DIR/desync-probe.sh" "http://$HOST:$PORT/health" >"$WORK/desync.out" 2>&1; then
  desync_ok=1
else
  say "  desync exit $? (expected 0): $(grep VERDICT "$WORK/desync.out" | head -1)"
fi
bash "$SCRIPT_DIR/race-probe.sh" -n 6 -X GET \
  "http://$HOST:$PORT/transfer?to=2&amount=0" >"$WORK/race.out" 2>&1
rrc=$?
race_ok=0
if [ "$rrc" = 0 ] || [ "$rrc" = 1 ]; then race_ok=1; else say "  race exit $rrc (expected 0|1)"; fi
# daemon-sweep against the fixture port: the fixture sends no ACAO and no WS 101,
# so a clean (exit 0) verdict is the deterministic expectation — exit 1 means the
# sweep's detection fired where it must not (or the fixture grew a CORS header)
dsrc=0
bash "$SCRIPT_DIR/daemon-sweep.sh" -p "$PORT" >"$WORK/dsweep.out" 2>&1 || dsrc=$?
ds_ok=0
if [ "$dsrc" = 0 ]; then ds_ok=1; else say "  daemon-sweep exit $dsrc (expected 0): $(grep VERDICT "$WORK/dsweep.out" | head -1)"; fi
# fuzz-lane: crash-path (marker seed crashes a SIGSEGV-on-marker node target at
# iteration 1 → exit 1) + clean-path (marker-free target → exit 0, budget 3s)
fz_ok=0
if command -v node >/dev/null 2>&1; then
  mkdir -p "$WORK/fuzzcorpus"
  printf 'MRK' > "$WORK/fuzzcorpus/seed.txt"
  printf '%s\n' \
    'let d="";process.stdin.on("data",c=>d+=c);' \
    'process.stdin.on("end",()=>{if(d.includes("MRK"))process.kill(process.pid,"SIGSEGV");else process.exit(0);});' \
    > "$WORK/fuzzcrash.mjs"
  printf '%s\n' \
    'let d="";process.stdin.on("data",c=>d+=c);' \
    'process.stdin.on("end",()=>process.exit(0));' \
    > "$WORK/fuzzclean.mjs"
  fzrc=0; node "$SCRIPT_DIR/fuzz-lane.mjs" --budget 5 --max 50 \
    --corpus "$WORK/fuzzcorpus" -- node "$WORK/fuzzcrash.mjs" >"$WORK/fuzzcrash.out" 2>&1 || fzrc=$?
  fzcleanrc=0; node "$SCRIPT_DIR/fuzz-lane.mjs" --budget 3 --max 20 \
    -- node "$WORK/fuzzclean.mjs" >"$WORK/fuzzclean.out" 2>&1 || fzcleanrc=$?
  if [ "$fzrc" = 1 ] && [ "$fzcleanrc" = 0 ]; then fz_ok=1
  else say "  fuzz exit crash=$fzrc (want 1) clean=$fzcleanrc (want 0)"; fi
else
  say "  fuzz skipped (no node)"
  fz_ok=1
fi
# dangling-dns: source-mode fixture run must exit 0 and emit valid JSON with
# >=1 provider candidate (no DNS is ever touched here — source mode is
# offline by design, so this is deterministic)
dd_ok=0
if command -v node >/dev/null 2>&1; then
  mkdir -p "$WORK/ddns"
  printf '%s\n' 'static.example.com CNAME docs.example.herokuapp.com' \
    'cdn.example.com 3600 IN CNAME d111111abcdef8.cloudfront.net' \
    > "$WORK/ddns/dns.zone"
  ddrc=0; node "$SCRIPT_DIR/dangling-dns.mjs" "$WORK/ddns" >"$WORK/ddns.json" 2>/dev/null || ddrc=$?
  if [ "$ddrc" = 0 ] && node -e '
    const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    process.exit(d.schema === "mr-robot-dangling-dns-v1" && d.mode === "source" && d.candidates.length >= 1 ? 0 : 1);
  ' "$WORK/ddns.json" 2>/dev/null; then dd_ok=1
  else say "  dangling-dns exit $ddrc (want 0) or JSON invalid/empty"; fi
else
  say "  dangling-dns skipped (no node)"
  dd_ok=1
fi
if [ "$desync_ok" = 1 ] && [ "$race_ok" = 1 ] && [ "$ds_ok" = 1 ] && [ "$fz_ok" = 1 ] && [ "$dd_ok" = 1 ]; then
  pass 5 "probers" "desync 0 + race $rrc + sweep clean + fuzz 1/0 + ddns 1"
else
  fail 5 "probers" "desync_ok=$desync_ok race_exit=$rrc ds_ok=$ds_ok (want 0) fz_ok=$fz_ok (crash=1 clean=0) dd_ok=$dd_ok"
fi

# ---------------------------------------------------------------- gates 6-9: scan + downstream chain
if [ "$QUICK" = 1 ]; then
  bash "$SCRIPT_DIR/scan-all.sh" "$WORK/fixture" >"$WORK/scan.log" 2>&1
else
  bash "$SCRIPT_DIR/scan-all.sh" --live "http://$HOST:$PORT" "$WORK/fixture" >"$WORK/scan.log" 2>&1
fi
src=$?
RUN="$(find "$WORK/fixture/.mr-robot" -maxdepth 1 -type d -name 'run-*' -mtime -1 2>/dev/null | sort | tail -1)"
if [ "$src" = 0 ] && [ -n "$RUN" ] && [ -s "$RUN/findings.json" ]; then
  pass 6 "scan" "$([ "$QUICK" = 1 ] && echo passive || echo "live, $(grep -c '\[ok\]' "$WORK/scan.log") engines ok")"
else
  fail 6 "scan" "exit $src / no findings.json (log: $WORK/scan.log)"
fi

# gate 7: findings-v1 invariants
if [ -n "$RUN" ] && python3 - "$RUN/findings.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema"] == "mr-robot-findings-v1", "schema"
fs = d["findings"]; assert fs, "no findings"
ids = [f["id"] for f in fs]; assert len(set(ids)) == len(ids), "duplicate ids"
assert sum(d["counts"].values()) == len(fs), "counts != len(findings)"
assert all(f["severity"] in d["counts"] for f in fs), "severity outside counts"
PYEOF
then pass 7 "findings" "$(python3 -c "import json;print(len(json.load(open('$RUN/findings.json'))['findings']))" 2>/dev/null) records, ids unique, counts consistent"
else fail 7 "findings" "schema/invariant check failed"; fi

# gate 8: har-audit — synthetic HAR fires many rules, then a sound --append merge
python3 - "$WORK/syn.har" <<'PYEOF'
import json, sys
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"
tok = "gho_xxxxxxxxxxxxxxxxxxxxYYYYYYYYYYYY"
e = lambda **kw: dict(time=5, startedDateTime="2026-10-25T10:00:00Z", serverIPAddress="93.184.216.34", **kw)
har = {"log": {"version": "1.2", "creator": {"name": "selftest", "version": "0"}, "entries": [
 e(request=dict(method="GET", url=f"http://api.test/v1/me?token={tok}&page=2",
   headers=[dict(name="Authorization", value=f"Bearer {jwt}"), dict(name="Cookie", value="sid=abc123")],
   queryString=[dict(name="token", value=tok), dict(name="page", value="2")]),
   response=dict(status=200, headers=[dict(name="Server", value="nginx/1.24.0")],
   content=dict(size=0, mimeType="application/json"))),
 e(request=dict(method="GET", url="https://secure.test/app", headers=[], queryString=[]),
   response=dict(status=200, headers=[dict(name="Set-Cookie", value=f"session={jwt}; Path=/"),
     dict(name="X-Powered-By", value="Express 4.18.2"),
     dict(name="Access-Control-Allow-Origin", value="https://evil.example"),
     dict(name="Access-Control-Allow-Credentials", value="true")],
   content=dict(size=40, mimeType="application/json", text='{"node":"10.20.30.40"}'))),
 e(request=dict(method="POST", url="https://secure.test/login",
   headers=[dict(name="Content-Type", value="application/x-www-form-urlencoded")], queryString=[],
   postData=dict(mimeType="application/x-www-form-urlencoded", text=f"username=a&password=hunter2&token={tok}",
     params=[dict(name="username", value="a"), dict(name="password", value="hunter2"), dict(name="token", value=tok)])),
   response=dict(status=302, headers=[dict(name="Access-Control-Allow-Origin", value="*"),
     dict(name="Access-Control-Allow-Credentials", value="true")], content=dict(size=0, mimeType="text/plain"))),
 e(request=dict(method="GET", url=f"https://jwt.test/cb?jwt={jwt}", headers=[], queryString=[dict(name="jwt", value=jwt)]),
   response=dict(status=200, headers=[], content=dict(size=2, mimeType="text/plain", text="ok"))),
]}}
open(sys.argv[1], "w").write(json.dumps(har))
PYEOF
node "$SCRIPT_DIR/har-audit.mjs" "$WORK/syn.har" >"$WORK/har-standalone.json" 2>/dev/null
nrules=$(python3 -c "
import json; d = json.load(open('$WORK/har-standalone.json'))
print(len({f['title'].split(':')[0] for f in d['findings']}))" 2>/dev/null || echo 0)
if [ -n "$RUN" ] && [ "$nrules" -ge 10 ]; then
  node "$SCRIPT_DIR/har-audit.mjs" --append "$RUN/findings.json" "$WORK/syn.har" >/dev/null 2>&1
  if python3 - "$RUN/findings.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
fs = d["findings"]; ids = [f["id"] for f in fs]
assert len(set(ids)) == len(ids), "duplicate ids after append"
assert sum(d["counts"].values()) == len(fs), "counts stale after append"
assert sum(1 for s in d["scanners"] if s["name"] == "har-audit") == 1, "scanner row not exactly 1"
assert any(f["source_tool"] == "har-audit" for f in fs), "no merged findings"
PYEOF
  then pass 8 "har-audit" "$nrules rule families, append merge sound"
  else fail 8 "har-audit" "append merge broke invariants"
  fi
else fail 8 "har-audit" "only $nrules rule families fired (need >=10)"; fi

# gate 9: score → verdict.json, report → REPORT.md skeleton
g9=""
if [ -n "$RUN" ]; then
  node "$SCRIPT_DIR/score.mjs" "$RUN/findings.json" >"$WORK/score.md" 2>&1
  node "$SCRIPT_DIR/report.mjs" "$RUN/findings.json" -o "$WORK/REPORT.md" 2>"$WORK/report.err"
  python3 - "$RUN/verdict.json" "$WORK/REPORT.md" <<'PYEOF' || g9="output invariants"
import json, re, sys
v = json.load(open(sys.argv[1]))
assert v["verdict"] in ("GO", "CONDITIONAL-GO", "NO-GO"), "verdict value"
r = open(sys.argv[2]).read()
for h in [f"## {i}." for i in range(1, 9)]:
    assert h in r, f"missing section {h}"
assert "VERDICT:" in r and "mr-robot security audit" in r, "missing verdict/title"
PYEOF
else g9="no run dir"; fi
if [ -z "$g9" ]; then
  pass 9 "score+report" "verdict + REPORT skeleton (8 sections)"
else
  fail 9 "score+report" "$g9"
fi

# ---------------------------------------------------------------- gate 10: cleanup
cleanup
trap - EXIT INT TERM
g10=ok
if [ -n "$FIX_PID" ] && kill -0 "$FIX_PID" 2>/dev/null; then g10="fixture still running"; fi
nc -z -w 1 "$HOST" "$PORT" 2>/dev/null && g10="port $PORT not released"
[ -d "$WORK" ] && g10="workspace not removed"
# repo fixture dir untouched: no scans ran against it
[ -d "$SKILL_DIR/assets/fixture/.mr-robot" ] && g10="repo fixture polluted with .mr-robot"
if [ "$g10" = ok ]; then
  pass 10 "cleanup" "fixture stopped, port free, workspace gone"
else
  fail 10 "cleanup" "$g10"
fi
FIX_PID=""

# ---------------------------------------------------------------- summary
say "────────────────────────────────────────"
if [ "$FAILS" = 0 ]; then
  if [ "$QUICK" = 1 ]; then
    say "RESULT: PASS — $PASSES/10 gates green (quick mode: run without --quick before release)"
  else
    say "RESULT: PASS — $PASSES/10 gates green"
  fi
  exit 0
fi
say "RESULT: FAIL — $FAILS gate(s) failed, $PASSES passed"
exit 1
