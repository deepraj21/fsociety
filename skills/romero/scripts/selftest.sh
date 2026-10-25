#!/usr/bin/env bash
# romero — end-to-end selftest: proves the installed skill actually works.
#
#   Usage:
#     selftest.sh            full run (~40s: two captures incl. budget run)
#     selftest.sh --quick    skip the budget-capture gate (~30s)
#
# Runs against a TEMP COPY of the bundled demo (never touches the repo's demo
# dir), requires python3/node/curl/nc + a Chrome-family browser, and refuses
# to start if port 8767 is already taken (stop a running demo first). All
# gates run even after a failure — you get the full picture — and cleanup
# runs on every exit path (trap).
#
#   Exit: 0 all gates pass · 1 one or more gates failed · 2 environment refusal
#
# Gates:
#   1 syntax        bash -n · node --check · demo py_compile
#   2 packaging     SKILL.md frontmatter (name, description <=1024) · file map
#   3 demo          boots on 127.0.0.1:8767 from the temp copy
#   4 capture       capture.mjs exit 0 + invariants (WS frames, SSE, cookies,
#                   redirect hop, storage, third-party host, HAR parity)
#   5 report        12 sections, verdict-free, JWT decoded, observation >=1
#   6 refusals      bad scheme / unknown flag → capture exit 2 · bad schema →
#                   report exit 2 (observer must refuse out-of-scope input)
#   7 budget        --budget 2 still exits 0 and flags budget.exceeded
#                   (skipped with --quick)
#   8 cleanup       demo stopped, port released, temp workspace removed
set -u

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
PORT=8767
HOST=127.0.0.1

WORK="$(mktemp -d /tmp/romero-selftest-XXXXXX)" || exit 2
DEMO_PID=""

# shellcheck disable=SC2329  # invoked via trap, not by name
cleanup() {
  [ -n "$DEMO_PID" ] && kill "$DEMO_PID" 2>/dev/null
  [ -n "$DEMO_PID" ] && wait "$DEMO_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

PASSES=0; FAILS=0
pass() { PASSES=$((PASSES + 1)); printf '[selftest] gate%d/8 %-24s PASS  %s\n' "$1" "$2" "${3:-}"; }
fail() { FAILS=$((FAILS + 1));  printf '[selftest] gate%d/8 %-24s FAIL  %s\n' "$1" "$2" "${3:-}"; }
say()  { printf '[selftest] %s\n' "$*"; }

# ---------------------------------------------------------------- environment
for cmd in python3 node curl nc; do
  command -v "$cmd" >/dev/null 2>&1 || { say "environment refusal: '$cmd' required"; exit 2; }
done
browser_found=0
for b in "${CHROME_PATH:-}" \
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
         "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
         "/usr/bin/google-chrome" "/usr/bin/chromium" "/usr/bin/chromium-browser"; do
  [ -n "$b" ] && [ -x "$b" ] && { browser_found=1; break; }
done
[ "$browser_found" = 1 ] || { say "environment refusal: no Chrome/Brave/Chromium found"; exit 2; }
if nc -z -w 1 "$HOST" "$PORT" 2>/dev/null; then
  say "environment refusal: port $PORT already in use — stop the running demo first"
  exit 2
fi
say "workspace: $WORK$([ "$QUICK" = 1 ] && echo '  (quick mode: budget gate skipped)')"

# ---------------------------------------------------------------- gate 1: syntax
g1=ok
for f in "$SCRIPT_DIR"/*.sh; do bash -n "$f" 2>"$WORK/g1.err" || { g1="bash -n: $(basename "$f")"; break; }; done
if [ "$g1" = ok ]; then
  for f in "$SCRIPT_DIR"/*.mjs; do node --check "$f" 2>"$WORK/g1.err" || { g1="node --check: $(basename "$f")"; break; }; done
fi
if [ "$g1" = ok ]; then
  python3 -c "import py_compile,sys; py_compile.compile(sys.argv[1], cfile='$WORK/demo.pyc', doraise=True)" \
    "$SKILL_DIR/assets/demo/app.py" 2>"$WORK/g1.err" || g1="demo py_compile"
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
if not re.search(r"^---\r?\nname: romero\r?\n", text): sys.exit(1)
m = re.search(r"^description: (.+?)\r?$", text, re.M)
if not m or len(m.group(1)) > 1024: sys.exit(1)
PYEOF
if [ "$g2" = ok ]; then
  for f in SKILL.md references/01-report-structure.md references/02-header-cookie-reference.md \
           scripts/capture.mjs scripts/report.mjs scripts/selftest.sh \
           assets/demo/app.py assets/demo/index.html assets/demo/README.md; do
    [ -f "$SKILL_DIR/$f" ] || { g2="missing $f"; break; }
  done
fi
if [ "$g2" = ok ]; then
  pass 2 "packaging" "frontmatter <=1024 + file map"
else
  fail 2 "packaging" "$g2"
fi

# ---------------------------------------------------------------- gate 3: demo boots (temp copy)
mkdir -p "$WORK/demo"
cp "$SKILL_DIR/assets/demo/app.py" "$SKILL_DIR/assets/demo/index.html" "$WORK/demo/" 2>/dev/null
python3 "$WORK/demo/app.py" >"$WORK/demo.log" 2>&1 &
DEMO_PID=$!
booted=0
i=0
while [ "$i" -lt 20 ]; do
  if curl -s --max-time 2 "http://$HOST:$PORT/" 2>/dev/null | grep -q "romero demo fixture"; then booted=1; break; fi
  i=$((i + 1)); sleep 0.5
done
if [ "$booted" = 1 ]; then
  pass 3 "demo" "loose fixture on $PORT (temp copy)"
else
  say "  demo.log tail: $(tail -2 "$WORK/demo.log" 2>/dev/null | tr '\n' ' ')"
  fail 3 "demo" "did not boot on http://$HOST:$PORT/"
fi

# ---------------------------------------------------------------- gate 4: capture invariants
node "$SCRIPT_DIR/capture.mjs" "http://$HOST:$PORT" --out "$WORK/cap1" \
  --route /final-page >"$WORK/cap1.log" 2>&1
caprc=$?
if [ "$caprc" = 0 ] && [ -s "$WORK/cap1/capture.json" ]; then
  if python3 - "$WORK" <<'PYEOF'
import json, sys
w = sys.argv[1]
d = json.load(open(f"{w}/cap1/capture.json"))
c = d["counts"]
assert d["schema"] == "mr-romero-capture-v1", "schema"
assert c["wsFrames"] >= 2, f'wsFrames={c["wsFrames"]}'
assert c["sseMessages"] >= 1, f'sseMessages={c["sseMessages"]}'
assert c["cookiesPost"] >= 3, f'cookiesPost={c["cookiesPost"]}'
assert any(r.get("redirect") for r in d["requests"]), "redirect hop"
assert d["storage"], "no storage"
assert d["storage"][0]["localStorage"].get("demoJwt", "").count(".") == 2, "JWT in storage"
hosts = {r["url"].split("/")[2] for r in d["requests"]}
assert "localhost:8767" in hosts, f"third-party host missing: {hosts}"
assert any("route executed" == p["kind"] for p in d["pages"]), "route not marked executed"
h = json.load(open(f"{w}/cap1/capture.har"))
assert h["log"]["version"] == "1.2", "har version"
assert len(h["log"]["entries"]) == len(d["requests"]), \
    f'HAR parity: {len(h["log"]["entries"])} != {len(d["requests"])}'
assert all(e["time"] >= 0 for e in h["log"]["entries"]), "negative har time"
assert any(e["response"]["cookies"] for e in h["log"]["entries"]), "no set-cookie in HAR"
PYEOF
  then
    pass 4 "capture" "$(python3 -c "import json;d=json.load(open('$WORK/cap1/capture.json'));c=d['counts'];print(f\"{c['requests']} req, {c['wsFrames']} ws, {c['sseMessages']} sse, {c['cookiesPost']} ck\")")"
  else
    fail 4 "capture" "invariant check failed (see $WORK/cap1/capture.json)"
  fi
else
  fail 4 "capture" "exit $caprc / no capture.json (log: $WORK/cap1.log)"
fi

# ---------------------------------------------------------------- gate 5: report
node "$SCRIPT_DIR/report.mjs" "$WORK/cap1/capture.json" -o "$WORK/cap1/REPORT.md" \
  >"$WORK/report.log" 2>&1
reprt=$?
if [ "$reprt" = 0 ] && [ -s "$WORK/cap1/REPORT.md" ]; then
  if python3 - "$WORK/cap1/REPORT.md" <<'PYEOF'
import re, sys
r = open(sys.argv[1]).read()
secs = re.findall(r"^## (\d+)\.", r, re.M)
assert secs == [str(i) for i in range(1, 13)], f"sections: {secs}"
assert "VERDICT" not in r and "NO-GO" not in r, "verdict language leaked"
assert "JWT payloads decoded" in r and "read:profile write:orders" in r, "JWT decode"
assert "Bearer eyJ" in r, "Authorization header row"
assert "localhost:8767" in r, "third-party row"
assert "romero-demo-db" in r, "IndexedDB row"
assert "echo:hello-from-page" in r, "WS frame sample"
assert "romero-sse" in r, "SSE sample"
assert re.search(r"^- .+\(§5\)", r, re.M), "observations missing section pointers"
assert "Coverage (honest scope)" in r, "coverage disclosure"
PYEOF
  then
    pass 5 "report" "12 sections, verdict-free, all lanes represented"
  else
    fail 5 "report" "content invariants failed (see $WORK/cap1/REPORT.md)"
  fi
else
  fail 5 "report" "exit $reprt (log: $WORK/report.log)"
fi

# ---------------------------------------------------------------- gate 6: refusals
g6=ok
node "$SCRIPT_DIR/capture.mjs" "ftp://example.com" --out "$WORK/x" >"$WORK/ref1.log" 2>&1 \
  || [ "$?" = 2 ] || g6="ftp scheme did not exit 2"
node "$SCRIPT_DIR/capture.mjs" "http://x.com" --nope >"$WORK/ref2.log" 2>&1 \
  || [ "$?" = 2 ] || g6="unknown flag did not exit 2"
echo '{"schema":"wrong"}' > "$WORK/bad.json"
node "$SCRIPT_DIR/report.mjs" "$WORK/bad.json" >"$WORK/ref3.log" 2>&1 \
  || [ "$?" = 2 ] || g6="bad schema did not exit 2"
grep -q "REFUSED" "$WORK/ref1.log" || g6="missing REFUSED message"
if [ "$g6" = ok ]; then
  pass 6 "refusals" "bad scheme · bad flag · bad schema → exit 2 + REFUSED"
else
  fail 6 "refusals" "$g6"
fi

# ---------------------------------------------------------------- gate 7: budget
if [ "$QUICK" = 1 ]; then
  say "gate7/8 budget                    SKIP  (quick mode)"
else
  node "$SCRIPT_DIR/capture.mjs" "http://$HOST:$PORT" --out "$WORK/cap2" \
    --budget 2 >"$WORK/cap2.log" 2>&1
  brc=$?
  if [ "$brc" = 0 ] && python3 - "$WORK/cap2/capture.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["budget"]["exceeded"] is True, f'not flagged: {d["budget"]}'
assert d["budget"]["observed"] > 2, "observed should exceed budget"
assert d["requests"], "still records what it saw"
PYEOF
  then
    pass 7 "budget" "budget 2 → observed >2, flagged, exit 0"
  else
    fail 7 "budget" "exit $brc / budget not flagged (log: $WORK/cap2.log)"
  fi
fi

# ---------------------------------------------------------------- gate 8: cleanup
cleanup
trap - EXIT INT TERM
g8=ok
if [ -n "$DEMO_PID" ] && kill -0 "$DEMO_PID" 2>/dev/null; then g8="demo still running"; fi
nc -z -w 1 "$HOST" "$PORT" 2>/dev/null && g8="port $PORT not released"
[ -d "$WORK" ] && g8="workspace not removed"
# the repo's demo dir must stay clean (selftest only ever runs the temp copy)
for f in "$SKILL_DIR/assets/demo"/*.log "$SKILL_DIR/assets/demo"/capture* "$SKILL_DIR/assets/demo"/*.har; do
  if [ -e "$f" ]; then g8="repo demo polluted: $(basename "$f")"; fi
done
if [ "$g8" = ok ]; then
  pass 8 "cleanup" "demo stopped, port free, workspace gone, repo clean"
else
  fail 8 "cleanup" "$g8"
fi
DEMO_PID=""

# ---------------------------------------------------------------- summary
say "────────────────────────────────────────"
if [ "$FAILS" = 0 ]; then
  if [ "$QUICK" = 1 ]; then
    say "RESULT: PASS — $PASSES gates green (quick mode: run without --quick before release)"
  else
    say "RESULT: PASS — $PASSES/8 gates green"
  fi
  exit 0
fi
say "RESULT: FAIL — $FAILS gate(s) failed, $PASSES passed"
exit 1
