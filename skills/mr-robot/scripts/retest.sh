#!/usr/bin/env bash
# retest.sh — remediation retest: prove which findings are actually fixed.
#
# usage: retest.sh <baseline-findings.json> [target-dir] [--live <url> | --passive]
#
#   Re-runs scan-all.sh against the same target (same mode as the baseline by
#   default), fingerprints every finding (source tool + title + file, normalized
#   for absolute paths and line drift), and classifies each baseline finding:
#
#     fixed        absent from the retest AND its source tool ran ok
#                  (or its file no longer exists in the target)
#     persisting   still present in the retest run
#     unknown      absent, but its source tool was skipped/failed in the
#                  retest → cannot claim fixed without evidence
#     new          not in the baseline (regression or previously-unscanned)
#
#   Findings already marked status:"fixed" in the baseline are skipped.
#
#   --live <url>   force an active retest even if the baseline was passive
#   --passive      force a passive retest even if the baseline was live
#                  (their live findings then classify as unknown — expected)
#
# exit codes: 0 = everything fixed and nothing new
#             1 = leftovers (persisting/unknown/new) — CI-gateable
#             2 = usage or run error
set -euo pipefail

die() { echo "[retest] error: $*" >&2; exit 2; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_ALL="$SCRIPT_DIR/scan-all.sh"

BASELINE=""; TARGET=""; LIVE=""; FORCE_PASSIVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --live)     LIVE="${2:-}"; [ -n "$LIVE" ] || die "--live needs a url"; shift 2 ;;
    --passive)  FORCE_PASSIVE=1; shift ;;
    -h|--help)  sed -n '2,26p' "$0"; exit 0 ;;
    -*)         die "unknown flag $1" ;;
    *)          if [ -z "$BASELINE" ]; then BASELINE="$1"
                elif [ -z "$TARGET" ]; then TARGET="$1"
                else die "unexpected argument: $1"; fi; shift ;;
  esac
done
[ -n "$BASELINE" ] || die "usage: retest.sh <baseline-findings.json> [target-dir] [--live <url> | --passive]"
[ -f "$BASELINE" ] || die "baseline not found: $BASELINE"
[ -f "$SCAN_ALL" ] || die "scan-all.sh not found next to retest.sh"

# ---- baseline metadata (target, live url, timestamp) ---------------------------
if ! META="$(python3 - "$BASELINE" <<'PYEOF'
import json, shlex, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("[retest] baseline is not valid JSON", file=sys.stderr)
    sys.exit(1)
if d.get("schema") != "mr-robot-findings-v1":
    print("[retest] baseline is not a mr-robot findings.json (schema mismatch)",
          file=sys.stderr)
    sys.exit(1)
cov = d.get("coverage") or {}
print(f"BASE_TARGET={shlex.quote(str(d.get('target') or ''))}")
print(f"BASE_LIVE={shlex.quote(str(cov.get('live_url') or ''))}")
print(f"BASE_AT={shlex.quote(str(d.get('generated_at') or ''))}")
print(f"BASE_COUNT={shlex.quote(str(len(d.get('findings') or [])))}")
PYEOF
)"; then
  die "could not read baseline metadata"
fi
eval "$META"

TARGET="${TARGET:-$BASE_TARGET}"
[ -n "$TARGET" ] || die "no target dir given and baseline has none"
[ -d "$TARGET" ] || die "target dir not found: $TARGET"

if [ -n "$FORCE_PASSIVE" ]; then
  LIVE=""
elif [ -z "$LIVE" ]; then
  # shellcheck disable=SC2153  # BASE_LIVE comes from the eval'd python output above
  LIVE="$BASE_LIVE"          # same mode as the baseline by default
fi

echo "[retest] baseline : $BASELINE ($BASE_COUNT findings, $BASE_AT)"
echo "[retest] target   : $TARGET"
if [ -n "$LIVE" ]; then
  echo "[retest] mode     : active (--live $LIVE)"
else
  echo "[retest] mode     : passive"
fi
echo "[retest] step 1/2 — re-running scan-all.sh ..."

# ---- re-run the same engagement scope ------------------------------------------
SCAN_LOG="$(mktemp -t mr-robot-retest.XXXXXX)"
trap 'rm -f "$SCAN_LOG"' EXIT
set +e
if [ -n "$LIVE" ]; then
  bash "$SCAN_ALL" --live "$LIVE" "$TARGET" 2>&1 | tee "$SCAN_LOG"
else
  bash "$SCAN_ALL" "$TARGET" 2>&1 | tee "$SCAN_LOG"
fi
SCAN_RC=${PIPESTATUS[0]}
set -e
[ "$SCAN_RC" -le 1 ] || die "scan-all.sh failed (exit $SCAN_RC)"

NEW_FINDINGS="$(grep -E 'findings : ' "$SCAN_LOG" | tail -1 | awk '{print $NF}' || true)"
[ -n "$NEW_FINDINGS" ] && [ -f "$NEW_FINDINGS" ] || die "could not locate retest findings.json"
NEW_RUN_DIR="$(dirname "$NEW_FINDINGS")"

# ---- diff baseline vs retest ----------------------------------------------------
echo "[retest] step 2/2 — diffing against baseline ..."
RETEST_JSON="$NEW_RUN_DIR/retest.json"
set +e
python3 - "$BASELINE" "$NEW_FINDINGS" "$NEW_RUN_DIR" "$RETEST_JSON" "$TARGET" <<'PYEOF'
import json, os, re, sys, datetime, collections

base_p, new_p, run_dir, out_p, target = sys.argv[1:6]
base = json.load(open(base_p))
new = json.load(open(new_p))

def norm(s, prefix=""):
    s = str(s or "")
    if prefix and s.startswith(prefix):
        s = s[len(prefix):]
    s = re.sub(r"^/+", "", s)
    return re.sub(r"\s+", " ", s).strip().lower()

def fkey(f):
    file = re.sub(r":\d+$", "", norm(f.get("file", ""), target))  # drop line drift
    return (norm(f.get("source_tool")), norm(f.get("title")), file)

# tool availability in the retest run (name -> status), names normalized
tstatus = {}
tsv = os.path.join(run_dir, ".scanners.tsv")
if os.path.exists(tsv):
    for ln in open(tsv):
        p = ln.rstrip("\n").split("\t")
        if len(p) >= 2:
            tstatus[p[0].lower().split(" (")[0]] = p[1]

def tool_ran_ok(source_tool):
    """True = tool ok, False = tool skipped/failed, None = tool not in retest."""
    st = str(source_tool or "").lower()
    if st in tstatus:
        return tstatus[st] == "ok"
    for k, v in tstatus.items():          # prefix match (osv-scanner (deps) etc.)
        if k.startswith(st) or st.startswith(k):
            return v == "ok"
    return None

new_keys = {fkey(f): f for f in new.get("findings", [])}

results = []
counts = collections.Counter()
for bf in base.get("findings", []):
    if str(bf.get("status", "")).lower() == "fixed":
        counts["already-fixed"] += 1
        continue
    k = fkey(bf)
    if k in new_keys:
        cls, why = "persisting", "still present in retest"
        rf = new_keys[k]
        if rf.get("severity") != bf.get("severity"):
            why = f"still present (severity {bf.get('severity')} -> {rf.get('severity')})"
    else:
        # file deleted entirely? strong evidence regardless of tool
        fpath = norm(bf.get("file", ""), target).split(":")[0]
        file_gone = bool(fpath) and not os.path.exists(os.path.join(target, fpath))
        ok = tool_ran_ok(bf.get("source_tool"))
        if file_gone:
            cls, why = "fixed", f"file gone from target ({fpath})"
        elif ok is True:
            cls, why = "fixed", f"absent; {bf.get('source_tool')} ran ok in retest"
        else:
            cls = "unknown"
            why = ("absent but source tool skipped/failed in retest — not proof"
                   if ok is False else "absent but source tool not present in retest")
    counts[cls] += 1
    results.append({
        "classification": cls,
        "reason": why,
        "baseline": {k2: bf.get(k2) for k2 in
                     ("id", "source_tool", "title", "file", "severity", "status")},
    })

base_keys = {fkey(b) for b in base.get("findings", [])}
new_findings = [{"id": f.get("id"), "source_tool": f.get("source_tool"),
                 "title": f.get("title"), "file": f.get("file"),
                 "severity": f.get("severity")}
                for f in new.get("findings", []) if fkey(f) not in base_keys]
counts["new"] = len(new_findings)

# coverage delta: tools that were ok in the baseline but not ok in the retest
def ok_tools(doc, scan_dir=None):
    out = set()
    for s in doc.get("scanners", []):
        if s.get("status") == "ok":
            out.add(s.get("name", "").lower().split(" (")[0])
    return out
lost = sorted(t for t in ok_tools(base) if tstatus.get(t) != "ok")

out = {
    "schema": "mr-robot-retest-v1",
    "baseline": os.path.abspath(base_p),
    "baseline_generated_at": base.get("generated_at"),
    "retest_findings": os.path.abspath(new_p),
    "retest_generated_at": new.get("generated_at"),
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "counts": dict(counts),
    "coverage_delta": {"tools_not_ok_in_retest": lost},
    "results": results,
    "new_findings": new_findings,
}
json.dump(out, open(out_p, "w"), indent=1)

# ---- human summary --------------------------------------------------------------
print()
print(f"[retest] fixed       : {counts['fixed']}")
print(f"[retest] persisting  : {counts['persisting']}")
print(f"[retest] unknown     : {counts['unknown']}  (tool didn't run — no fix credit)")
print(f"[retest] new         : {counts['new']}")
if counts.get("already-fixed"):
    print(f"[retest] already fixed in baseline (skipped): {counts['already-fixed']}")
for r in results:
    if r["classification"] in ("persisting", "unknown"):
        b = r["baseline"]
        print(f"  [{r['classification']:<10}] {b.get('id')} {b.get('severity')}: "
              f"{str(b.get('title'))[:90]}")
        print(f"               reason: {r['reason']}")
for f in new_findings[:10]:
    print(f"  [new       ] {f.get('severity')}: {str(f.get('title'))[:90]}")
if len(new_findings) > 10:
    print(f"  [new       ] … and {len(new_findings) - 10} more (see retest.json)")
if lost:
    if counts["unknown"]:
        unknown_tools = sorted({str(r["baseline"].get("source_tool") or "?")
                                for r in results if r["classification"] == "unknown"})
        print(f"[retest] WARNING: {counts['unknown']} absent finding(s) got NO fix "
              f"credit — tools not ok in retest: {', '.join(unknown_tools)}")
    else:
        print(f"[retest] note: tools not ok in retest (all their baseline findings "
              f"still provable): {', '.join(lost)}")
print(f"[retest] written → {out_p}")
print(f"[retest] next: mark fixed findings status:\"fixed\" in the baseline "
      f"findings.json, then re-run score.mjs for an updated verdict")
sys.exit(0 if (counts["persisting"] == 0 and counts["unknown"] == 0
               and counts["new"] == 0) else 1)
PYEOF
DIFF_RC=$?
set -e
echo "[retest] done (exit $DIFF_RC — 0 all fixed & nothing new, 1 leftovers)."
exit "$DIFF_RC"
