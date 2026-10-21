#!/usr/bin/env bash
# mr-robot — multi-method vulnerability scanner orchestrator.
#
# Runs every applicable free/local scanner against a project, then merges all raw
# outputs into ONE normalized findings.json the agent (and score.mjs) can consume.
#
#   Usage:
#     scan-all.sh [--out <dir>] <target-dir>          # passive (default, always safe)
#     scan-all.sh --live <url> [--out <dir>] <dir>    # + nuclei DAST — localhost ONLY
#
# Guarantees: no accounts, no API keys, code never leaves the machine.
# Every scanner failure is non-fatal: unavailability is recorded, runs continue.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"

TARGET=""; OUT=""; LIVE_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out)   OUT="${2:-}"; shift 2 ;;
    --live)  LIVE_URL="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) if [ -z "$TARGET" ]; then TARGET="$1"; shift; else echo "unknown arg: $1" >&2; exit 2; fi ;;
  esac
done
TARGET="${TARGET:-.}"
TARGET="$(cd "$TARGET" && pwd)" || { echo "target not found" >&2; exit 2; }
[ -n "$OUT" ] || OUT="$TARGET/.mr-robot/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT" || exit 2
OUT="$(cd "$OUT" && pwd)"
LOG="$OUT/scan.log"
: > "$LOG"

# ---- authorization guard: live mode only ever talks to loopback ----------------
if [ -n "$LIVE_URL" ]; then
  host="$(printf '%s' "$LIVE_URL" | sed -E 's#^[a-zA-Z]+://([^:/]+).*#\1#')"
  case "$host" in
    localhost|127.0.0.1|::1|0.0.0.0) ;;
    *) echo "REFUSED: --live targets must be localhost (got host '$host')." >&2
       echo "Only run active tests against an instance of YOUR OWN project." >&2
       exit 3 ;;
  esac
  command -v python3 >/dev/null 2>&1 && \
    ! python3 - "$LIVE_URL" <<'PYEOF' && { echo "REFUSED: malformed URL." >&2; exit 3; }
import sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1])
sys.exit(0 if u.scheme in ("http","https") and u.netloc else 1)
PYEOF
fi

have() { command -v "$1" >/dev/null 2>&1; }
export PATH="$HOME/.local/bin:$PATH:$(go env GOPATH 2>/dev/null)/bin"

SCANNERS_JSON="$OUT/.scanners.tsv"   # name <TAB> status <TAB> detail
: > "$SCANNERS_JSON"
note()    { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$SCANNERS_JSON"; }
skip()    { note "$1" skipped "not installed"; printf '[skip]   %s (not installed)\n' "$1"; }
ran()     { note "$1" ok "${2:-}"; printf '[ok]     %s\n' "$1"; }
failrun() { note "$1" failed "${2:-}"; printf '[fail]   %s — %s\n' "$1" "${2:-see log}"; }

valid_json() { [ -s "$1" ] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$1" 2>/dev/null; }

# run_into <tool> <outfile> <accept-exit-codes...> -- <cmd...>
#   Runs cmd, tolerating "findings" exit codes; validates outfile when it is JSON.
run_into() {
  local tool="$1" out="$2"; shift 2
  local accept=(); while [ "$1" != "--" ]; do accept+=("$1"); shift; done; shift
  local rc=0; "$@" >>"$LOG" 2>&1 || rc=$?
  local okc=0 c
  for c in 0 1 "${accept[@]}"; do [ "$rc" = "$c" ] && okc=1 && break; done
  if [ "$okc" = 1 ] && valid_json "$out"; then
    ran "$tool"
  elif [ "$okc" = 1 ]; then
    failrun "$tool" "no valid json output"
  else
    failrun "$tool" "exit $rc"
  fi
}

echo "[scan] target : $TARGET"
echo "[scan] output : $OUT"
echo "[scan] mode   : $([ -n "$LIVE_URL" ] && echo "active (--live $LIVE_URL)" || echo "passive")"
echo "[scan] step 1/3 — scanners"

EXCL='.mr-robot,node_modules,vendor,.venv,venv,dist,build,target,.git,.tox'
EXCL_GLOB='.mr-robot/*,node_modules/*,vendor/*,.venv/*,venv/*,dist/*,build/*,target/*,.git/*'
# semgrep/opengrep --exclude accepts one glob per flag
EXCL_FLAGS=(--exclude '.mr-robot/*' --exclude 'node_modules/*' --exclude '*/node_modules/*'
            --exclude 'vendor/*' --exclude '.venv/*' --exclude 'venv/*'
            --exclude 'dist/*' --exclude 'build/*' --exclude 'target/*' --exclude '.git/*')

# ---------------------------------------------------------------- SAST
SAST_ENGINE=""
have opengrep && SAST_ENGINE=opengrep
[ -n "$SAST_ENGINE" ] || { have semgrep && SAST_ENGINE=semgrep; }
if [ -n "$SAST_ENGINE" ]; then
  cfg_ok=0
  # 1st: online community pack (downloads RULES only — never your code)
  if "$SAST_ENGINE" scan --config p/security-audit --json --quiet \
       "${EXCL_FLAGS[@]}" --output "$OUT/sast.json" "$TARGET" >>"$LOG" 2>&1 \
     && valid_json "$OUT/sast.json"; then
    cfg_ok=1; ran "$SAST_ENGINE (p/security-audit)"
  fi
  # 2nd: bundled offline rules — zero network
  if [ "$cfg_ok" = 0 ] && "$SAST_ENGINE" scan --config "$SKILL_DIR/assets/rules/local.yml" \
       --json --quiet "${EXCL_FLAGS[@]}" --output "$OUT/sast.json" "$TARGET" >>"$LOG" 2>&1 \
     && valid_json "$OUT/sast.json"; then
    cfg_ok=1; ran "$SAST_ENGINE (bundled offline rules)"
  fi
  [ "$cfg_ok" = 1 ] || failrun "$SAST_ENGINE" "rule config unavailable"
else
  skip "opengrep/semgrep"
fi

# ---------------------------------------------------------------- Secrets (tree + git history)
if have gitleaks; then
  GLCONF="$SKILL_DIR/assets/gitleaks.toml"   # default rules + path allowlist
  gl_ok=0
  # working tree (catches uncommitted .env, keys, fixtures)
  if gitleaks dir "$TARGET" -c "$GLCONF" -f json -r "$OUT/gitleaks-dir.json" \
       --redact --no-banner --exit-code 0 >>"$LOG" 2>&1 \
     && valid_json "$OUT/gitleaks-dir.json"; then gl_ok=1; fi
  # git history (catches secrets ever committed) — only inside a repo
  if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if gitleaks git "$TARGET" -c "$GLCONF" -f json -r "$OUT/gitleaks-git.json" \
         --redact --no-banner --exit-code 0 >>"$LOG" 2>&1 \
       && valid_json "$OUT/gitleaks-git.json"; then gl_ok=1; fi
  fi
  if [ "$gl_ok" = 1 ]; then ran "gitleaks (secrets: tree + history)"; else failrun "gitleaks" "no valid output"; fi
else skip "gitleaks"; fi

# ---------------------------------------------------------------- SCA: deps / CVEs / IaC / misconfig
if have trivy; then
  run_into trivy "$OUT/trivy.json" 0 1 -- \
    trivy fs --format json --quiet --scanners vuln,secret,misconfig \
      --skip-dirs "$EXCL" --output "$OUT/trivy.json" "$TARGET"
else skip "trivy"; fi

if have osv-scanner; then
  osv_rc=0
  # current v2 syntax; older syntax as fallback — both validated after the run
  osv-scanner scan source -r "$TARGET" --format json > "$OUT/osv.json" 2>>"$LOG" || osv_rc=$?
  if [ "$osv_rc" -gt 1 ] && ! valid_json "$OUT/osv.json"; then
    osv_rc=0
    osv-scanner scan --format json -r "$TARGET" > "$OUT/osv.json" 2>>"$LOG" || osv_rc=$?
  fi
  if ! valid_json "$OUT/osv.json" && grep -q "No package sources" "$LOG" 2>/dev/null; then
    # not an error: the project simply has no lockfiles for osv to read
    note osv-scanner skipped "no lockfiles/manifests"
    echo "[skip]   osv-scanner (no package sources)"
  elif valid_json "$OUT/osv.json" && [ "$osv_rc" -le 1 ]; then
    ran "osv-scanner (deps)"
  else
    failrun "osv-scanner" "exit $osv_rc"
  fi
else skip "osv-scanner"; fi

if have checkov; then
  checkov -d "$TARGET" --quiet --compact --output json > "$OUT/checkov.json" 2>>"$LOG"
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/checkov.json"; then ran "checkov (IaC/cloud)"; else failrun "checkov" "exit $rc"; fi
else skip "checkov"; fi

# ---------------------------------------------------------------- language specialists
if have bandit; then
  bandit -q -f json -o "$OUT/bandit.json" -r "$TARGET" -x "$EXCL_GLOB" >>"$LOG" 2>&1
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/bandit.json"; then ran "bandit (python)"; else failrun "bandit" "exit $rc"; fi
else skip "bandit"; fi

if have gosec && [ -f "$TARGET/go.mod" ]; then
  ( cd "$TARGET" && gosec -quiet -fmt json -out "$OUT/gosec.json" ./... ) >>"$LOG" 2>&1
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/gosec.json"; then ran "gosec (go)"; else failrun "gosec" "exit $rc"; fi
elif have gosec; then
  note gosec skipped "no go.mod"
fi

if have njsscan; then
  njsscan --json "$TARGET" -o "$OUT/njsscan.json" >>"$LOG" 2>&1
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/njsscan.json"; then ran "njsscan (nodejs)"; else failrun "njsscan" "exit $rc"; fi
else skip "njsscan"; fi

if have brakeman && [ -f "$TARGET/Gemfile" ]; then
  ( cd "$TARGET" && brakeman -f json -o "$OUT/brakeman.json" --no-pager ) >>"$LOG" 2>&1
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/brakeman.json"; then ran "brakeman (rails)"; else failrun "brakeman" "exit $rc"; fi
elif have brakeman; then
  note brakeman skipped "no Gemfile"
fi

if have shellcheck; then
  sh_files=()
  while IFS= read -r _sf; do sh_files+=("$_sf"); done < <(find "$TARGET" -type f \( -name '*.sh' -o -name '*.bash' \) \
      -not -path '*/.mr-robot/*' -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -n 400)
  if [ "${#sh_files[@]}" -gt 0 ]; then
    shellcheck -f json1 "${sh_files[@]}" > "$OUT/shellcheck.json" 2>>"$LOG"
    rc=$?
    if [ "$rc" -le 1 ] && valid_json "$OUT/shellcheck.json"; then ran "shellcheck (${#sh_files[@]} shell files)"; else failrun "shellcheck" "exit $rc"; fi
  else note shellcheck skipped "no shell files"; fi
else skip "shellcheck"; fi

if have cppcheck; then
  c_files=()
  while IFS= read -r _cf; do c_files+=("$_cf"); done < <(find "$TARGET" -type f \( -name '*.c' -o -name '*.cpp' -o -name '*.cc' -o -name '*.h' \) \
      -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -n 400)
  if [ "${#c_files[@]}" -gt 0 ]; then
    cppcheck --enable=warning,performance,portability --inline-suppr --template='{...}' \
      --xml-version=2 "${c_files[@]}" > "$OUT/cppcheck.xml" 2>>"$LOG"
    rc=$?
    if [ "$rc" -le 1 ] && [ -s "$OUT/cppcheck.xml" ]; then ran "cppcheck (c/c++)"; else failrun "cppcheck" "exit $rc"; fi
  else note cppcheck skipped "no c/c++ files"; fi
else skip "cppcheck"; fi

# ---------------------------------------------------------------- active DAST (gated)
if [ -n "$LIVE_URL" ]; then
  echo "[scan] step 2/3 — active DAST against $LIVE_URL (loopback only)"
  if have nuclei; then
    # first run needs the community template pack — warm it once (downloads RULES
    # only, never your code). Subsequent runs are fully local.
    NUC_TEMPLATES="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"
    if [ ! -d "$NUC_TEMPLATES" ]; then
      echo "[scan] warming nuclei templates (one-time download)..."
      nuclei -update-templates >>"$LOG" 2>&1 || true
    fi
    nuc_rc=0
    # localhost: 25 rps / 5 workers is a bounded, minutes-scale sweep of the
    # community pack — safe against the user's own instance.
    NUC_CMD=(nuclei -u "$LIVE_URL" -severity critical,high,medium -silent -duc \
             -jsonl-export "$OUT/nuclei.jsonl" -rate-limit 25 -c 5)
    # Portable 300s hard cap: background the sweep + watchdog kill. Signal-based
    # wrappers (GNU timeout / perl alarm) don't work here — nuclei (Go) ignores
    # SIGALRM and GNU timeout doesn't exist on stock macOS. SIGTERM/SIGKILL do work.
    "${NUC_CMD[@]}" >>"$LOG" 2>&1 &
    nuc_pid=$!
    (
      sleep 300
      kill -TERM "$nuc_pid" 2>/dev/null
      sleep 5
      kill -KILL "$nuc_pid" 2>/dev/null
    ) &
    nuc_wd=$!
    wait "$nuc_pid"; nuc_rc=$?
    kill "$nuc_wd" 2>/dev/null
    wait "$nuc_wd" 2>/dev/null
    # 143 = SIGTERM (watchdog), 137 = SIGKILL (watchdog, escalated)
    if [ "$nuc_rc" -eq 143 ] || [ "$nuc_rc" -eq 137 ]; then
      failrun "nuclei" "timed out after 300s (partial results kept if any)"
    elif [ "$nuc_rc" -le 1 ]; then
      ran "nuclei (live, $LIVE_URL)"
    else
      failrun "nuclei" "exit $nuc_rc"
    fi
  else skip "nuclei"; fi
else
  echo "[scan] step 2/3 — active DAST skipped (passive mode; re-run with --live http://localhost:PORT)"
fi

# ---------------------------------------------------------------- merge
echo "[scan] step 3/3 — merging raw outputs → findings.json"
MERGED="$OUT/findings.json"
python3 - "$OUT" "$TARGET" "$MERGED" <<'PYEOF'
import json, os, re, sys, glob, datetime, xml.etree.ElementTree as ET

out, target, merged_path = sys.argv[1], sys.argv[2], sys.argv[3]
SEVS = {"critical", "high", "medium", "low", "info"}

def sev(x, default="info"):
    if x is None: return default
    s = str(x).strip().lower()
    if s in SEVS: return s
    if s in ("error", "fatal", "dangerous", "critical"): return "high" if s == "error" else "critical"
    if s in ("warning", "warn"): return "medium"
    if s in ("med", "moderate", "medium"): return "medium"
    if s in ("notice", "style", "note", "informational"): return "info"
    if s in ("high", "important"): return "high"
    return default

def cwe_of(*vals):
    for v in vals:
        if v is None: continue
        if isinstance(v, list):
            for item in v:
                m = re.search(r"CWE-?(\d+)", str(item), re.I)
                if m: return "CWE-" + m.group(1)
        else:
            m = re.search(r"CWE-?(\d+)", str(v), re.I)
            if m: return "CWE-" + m.group(1)
    return None

def owasp_of(*vals):
    for v in vals:
        if v is None: continue
        items = v if isinstance(v, list) else [v]
        for item in items:
            m = re.search(r"A\d{2}:2025[-\w]*", str(item), re.I)
            if m: return m.group(0).upper()
    return None

findings, seq = [], 0
def add(tool, title, file=None, line=None, severity="info", cwe=None, owasp=None,
        evidence=None, extra=None):
    global seq
    seq += 1
    rec = {
        "id": f"MR-{seq:04d}",
        "source_tool": tool,
        "title": str(title).strip()[:400] or "(no title)",
        "file": file, "line": line,
        "severity": sev(severity),
        "cwe": cwe, "owasp": owasp,
        "evidence": (str(evidence).strip()[:600] if evidence else None),
        "status": "candidate",   # agent must verify before reporting
        "verified_by": None, "notes": None,
    }
    if extra: rec.update(extra)
    findings.append(rec)

def load(name):
    p = os.path.join(out, name)
    if os.path.exists(p) and os.path.getsize(p) > 0:
        try:
            with open(p) as f: return json.load(f)
        except Exception: return None
    return None

# --- semgrep / opengrep -------------------------------------------------------
d = load("sast.json")
if isinstance(d, dict):
    for m in d.get("results", []):
        ex = m.get("extra", {}) or {}
        meta = ex.get("metadata", {}) or {}
        impact = meta.get("impact")
        conf = str(ex.get("severity", "")).lower()
        s = sev(impact) if impact and str(impact).lower() in SEVS or (impact and str(impact).lower()=="critical") \
            else {"error": "medium", "warning": "low", "info": "info"}.get(conf, "low")
        add(m.get("check_id", "sast"), ex.get("message", "SAST finding"),
            m.get("path"), (m.get("start") or {}).get("line"), s,
            cwe_of(meta.get("cwe")), owasp_of(meta.get("owasp")),
            None, {"engine": "sast"})

# --- gitleaks (working-tree + git-history outputs) ---------------------------
for _gname in ("gitleaks-dir.json", "gitleaks-git.json", "gitleaks.json"):
    d = load(_gname)
    if not isinstance(d, list):
        continue
    for r in d:
        rid = r.get("RuleID", "")
        rule_l = rid.lower()
        s = "critical" if "private" in rule_l or ("high-entropy" in rule_l and "key" in rule_l) else "high"
        add("gitleaks", r.get("Description") or rid,
            r.get("File"), r.get("StartLine"), s,
            "CWE-798", None, f"rule={rid} (secret value redacted)",
            {"engine": "secrets"})

# --- trivy --------------------------------------------------------------------
d = load("trivy.json")
if isinstance(d, dict):
    for res in d.get("Results", []) or []:
        tgt = res.get("Target")
        for v in res.get("Vulnerabilities", []) or []:
            cv = None
            for src in ((v.get("CVSS") or {}).values()):
                vec = (src or {}).get("Vector") or (src or {}).get("VectorString")
                if vec: cv = vec; break
            add("trivy", f"{v.get('VulnerabilityID')} — {v.get('Title') or v.get('PkgName')}",
                tgt, None, v.get("Severity"), cwe_of(v.get("CWEs")),
                None, f"pkg {v.get('PkgName')} {v.get('InstalledVersion')} → fixed {v.get('FixedVersion')}",
                {"engine": "sca", "cvss_vector": cv, "aliases": v.get("aliases") or v.get("References") and None})
        for m in res.get("Misconfigurations", []) or []:
            add("trivy", f"[misconfig] {m.get('ID')} {m.get('Title')}",
                m.get("File") or tgt, m.get("StartLine"), m.get("Severity"),
                cwe_of(m.get("AVDID"), m.get("ID")), owasp_of(m.get("References")),
                (m.get("Description") or "")[:400], {"engine": "misconfig"})
        for sres in res.get("Secrets", []) or []:
            add("trivy", f"[secret] {sres.get('Title')}",
                sres.get("File") or tgt, sres.get("StartLine"), sres.get("Severity") or "high",
                "CWE-798", None, (sres.get("Category") or ""), {"engine": "secrets"})

# --- osv-scanner ---------------------------------------------------------------
d = load("osv.json")
if isinstance(d, dict):
    for group in d.get("results", []) or []:
        path = group.get("path")
        for pkg in group.get("packages", []) or []:
            pname = (pkg.get("package") or {}).get("name")
            for v in pkg.get("vulns", []) or []:
                s = "medium"
                for sv in v.get("severity", []) or []:
                    dbsev = (sv.get("database_specific") or {}).get("severity")
                    if dbsev: s = sev(dbsev); break
                add("osv-scanner", f"{v.get('id')} — {v.get('summary') or v.get('details','')[:80]}",
                    path, None, s, None, None,
                    f"package {pname}; aliases {', '.join((v.get('aliases') or [])[:4])}",
                    {"engine": "sca"})

# --- bandit --------------------------------------------------------------------
d = load("bandit.json")
if isinstance(d, dict):
    for r in d.get("results", []) or []:
        add("bandit", f"{r.get('test_name')}: {r.get('issue_text')}",
            r.get("filename"), r.get("line_number"), r.get("issue_severity"),
            cwe_of((r.get("issue_cwe") or {}).get("id")), None,
            f"confidence={r.get('issue_confidence')}", {"engine": "sast"})

# --- gosec ---------------------------------------------------------------------
d = load("gosec.json")
if isinstance(d, dict):
    for r in d.get("Issues", []) or []:
        add("gosec", f"{r.get('rule_id','?')}: {str(r.get('details',''))[:300]}",
            r.get("file"), r.get("line"), r.get("severity"),
            cwe_of((r.get("cwe") or {}).get("value")), None, None, {"engine": "sast"})

# --- shellcheck ----------------------------------------------------------------
d = load("shellcheck.json")
if isinstance(d, list):
    for r in d:
        lvl = str(r.get("level", "info")).lower()
        if lvl not in ("error", "warning"): continue   # keep noise out of findings
        add("shellcheck", f"SC{r.get('code')}: {r.get('message')}",
            r.get("file"), r.get("line"), "low" if lvl == "error" else "info",
            None, None, None, {"engine": "lint"})

# --- checkov -------------------------------------------------------------------
d = load("checkov.json")
if isinstance(d, dict):
    for r in (d.get("results") or {}).get("failed_checks", []) or []:
        add("checkov", f"[iac] {r.get('check_id')} {r.get('check_name')}",
            r.get("file_path"), r.get("start_line"), r.get("severity") or "medium",
            owasp_of(r.get("check_id")), "A02:2025-Security-Misconfiguration",
            f"resource: {r.get('resource')}", {"engine": "iac"})

# --- brakeman -------------------------------------------------------------------
d = load("brakeman.json")
if isinstance(d, dict):
    for r in d.get("warnings", []) or []:
        wt = str(r.get("warning_type", ""))
        s = "high" if "SQL" in wt or "Command" in wt else ("medium" if str(r.get("confidence","")).lower()=="high" else "low")
        add("brakeman", f"{wt}: {str(r.get('message',''))[:300]}",
            r.get("file"), r.get("line"), s, None, None,
            f"confidence={r.get('confidence')}", {"engine": "sast"})

# --- njsscan (schema varies → generic walker) ------------------------------------
def walk(obj, tool):
    if isinstance(obj, dict):
        has_loc = "line" in obj or "line_number" in obj or "lineno" in obj
        has_msg = any(k in obj for k in ("message", "description", "msg", "issue_text"))
        if has_loc and has_msg:
            add(tool,
                obj.get("message") or obj.get("description") or obj.get("msg") or obj.get("issue_text"),
                obj.get("file") or obj.get("path") or obj.get("filename"),
                obj.get("line") or obj.get("line_number") or obj.get("lineno"),
                sev((obj.get("metadata") or {}).get("severity") or obj.get("severity")),
                cwe_of(obj.get("cwe"), (obj.get("metadata") or {}).get("cwe")),
                owasp_of(obj.get("owasp"), (obj.get("metadata") or {}).get("owasp")),
                None, {"engine": "sast"})
        for v in obj.values(): walk(v, tool)
    elif isinstance(obj, list):
        for v in obj: walk(v, tool)

d = load("njsscan.json")
if d is not None: walk(d, "njsscan")

# --- nuclei (jsonl) --------------------------------------------------------------
p = os.path.join(out, "nuclei.jsonl")
if os.path.exists(p):
    with open(p) as f:
        for ln in f:
            ln = ln.strip()
            if not ln: continue
            try: r = json.loads(ln)
            except Exception: continue
            info = r.get("info") or {}
            add("nuclei", f"{r.get('templateID')}: {info.get('name')}",
                r.get("matched-at") or r.get("host"), None,
                info.get("severity"), cwe_of((info.get("classification") or {}).get("cwe-id")),
                owasp_of((info.get("classification") or {}).get("owasp")),
                str(r.get("matched-at") or "")[:200], {"engine": "dast"})

# --- cppcheck (xml) ---------------------------------------------------------------
p = os.path.join(out, "cppcheck.xml")
if os.path.exists(p) and os.path.getsize(p) > 0:
    try:
        root = ET.parse(p).getroot()
        for err in root.iter("error"):
            sev_c = err.get("severity", "warning")
            if sev_c not in ("error", "warning"): continue
            loc = err.find("location")
            add("cppcheck", f"{err.get('id')}: {err.get('msg')}",
                loc.get("file") if loc is not None else None,
                int(loc.get("line")) if loc is not None and loc.get("line") else None,
                "medium" if sev_c == "error" else "low", None, None, None,
                {"engine": "sast"})
    except Exception:
        pass

# --- scanners status ---------------------------------------------------------------
scanners = []
sp = os.path.join(out, ".scanners.tsv")
if os.path.exists(sp):
    for ln in open(sp):
        parts = ln.rstrip("\n").split("\t")
        if len(parts) >= 2:
            scanners.append({"name": parts[0], "status": parts[1], "detail": parts[2] if len(parts) > 2 else ""})

# --- dedupe + finalize --------------------------------------------------------------
seen, final = set(), []
for f in findings:
    key = (f["source_tool"], f["file"], f["line"], f["title"][:120])
    if key in seen: continue
    seen.add(key)
    final.append(f)

order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
final.sort(key=lambda f: (order.get(f["severity"], 5), f["source_tool"]))

doc = {
    "schema": "mr-robot-findings-v1",
    "target": target,
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "mode": "active" if any(s["name"].startswith("nuclei") and s["status"] == "ok" for s in scanners) else "passive",
    "scanners": scanners,
    "counts": {s: sum(1 for f in final if f["severity"] == s) for s in SEVS},
    "findings": final,
}
with open(merged_path, "w") as f:
    json.dump(doc, f, indent=2)
print(f"[merge] {len(final)} candidate findings → {merged_path}")
for s in ("critical", "high", "medium", "low", "info"):
    c = doc["counts"][s]
    if c: print(f"          {s:9s}: {c}")
PYEOF

rc=$?
if [ "$rc" -ne 0 ]; then
  echo "[scan] merge FAILED (python exit $rc) — raw outputs are in $OUT" >&2
  exit "$rc"
fi

echo
echo "[scan] done."
echo "  findings : $MERGED"
echo "  raw logs : $LOG"
echo "  next     : run scripts/score.mjs $MERGED  (or hand findings.json to the agent for verification)"
exit 0
