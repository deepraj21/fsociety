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
PATH="$HOME/.local/bin:$PATH:$(go env GOPATH 2>/dev/null)/bin"
export PATH

SCANNERS_JSON="$OUT/.scanners.tsv"   # name <TAB> status <TAB> detail
: > "$SCANNERS_JSON"
note()    { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$SCANNERS_JSON"; }
skip()    { note "$1" skipped "not installed"; printf '[skip]   %s (not installed)\n' "$1"; }
ran()     { note "$1" ok "${2:-}"; printf '[ok]     %s\n' "$1"; }
failrun() { note "$1" failed "${2:-}"; printf '[fail]   %s — %s\n' "$1" "${2:-see log}"; }

valid_json() { [ -s "$1" ] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$1" 2>/dev/null; }

# run_into_bg <tool> <outfile> <accept-exit-codes...> -- <cmd...>
#   Runs cmd in background, tolerating "findings" exit codes; validates outfile
#   when it is JSON. Collect all background jobs with wait_bg_all before merging.
BG_PIDS=""
run_into_bg() {
  local tool="$1" out="$2"; shift 2
  local accept=(); while [ "$1" != "--" ]; do accept+=("$1"); shift; done; shift
  (
    local rc=0; "$@" >>"$LOG.$tool" 2>&1 || rc=$?
    local okc=0 c
    # ${arr[@]+...} guard: empty array expansion is "unbound" under set -u on bash 3.2
    for c in 0 1 ${accept[@]+"${accept[@]}"}; do [ "$rc" = "$c" ] && okc=1 && break; done
    if [ "$okc" = 1 ] && valid_json "$out"; then
      ran "$tool"
    elif [ "$okc" = 1 ]; then
      failrun "$tool" "no valid json output"
    else
      failrun "$tool" "exit $rc"
    fi
  ) &
  BG_PIDS="$BG_PIDS $!"
}
wait_bg_all() {
  local p
  for p in $BG_PIDS; do wait "$p" 2>/dev/null; done
  BG_PIDS=""
}

# ---------------------------------------------------------------- stack fingerprint (for nuclei tags + new linters)
STACK_TAGS=""
detect_stack() {
  local t="$1" tags=""
  [ -f "$t/package.json" ]      && tags="$tags,cdn,js,nodejs"
  [ -f "$t/requirements.txt" ] || [ -f "$t/pyproject.toml" ] && tags="$tags,python,flask,django,fastapi"
  [ -f "$t/go.mod" ]            && tags="$tags,golang"
  [ -f "$t/Gemfile" ]           && tags="$tags,ruby,rails"
  [ -f "$t/pom.xml" ] || [ -f "$t/build.gradle" ] && tags="$tags,java,spring"
  [ -f "$t/composer.json" ]     && tags="$tags,php,laravel"
  [ -f "$t/Cargo.toml" ]        && tags="$tags,rust"
  [ -f "$t/Dockerfile" ]        && tags="$tags,docker,container"
  [ -d "$t/kubernetes" ] || [ -d "$t/k8s" ] || ls "$t"/deploy/*.yaml >/dev/null 2>&1 && tags="$tags,k8s"
  # always include generic misconfig/exposure checks (comma only if stack tags exist)
  tags="${tags#,}"
  [ -n "$tags" ] && tags="$tags,"
  tags="${tags}misconfig,exposure,default-login,cves"
  printf '%s' "$tags" | tr ',' '\n' | sort -u | paste -sd, -
}
STACK_TAGS="$(detect_stack "$TARGET")"
echo "[scan] stack tags: $STACK_TAGS"

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

# ---------------------------------------------------------------- SAST (bg)
SAST_ENGINE=""
have opengrep && SAST_ENGINE=opengrep
[ -n "$SAST_ENGINE" ] || { have semgrep && SAST_ENGINE=semgrep; }
if [ -n "$SAST_ENGINE" ]; then
  (
  cfg_ok=0
  # 1st: online community pack (downloads RULES only — never your code)
  if "$SAST_ENGINE" scan --config p/security-audit --json --quiet \
       "${EXCL_FLAGS[@]}" --output "$OUT/sast.json" "$TARGET" >>"$LOG.sast" 2>&1 \
     && valid_json "$OUT/sast.json"; then
    cfg_ok=1; ran "$SAST_ENGINE (p/security-audit)"
  fi
  # 2nd: bundled offline rules — zero network
  if [ "$cfg_ok" = 0 ] && "$SAST_ENGINE" scan --config "$SKILL_DIR/assets/rules/local.yml" \
       --json --quiet "${EXCL_FLAGS[@]}" --output "$OUT/sast.json" "$TARGET" >>"$LOG.sast" 2>&1 \
     && valid_json "$OUT/sast.json"; then
    cfg_ok=1; ran "$SAST_ENGINE (bundled offline rules)"
  fi
  [ "$cfg_ok" = 1 ] || failrun "$SAST_ENGINE" "rule config unavailable"
  ) &
  BG_PIDS="$BG_PIDS $!"
else
  skip "opengrep/semgrep"
fi

# ---------------------------------------------------------------- Secrets (bg: tree + git history)
if have gitleaks; then
  (
  GLCONF="$SKILL_DIR/assets/gitleaks.toml"   # default rules + path allowlist
  gl_ok=0
  # working tree (catches uncommitted .env, keys, fixtures)
  if gitleaks dir "$TARGET" -c "$GLCONF" -f json -r "$OUT/gitleaks-dir.json" \
       --redact --no-banner --exit-code 0 >>"$LOG.gitleaks" 2>&1 \
     && valid_json "$OUT/gitleaks-dir.json"; then gl_ok=1; fi
  # git history (catches secrets ever committed) — only inside a repo
  if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if gitleaks git "$TARGET" -c "$GLCONF" -f json -r "$OUT/gitleaks-git.json" \
         --redact --no-banner --exit-code 0 >>"$LOG.gitleaks" 2>&1 \
       && valid_json "$OUT/gitleaks-git.json"; then gl_ok=1; fi
  fi
  if [ "$gl_ok" = 1 ]; then ran "gitleaks (secrets: tree + history)"; else failrun "gitleaks" "no valid output"; fi
  ) &
  BG_PIDS="$BG_PIDS $!"
else skip "gitleaks"; fi

# ---------------------------------------------------------------- SCA: deps / CVEs / IaC / misconfig (bg)
if have trivy; then
  run_into_bg trivy "$OUT/trivy.json" 0 1 -- \
    trivy fs --format json --quiet --scanners vuln,secret,misconfig \
      --skip-dirs "$EXCL" --output "$OUT/trivy.json" "$TARGET"
else skip "trivy"; fi

if have osv-scanner; then
  (
  osv_rc=0
  # current v2 syntax; older syntax as fallback — both validated after the run
  osv-scanner scan source -r "$TARGET" --format json > "$OUT/osv.json" 2>>"$LOG.osv" || osv_rc=$?
  if [ "$osv_rc" -gt 1 ] && ! valid_json "$OUT/osv.json"; then
    osv_rc=0
    osv-scanner scan --format json -r "$TARGET" > "$OUT/osv.json" 2>>"$LOG.osv" || osv_rc=$?
  fi
  if ! valid_json "$OUT/osv.json" && grep -q "No package sources" "$LOG.osv" 2>/dev/null; then
    # not an error: the project simply has no lockfiles for osv to read
    note osv-scanner skipped "no lockfiles/manifests"
    echo "[skip]   osv-scanner (no package sources)"
  elif valid_json "$OUT/osv.json" && [ "$osv_rc" -le 1 ]; then
    ran "osv-scanner (deps)"
  else
    failrun "osv-scanner" "exit $osv_rc"
  fi
  ) &
  BG_PIDS="$BG_PIDS $!"
else skip "osv-scanner"; fi

if have checkov; then
  (
  checkov -d "$TARGET" --quiet --compact --output json > "$OUT/checkov.json" 2>>"$LOG.checkov"
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/checkov.json"; then ran "checkov (IaC/cloud)"; else failrun "checkov" "exit $rc"; fi
  ) &
  BG_PIDS="$BG_PIDS $!"
else skip "checkov"; fi

# known-CVE verification lane (references/03n) — fingerprint + curated table;
# passive always, + harmless header-diff probe when --live
if have node; then
  if [ -n "$LIVE_URL" ]; then
    run_into_bg cve-audit "$OUT/cve-audit.json" -- \
      node "$SCRIPT_DIR/cve-audit.mjs" "$TARGET" --live "$LIVE_URL" --out "$OUT/cve-audit.json"
  else
    run_into_bg cve-audit "$OUT/cve-audit.json" -- \
      node "$SCRIPT_DIR/cve-audit.mjs" "$TARGET" --out "$OUT/cve-audit.json"
  fi
else skip "cve-audit"; fi

# ---------------------------------------------------------------- language specialists (bg)
if have bandit; then
  run_into_bg bandit "$OUT/bandit.json" -- \
    bandit -q -f json -o "$OUT/bandit.json" -r "$TARGET" -x "$EXCL_GLOB"
else skip "bandit"; fi

if have gosec && [ -f "$TARGET/go.mod" ]; then
  (
  # NOTE: no -quiet — in gosec 2.29.0 -quiet suppresses the -out report file entirely
  ( cd "$TARGET" && gosec -fmt json -out "$OUT/gosec.json" ./... ) >>"$LOG.gosec" 2>&1
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/gosec.json"; then ran "gosec (go)"; else failrun "gosec" "exit $rc"; fi
  ) &
  BG_PIDS="$BG_PIDS $!"
elif have gosec; then
  note gosec skipped "no go.mod"
fi

if have njsscan; then
  run_into_bg njsscan "$OUT/njsscan.json" -- \
    njsscan --json "$TARGET" -o "$OUT/njsscan.json"
else skip "njsscan"; fi

if have brakeman && [ -f "$TARGET/Gemfile" ]; then
  (
  ( cd "$TARGET" && brakeman -f json -o "$OUT/brakeman.json" --no-pager ) >>"$LOG.brakeman" 2>&1
  rc=$?
  if [ "$rc" -le 1 ] && valid_json "$OUT/brakeman.json"; then ran "brakeman (rails)"; else failrun "brakeman" "exit $rc"; fi
  ) &
  BG_PIDS="$BG_PIDS $!"
elif have brakeman; then
  note brakeman skipped "no Gemfile"
fi

if have staticcheck && [ -f "$TARGET/go.mod" ]; then
  run_into_bg staticcheck "$OUT/staticcheck.json" -- \
    bash -c "cd '$TARGET' && staticcheck -f json ./... > '$OUT/staticcheck.json' 2>>'$LOG.staticcheck'; \
             [ -s '$OUT/staticcheck.json' ] || echo '[]' > '$OUT/staticcheck.json'"
elif have staticcheck; then
  note staticcheck skipped "no go.mod"
fi

if have hadolint; then
  hl_files=()
  while IFS= read -r _hl; do hl_files+=("$_hl"); done < <(find "$TARGET" -maxdepth 3 -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.dockerfile' \) \
      -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -n 20)
  if [ "${#hl_files[@]}" -gt 0 ]; then
    run_into_bg hadolint "$OUT/hadolint.json" -- hadolint -f json -o "$OUT/hadolint.json" "${hl_files[@]}"
  else note hadolint skipped "no Dockerfiles"; fi
else skip "hadolint"; fi

if have kube-linter; then
  kl_target=""
  for _kl in "$TARGET/kubernetes" "$TARGET/k8s" "$TARGET/deploy" "$TARGET/infra" "$TARGET/charts" "$TARGET/helm"; do
    [ -d "$_kl" ] && { kl_target="$_kl"; break; }
  done
  if [ -n "$kl_target" ]; then
    run_into_bg kube-linter "$OUT/kubelinter.json" -- \
      kube-linter lint "$kl_target" --format json --output "$OUT/kubelinter.json"
  else note kube-linter skipped "no k8s manifests dir"; fi
else skip "kube-linter"; fi

# eslint-plugin-security — only when the project already has it installed
# (we never modify the user's project by installing dev-deps ourselves)
if have npx && [ -f "$TARGET/package.json" ] && [ -d "$TARGET/node_modules/eslint-plugin-security" ]; then
  cat > "$OUT/eslint-sec.json" <<'ESLCONF'
{ "plugins": ["security"], "parserOptions": { "ecmaVersion": 2022, "sourceType": "module" },
  "rules": { "security/detect-object-injection": "warn", "security/detect-non-literal-fs-filename": "warn",
             "security/detect-eval-with-expression": "error", "security/detect-possible-timing-attacks": "warn",
             "security/detect-pseudoRandomBytes": "error" } }
ESLCONF
  run_into_bg eslint-sec "$OUT/eslint-sec-findings.json" -- \
    bash -c "cd '$TARGET' && npx --no-install eslint --no-eslintrc --config '$OUT/eslint-sec.json' \
             --resolve-plugins-relative-to '$TARGET' --ext .js,.ts,.jsx,.tsx -f json . \
             --ignore-pattern node_modules --ignore-pattern .mr-robot > '$OUT/eslint-sec-findings.json'"
else
  have npx && [ -f "$TARGET/package.json" ] && note eslint-sec skipped "eslint-plugin-security not in node_modules"
fi

if have shellcheck; then
  (
  sh_files=()
  while IFS= read -r _sf; do sh_files+=("$_sf"); done < <(find "$TARGET" -type f \( -name '*.sh' -o -name '*.bash' \) \
      -not -path '*/.mr-robot/*' -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -n 400)
  if [ "${#sh_files[@]}" -gt 0 ]; then
    shellcheck -f json1 "${sh_files[@]}" > "$OUT/shellcheck.json" 2>>"$LOG.shellcheck"
    rc=$?
    if [ "$rc" -le 1 ] && valid_json "$OUT/shellcheck.json"; then ran "shellcheck (${#sh_files[@]} shell files)"; else failrun "shellcheck" "exit $rc"; fi
  else note shellcheck skipped "no shell files"; fi
  ) &
  BG_PIDS="$BG_PIDS $!"
else skip "shellcheck"; fi

if have cppcheck; then
  (
  c_files=()
  while IFS= read -r _cf; do c_files+=("$_cf"); done < <(find "$TARGET" -type f \( -name '*.c' -o -name '*.cpp' -o -name '*.cc' -o -name '*.h' \) \
      -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -n 400)
  if [ "${#c_files[@]}" -gt 0 ]; then
    cppcheck --enable=warning,performance,portability --inline-suppr --template='{...}' \
      --xml-version=2 "${c_files[@]}" > "$OUT/cppcheck.xml" 2>>"$LOG.cppcheck"
    rc=$?
    if [ "$rc" -le 1 ] && [ -s "$OUT/cppcheck.xml" ]; then ran "cppcheck (c/c++)"; else failrun "cppcheck" "exit $rc"; fi
  else note cppcheck skipped "no c/c++ files"; fi
  ) &
  BG_PIDS="$BG_PIDS $!"
else skip "cppcheck"; fi

# collect all passive scanner jobs before proceeding
wait_bg_all

# ---------------------------------------------------------------- active DAST (gated)
if [ -n "$LIVE_URL" ]; then
  echo "[scan] step 2/3 — active DAST against $LIVE_URL (loopback only)"

  # ---- bounded localhost port sweep (nmap) — unexpected listening services
  if have nmap; then
    nmap_host="$(printf '%s' "$LIVE_URL" | sed -E 's#^[a-zA-Z]+://([^:/]+).*#\1#')"
    case "$nmap_host" in
      0.0.0.0) nmap_host="127.0.0.1" ;;
    esac
    if nmap -Pn -T4 -sV --top-ports 200 -oX "$OUT/nmap.xml" -PE -n "$nmap_host" >>"$LOG.nmap" 2>&1 \
       && [ -s "$OUT/nmap.xml" ]; then
      ran "nmap (localhost top-200 ports, -sV)"
    else
      failrun "nmap" "exit $?"
    fi
  else skip "nmap"; fi

  # ---- TLS audit (testssl) — https targets only
  # Bounded by the nuclei-style background watchdog: testssl's own
  # --connect-timeout needs the GNU `timeout` binary (absent on stock macOS)
  # and FATALs without it, so wall-time is enforced from here instead.
  case "$LIVE_URL" in
    https://*)
      if have testssl; then
        tls_t="$(printf '%s' "$LIVE_URL" | sed -E 's#^https://##; s#/.*$##')"
        echo "[scan] TLS audit: $tls_t (protocols, server defaults, headers, preference)"
        testssl --quiet --color 0 --jsonfile "$OUT/testssl.json" -p -S -h -P "$tls_t" \
          >>"$LOG.testssl" 2>&1 &
        tsc_pid=$!
        (
          sleep 120
          kill -TERM "$tsc_pid" 2>/dev/null
          sleep 5
          kill -KILL "$tsc_pid" 2>/dev/null
        ) &
        tsc_wd=$!
        wait "$tsc_pid"; tsc_rc=$?
        kill "$tsc_wd" 2>/dev/null
        wait "$tsc_wd" 2>/dev/null
        if [ -s "$OUT/testssl.json" ]; then
          ran "testssl (TLS audit, $tls_t)"
        elif [ "$tsc_rc" -eq 143 ] || [ "$tsc_rc" -eq 137 ]; then
          failrun "testssl" "timed out after 120s ($tls_t)"
        else
          failrun "testssl" "exit $tsc_rc ($tls_t)"
        fi
      else skip "testssl (not installed — run setup-tools.sh)"; fi ;;
    *) skip "testssl (target is plain http — nothing to audit)" ;;
  esac

  # ---- nuclei DAST — stack-aware template tag selection
  if have nuclei; then
    # first run needs the community template pack — warm it once (downloads RULES
    # only, never your code). Subsequent runs are fully local.
    NUC_TEMPLATES="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"
    if [ ! -d "$NUC_TEMPLATES" ]; then
      echo "[scan] warming nuclei templates (one-time download)..."
      nuclei -update-templates >>"$LOG.nuclei" 2>&1 || true
    fi
    nuc_rc=0
    # Stack-aware tag selection: only templates relevant to the detected stack
    # (e.g. python/django/flask + generic misconfig/exposure/default-login/cves).
    # Falls back to the generic set if no stack detected — the goal is to stay
    # inside the 300s watchdog rather than sweep the full community pack.
    echo "[scan] nuclei tags: $STACK_TAGS"
    NUC_CMD=(nuclei -u "$LIVE_URL" -tags "$STACK_TAGS" -severity "critical,high,medium"
             -silent -duc -jsonl-export "$OUT/nuclei.jsonl" -rate-limit 25 -c 5)
    # Portable 300s hard cap: background the sweep + watchdog kill. Signal-based
    # wrappers (GNU timeout / perl alarm) don't work here — nuclei (Go) ignores
    # SIGALRM and GNU timeout doesn't exist on stock macOS. SIGTERM/SIGKILL do work.
    "${NUC_CMD[@]}" >>"$LOG.nuclei" 2>&1 &
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
      failrun "nuclei" "timed out after 300s (partial results kept if any; tags: $STACK_TAGS)"
    elif [ "$nuc_rc" -le 1 ]; then
      ran "nuclei (live, $LIVE_URL, tags: $STACK_TAGS)"
    else
      failrun "nuclei" "exit $nuc_rc (tags: $STACK_TAGS)"
    fi
  else skip "nuclei"; fi
else
  echo "[scan] step 2/3 — active DAST skipped (passive mode; re-run with --live http://localhost:PORT)"
fi

# ---------------------------------------------------------------- merge
echo "[scan] step 3/3 — merging raw outputs → findings.json"
MERGED="$OUT/findings.json"
python3 - "$OUT" "$TARGET" "$MERGED" "$STACK_TAGS" "${LIVE_URL:-}" <<'PYEOF'
import json, os, re, sys, glob, datetime, xml.etree.ElementTree as ET

out, target, merged_path = sys.argv[1], sys.argv[2], sys.argv[3]
stack_tags = sys.argv[4] if len(sys.argv) > 4 else ""
live_url = sys.argv[5] if len(sys.argv) > 5 else ""
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
        # source_tool = the scanner (retest diffs match on it); rule id goes in the title
        add("semgrep", f"{m.get('check_id', 'sast')}: {ex.get('message', 'SAST finding')}",
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
# v2 (osv-scanner >= 2): results[].{source:{path}, packages[]:
#   {package:{name,version}, groups[], vulnerabilities:[osv records]}}
# v1 tolerated: results[].{path, packages[].{package, vulns[]}}
d = load("osv.json")
if isinstance(d, dict):
    for group in d.get("results", []) or []:
        path = (group.get("source") or {}).get("path") or group.get("path")
        for pkg in group.get("packages", []) or []:
            pmeta = pkg.get("package") or {}
            pname, pver = pmeta.get("name"), pmeta.get("version")
            for v in (pkg.get("vulnerabilities") or pkg.get("vulns") or []):
                s, vec = "medium", None
                for sv in v.get("severity", []) or []:
                    if str(sv.get("type", "")).startswith("CVSS") and sv.get("score"):
                        vec = sv.get("score")
                    dbsev = (sv.get("database_specific") or {}).get("severity")
                    if dbsev: s = sev(dbsev, s); break
                extra = {"engine": "sca"}
                if vec and str(vec).startswith("CVSS:3."):
                    extra["cvss_vector"] = str(vec)   # score.mjs computes the real base score
                add("osv-scanner",
                    f"{v.get('id')} — {v.get('summary') or str(v.get('details') or '')[:80]}",
                    path, None, s, None, None,
                    f"package {pname}{(' ' + pver) if pver else ''}; "
                    f"aliases {', '.join((v.get('aliases') or [])[:4])}",
                    extra)

# --- cve-audit (known-CVE verification lane, references/03n) ------------------
# {"schema":"mr-robot-cve-audit-v1", findings:[{cve, also, pkg, version, source,
#   severity, cvss, cwe, owasp, fixed, title, evidence, kev}]}
d = load("cve-audit.json")
if isinstance(d, dict):
    for f in d.get("findings", []) or []:
        extra = {"engine": "known-cve",
                 "aliases": [f.get("cve")] + [a for a in (f.get("also") or []) if a]}
        if isinstance(f.get("cvss"), (int, float)):
            extra["cvss_score"] = f["cvss"]   # score.mjs: basis "reported"
        add("cve-audit", f.get("title") or f.get("cve"),
            None, None, f.get("severity") or "info",
            f.get("cwe"), f.get("owasp"), f.get("evidence"), extra)

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
# checkov --output json emits a LIST of per-framework results when several
# frameworks match (k8s + Dockerfile …) and a bare DICT when only one does.
d = load("checkov.json")
if isinstance(d, dict): d = [d]
if isinstance(d, list):
    for ent in d:
        if not isinstance(ent, dict): continue
        for r in (ent.get("results") or {}).get("failed_checks", []) or []:
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

# --- hadolint --------------------------------------------------------------------
d = load("hadolint.json")
if isinstance(d, list):
    for r in d:
        lvl = str(r.get("level", "warning")).lower()
        s = {"error": "medium", "warning": "low"}.get(lvl, "info")
        code = str(r.get("code", ""))
        add("hadolint", f"Dockerfile: {r.get('message', '')} (rule {code})",
            r.get("file"), r.get("line"), s, None, None, None,
            {"engine": "lint"})

# --- staticcheck -----------------------------------------------------------------
d = load("staticcheck.json")
if isinstance(d, list):
    for r in d:
        code = r.get("code", "")
        sev_s = "medium" if code.startswith(("SA9", "SA10", "SA2")) else "low"
        add("staticcheck", f"{code}: {r.get('message', '')}",
            r.get("location", {}).get("file"), (r.get("location", {}).get("line")),
            sev_s, None, None, None, {"engine": "sast"})

# --- kube-linter --------------------------------------------------------------------
# kube-linter JSON: {"Checks":[defs], "Reports":[{Check, Diagnostic:{Message}, Object:{Metadata:{FilePath}, ...}}], "Summary":...}
d = load("kubelinter.json")
if isinstance(d, dict):
    _sec_kw = ("privilege", "root", "hostnetwork", "hostpid", "hostipc",
               "capabilities", "seccomp", "apparmor", "automount", "serviceaccount")
    for r in d.get("Reports", []) or []:
        check = str(r.get("Check", r.get("CheckName", "")))
        obj = r.get("Object", {}) or {}
        msg = ((r.get("Diagnostic") or {}).get("Message")) or r.get("Description", "")
        sev_k = "medium" if any(w in check.lower() for w in _sec_kw) else "low"
        add("kube-linter", f"[k8s] {check}: {msg}",
            (obj.get("Metadata") or {}).get("FilePath") or obj.get("File"),
            obj.get("Line"),
            sev_k, None, "A05:2025", None, {"engine": "iac"})

# --- eslint-plugin-security --------------------------------------------------------
def walk_eslint(obj, tool):
    if isinstance(obj, dict):
        if "ruleId" in obj and obj.get("ruleId"):
            sev_e = "medium" if str(obj.get("severity", 1)) == "2" else "low"
            add(tool, f"{obj['ruleId']}: {obj.get('message', '')}",
                (obj.get("line") and obj.get("filePath")) or obj.get("filePath"),
                obj.get("line"), sev_e, None, None, None, {"engine": "sast"})
        for v in obj.values(): walk_eslint(v, tool)
    elif isinstance(obj, list):
        for v in obj: walk_eslint(v, tool)

d = load("eslint-sec-findings.json")
if d is not None: walk_eslint(d, "eslint-sec")

# --- nmap (unexpected listening services) -------------------------------------------
p = os.path.join(out, "nmap.xml")
if os.path.exists(p) and os.path.getsize(p) > 0:
    try:
        root = ET.parse(p).getroot()
        expected = {80, 443, 3000, 5000, 5173, 4173, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 27017, 5432, 3306, 6379}
        for host in root.iter("host"):
            for port in host.iter("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open": continue
                pid = int(port.get("portid", 0))
                service = port.find("service")
                svc_name = service.get("name", "") if service is not None else ""
                svc_extra = ""
                if service is not None:
                    _prod, _ver = service.get("product") or "", service.get("version") or ""
                    if _prod: svc_extra = f" — {_prod} {_ver}".rstrip()
                s = "info" if pid in expected else "medium"
                note_str = "expected" if pid in expected else "unexpected — verify it is intentional"
                add("nmap", f"Port {pid}/{port.get('protocol')} open ({svc_name}{svc_extra}) — {note_str}",
                    None, None, s, None, None, None, {"engine": "recon"})
    except Exception:
        pass

# --- testssl (TLS audit — https targets) -------------------------------------------
p = os.path.join(out, "testssl.json")
if os.path.exists(p) and os.path.getsize(p) > 0:
    try:
        entries = json.load(open(p))
        # operational ids describe OUR runner, not the target — never findings
        _op_ids = {"engine_problem", "scanProblem", "scanTime"}
        if isinstance(entries, list):
            for e in entries:
                if not isinstance(e, dict): continue
                if e.get("id") in _op_ids: continue
                _e_sev = str(e.get("severity") or "").upper()
                if _e_sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"): continue
                add("testssl", f"{e.get('id')}: {str(e.get('finding'))[:200]}",
                    None, None, _e_sev.lower(), None, None,
                    f"ip {e.get('ip')} port {e.get('port')}", {"engine": "network"})
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
scanners.sort(key=lambda s: s["name"])   # parallel runs write TSV out of order

# --- KEV enrichment (CISA known-exploited catalog — cached, offline-safe) ----------
# Only catalog metadata is downloaded (like nuclei templates): never target data.
# MR_ROBOT_NO_NETWORK=1 skips the fetch; a stale cache is still used.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_set = None
kev_info = {"source": KEV_URL, "status": "unavailable"}
try:
    import time as _time
    _cache_dir = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "mr-robot")
    _cache = os.path.join(_cache_dir, "kev.json")
    _fresh = os.path.exists(_cache) and (_time.time() - os.path.getmtime(_cache)) < 7 * 86400
    _fetched = False
    if not _fresh and os.environ.get("MR_ROBOT_NO_NETWORK") != "1":
        _raw = None
        try:  # urllib first...
            import urllib.request as _urlreq
            _req = _urlreq.Request(KEV_URL, headers={"User-Agent": "mr-robot-skill"})
            _raw = _urlreq.urlopen(_req, timeout=10).read()
        except Exception:
            # ...then curl: macOS system Pythons often lack a CA bundle while
            # curl uses the OS trust store. Catalog metadata only — never target data.
            try:
                import subprocess as _sp, shutil as _sh
                if _sh.which("curl"):
                    _p = _sp.run(["curl", "-fsSL", "--max-time", "15", "-A", "mr-robot-skill", KEV_URL],
                                 capture_output=True, timeout=20)
                    _raw = _p.stdout or None
            except Exception:
                _raw = None
        if _raw:
            try:
                json.loads(_raw)                     # validate before caching
                os.makedirs(_cache_dir, exist_ok=True)
                with open(_cache, "wb") as _fh: _fh.write(_raw)
                _fetched, _fresh = True, True
            except Exception:
                pass                                 # corrupt body → keep stale cache
    if os.path.exists(_cache):
        _cat = json.load(open(_cache))
        kev_set = {v["cveID"] for v in _cat.get("vulnerabilities", []) if v.get("cveID")}
        kev_info = {"source": KEV_URL,
                    "status": "fetched" if _fetched else ("cache" if _fresh else "stale-cache"),
                    "entries": len(kev_set),
                    "catalog_version": _cat.get("catalogVersion")}
except Exception as _e:
    kev_info["error"] = str(_e)[:160]

# --- dedupe + finalize --------------------------------------------------------------
seen, final = set(), []
for f in findings:
    key = (f["source_tool"], f["file"], f["line"], f["title"][:120])
    if key in seen: continue
    seen.add(key)
    final.append(f)

order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
final.sort(key=lambda f: (order.get(f["severity"], 5), f["source_tool"]))

# CVE findings → kev: true/false (only CVE-bearing findings get the field;
# only when the catalog loaded)
if kev_set:
    _cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    for f in final:
        _m = _cve_re.search(f.get("title") or "") or _cve_re.search(f.get("evidence") or "")
        if _m:
            f["kev"] = _m.group(0).upper() in kev_set

doc = {
    "schema": "mr-robot-findings-v1",
    "target": target,
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "mode": "active" if any(s["name"].startswith("nuclei") and s["status"] == "ok" for s in scanners) else "passive",
    "coverage": {
        "nuclei_template_tags": stack_tags or None,
        "live_url": live_url or None,
        "kev_catalog": kev_info,
    },
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
if kev_set:
    _nk = sum(1 for f in final if f.get("kev"))
    print(f"          kev      : {_nk} finding(s) in CISA KEV catalog ({kev_info['status']})")
elif kev_info.get("status") == "unavailable":
    print("          kev      : catalog unavailable (offline) — findings not annotated")
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
echo "  next     : run scripts/score.mjs $MERGED  (verdict · --ci for gates) · scripts/sarif.mjs $MERGED (SARIF for CI upload)"
exit 0
