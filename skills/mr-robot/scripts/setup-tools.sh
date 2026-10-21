#!/usr/bin/env bash
# mr-robot — zero-cost, local-only security toolchain installer.
# - Idempotent: safe to run repeatedly; already-installed tools are left alone.
# - Never prompts (non-interactive), never sends your source code anywhere.
# - Missing tools are reported, never fatal: scan-all.sh degrades gracefully.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OK_TOOLS=()      # available now
ADDED_TOOLS=()   # installed by this run
MISSING_TOOLS=() # could not install (reported with manual instructions)

log() { printf '[mr-robot:setup] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

HAVE_BREW=0;  have brew  && HAVE_BREW=1
HAVE_PIPX=0;  have pipx  && HAVE_PIPX=1
HAVE_PIP3=0;  have pip3  && HAVE_PIP3=1
HAVE_GO=0;    have go    && HAVE_GO=1
HAVE_APT=0;   have apt-get && HAVE_APT=1
HAVE_SUDO=0;  sudo -n true >/dev/null 2>&1 && HAVE_SUDO=1

quiet() { "$@" >/dev/null 2>&1; }

brew_install()  { [ "$HAVE_BREW" = 1 ]  || return 1; HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_AUTO_UPDATE=1 quiet brew install "$1"; }
pipx_install()  { [ "$HAVE_PIPX" = 1 ]  || return 1; quiet pipx install "$1"; }
pip3_install()  { [ "$HAVE_PIP3" = 1 ]  || return 1; quiet pip3 install --user --quiet "$1"; }
go_install()    { [ "$HAVE_GO" = 1 ]    || return 1; quiet go install "$1"; }
apt_install()   { [ "$HAVE_APT" = 1 ] && [ "$HAVE_SUDO" = 1 ] || return 1; quiet sudo -n apt-get install -y -q "$1"; }

# register <command> — mark available
reg_ok()  { OK_TOOLS+=("$1"); }

# ensure <command> <label> <install-fn...> — install if missing, try each method in order
ensure() {
  local cmd="$1"; shift
  local label="$1"; shift
  if have "$cmd"; then reg_ok "$cmd"; return 0; fi
  local fn
  for fn in "$@"; do
    if eval "$fn"; then
      hash -r 2>/dev/null || true
      if have "$cmd"; then
        log "installed: $label"
        ADDED_TOOLS+=("$label")
        reg_ok "$cmd"
        return 0
      fi
    fi
  done
  MISSING_TOOLS+=("$label")
  return 1
}

# ---------------------------------------------------------------- toolchain
log "checking toolchain (target: 100% free & local) ..."

# Core helpers
ensure jq jq \
  'brew_install jq' 'pipx_install jq' 'pip3_install jq' 'apt_install jq'

# SAST engine — official installer only (no brew/pypi formula exists for opengrep).
# Fallback: semgrep community edition (same rule format) if opengrep install fails.
install_opengrep() {
  command -v curl >/dev/null 2>&1 || return 1
  quiet curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash || return 1
  hash -r 2>/dev/null || true
  # installer symlinks into ~/.local/bin — make sure it is usable
  [ -x "$HOME/.local/bin/opengrep" ] && PATH="$HOME/.local/bin:$PATH"
  have opengrep
}
if ! have opengrep; then
  if install_opengrep; then
    log "installed: opengrep (SAST engine)"
    ADDED_TOOLS+=("opengrep"); reg_ok opengrep
  else
    # fallback to semgrep CE (drop-in compatible rules)
    if have semgrep; then
      reg_ok semgrep
      log "opengrep unavailable — will use semgrep (CE) instead"
    elif brew_install semgrep || pipx_install semgrep || pip3_install semgrep; then
      hash -r 2>/dev/null || true
      if have semgrep; then reg_ok semgrep; log "installed: semgrep (CE)"; ADDED_TOOLS+=("semgrep"); fi
    fi
    if ! have opengrep && ! have semgrep; then
      MISSING_TOOLS+=("opengrep (or semgrep)")
    fi
  fi
else
  reg_ok opengrep
fi

# Secrets scanning
install_gitleaks() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install gitleaks && return 0; fi
  command -v curl >/dev/null 2>&1 || return 1
  local ver tar url tmp
  ver="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest 2>/dev/null \
        | grep -m1 '"tag_name"' | sed 's/.*"v\{0,1\}\([^"]*\)".*/\1/')" || return 1
  [ -n "$ver" ] || return 1
  tmp="$(mktemp -d)"
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  tar="gitleaks_${ver}_mac_arm64.tar.gz" ;;
    Darwin-x86_64) tar="gitleaks_${ver}_mac_x64.tar.gz" ;;
    Linux-x86_64)  tar="gitleaks_${ver}_linux_x64.tar.gz" ;;
    Linux-aarch64) tar="gitleaks_${ver}_linux_aarch64.tar.gz" ;;
    *) return 1 ;;
  esac
  url="https://github.com/gitleaks/gitleaks/releases/download/v${ver}/${tar}"
  quiet curl -fsSL "$url" -o "$tmp/$tar" || { rm -rf "$tmp"; return 1; }
  tar -xzf "$tmp/$tar" -C "$tmp" gitleaks 2>/dev/null || { rm -rf "$tmp"; return 1; }
  mkdir -p "$HOME/.local/bin"
  install -m 0755 "$tmp/gitleaks" "$HOME/.local/bin/gitleaks" 2>/dev/null \
    || { cp "$tmp/gitleaks" "$HOME/.local/bin/gitleaks" && chmod 0755 "$HOME/.local/bin/gitleaks"; }
  rm -rf "$tmp"
  PATH="$HOME/.local/bin:$PATH"
  have gitleaks
}
ensure gitleaks gitleaks install_gitleaks

# Dependency / CVE / IaC scanner (also covers secrets + misconfig)
install_trivy() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install trivy && return 0; fi
  if [ "$HAVE_APT" = 1 ] && [ "$HAVE_SUDO" = 1 ]; then apt_install trivy && return 0; fi
  command -v curl >/dev/null 2>&1 || return 1
  quiet curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b "$HOME/.local/bin" >/dev/null 2>&1 || return 1
  PATH="$HOME/.local/bin:$PATH"
  have trivy
}
ensure trivy trivy install_trivy

# OSV dependency scanner (redundant coverage with trivy — belt & braces)
install_osv() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install osv-scanner && return 0; fi
  go_install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest || return 1
  PATH="$(go env GOPATH 2>/dev/null)/bin:$PATH"
  have osv-scanner
}
ensure osv-scanner osv-scanner install_osv

# IaC / cloud misconfiguration
install_checkov() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install checkov && return 0; fi
  pipx_install checkov || pip3_install checkov || return 1
  PATH="$HOME/.local/bin:$PATH"
  have checkov
}
ensure checkov checkov install_checkov

# Language specialists (optional but free)
install_bandit() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install bandit && return 0; fi
  pipx_install bandit || pip3_install bandit || return 1
  PATH="$HOME/.local/bin:$PATH"
  have bandit
}
ensure bandit bandit install_bandit

install_gosec() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install gosec && return 0; fi
  go_install github.com/securego/gosec/v2/cmd/gosec@latest || return 1
  PATH="$(go env GOPATH 2>/dev/null)/bin:$PATH"
  have gosec
}
ensure gosec gosec install_gosec

install_njsscan() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install njsscan && return 0; fi
  pipx_install njsscan || pip3_install njsscan || return 1
  PATH="$HOME/.local/bin:$PATH"
  have njsscan
}
ensure njsscan njsscan install_njsscan

install_shellcheck() {
  brew_install shellcheck && return 0
  apt_install shellcheck && return 0
  return 1
}
ensure shellcheck shellcheck install_shellcheck

install_brakeman() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install brakeman && return 0; fi
  if have gem; then
    quiet gem install --user-install brakeman || return 1
    hash -r 2>/dev/null || true
    have brakeman && return 0
  fi
  return 1
}
ensure brakeman brakeman install_brakeman

install_cppcheck() {
  brew_install cppcheck && return 0
  apt_install cppcheck && return 0
  return 1
}
ensure cppcheck cppcheck install_cppcheck

# Active-phase DAST engine (only used with --live against localhost)
install_nuclei() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install nuclei && return 0; fi
  go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || return 1
  PATH="$(go env GOPATH 2>/dev/null)/bin:$PATH"
  have nuclei
}
ensure nuclei nuclei install_nuclei

# ------------------------------------------------- active offensive toolkit (Phase 2/4)
# Enumeration & live exploitation — all free OSS, same degrade-gracefully contract.
install_ffuf() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install ffuf && return 0; fi
  go_install github.com/ffuf/ffuf/v2@latest || return 1
  PATH="$(go env GOPATH 2>/dev/null)/bin:$PATH"
  have ffuf
}
ensure ffuf ffuf install_ffuf

install_ferox() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install feroxbuster && return 0; fi
  if have cargo; then quiet cargo install feroxbuster && PATH="$HOME/.cargo/bin:$PATH" && have feroxbuster && return 0; fi
  return 1
}
ensure feroxbuster feroxbuster install_ferox

install_httpx() {
  # ProjectDiscovery httpx — go install first (plain `brew install httpx` may hit the
  # unrelated Python HTTP library); fall back to their tap.
  go_install github.com/projectdiscovery/httpx/cmd/httpx@latest && {
    PATH="$(go env GOPATH 2>/dev/null)/bin:$PATH"; have httpx && return 0; }
  [ "$HAVE_BREW" = 1 ] && quiet brew install projectdiscovery/httpx/httpx && hash -r && have httpx && return 0
  have httpx
}
ensure httpx httpx install_httpx

install_katana() {
  go_install github.com/projectdiscovery/katana/cmd/katana@latest && {
    PATH="$(go env GOPATH 2>/dev/null)/bin:$PATH"; have katana && return 0; }
  [ "$HAVE_BREW" = 1 ] && quiet brew install katana && hash -r && have katana && return 0
  have katana
}
ensure katana katana install_katana

install_arjun() {
  pipx_install arjun || pip3_install arjun || return 1
  PATH="$HOME/.local/bin:$PATH"
  have arjun
}
ensure arjun arjun install_arjun

install_sqlmap() {
  if [ "$HAVE_BREW" = 1 ]; then brew_install sqlmap && return 0; fi
  command -v git >/dev/null 2>&1 || return 1
  local dest="$HOME/.local/share/sqlmap"
  [ -d "$dest" ] || quiet git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$dest" || return 1
  mkdir -p "$HOME/.local/bin"
  ln -sf "$dest/sqlmap.py" "$HOME/.local/bin/sqlmap"
  chmod +x "$dest/sqlmap.py" 2>/dev/null || true
  PATH="$HOME/.local/bin:$PATH"
  have sqlmap
}
ensure sqlmap sqlmap install_sqlmap

# ---------------------------------------------------------------- report
export PATH="$HOME/.local/bin:$PATH"
printf '\n[mr-robot:setup] result:\n'
printf '  available (%d): %s\n' "${#OK_TOOLS[@]}" "${OK_TOOLS[*]:-none}"
if [ "${#ADDED_TOOLS[@]}" -gt 0 ]; then
  printf '  newly installed (%d): %s\n' "${#ADDED_TOOLS[@]}" "${ADDED_TOOLS[*]}"
fi
if [ "${#MISSING_TOOLS[@]}" -gt 0 ]; then
  printf '  not installed (%d): %s\n' "${#MISSING_TOOLS[@]}" "${MISSING_TOOLS[*]}"
  printf '  → scans will skip these and continue. Install manually later if wanted.\n'
fi
cat <<'EOF'

NOTE: ensure ~/.local/bin is on your PATH for user-level installs:
  export PATH="$HOME/.local/bin:$PATH"
No accounts, no API keys, no code ever leaves this machine.
EOF

# persist PATH hint for this shell session's parent is not possible; harmless.
if ! have python3; then
  log "error: python3 is required for report merging (macOS: xcode-select --install)"
  exit 1
fi
exit 0
