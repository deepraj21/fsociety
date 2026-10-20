#!/usr/bin/env bash
# mr-robot — backdoor / webshell / supply-chain implant DETECTOR (passive, read-only).
#
# Scans the project tree (and git history metadata) for patterns that indicate
# planted or accidental backdoors: reverse shells, obfuscated payloads, hostile
# install hooks, tampered git hooks, rogue persistence files.
#
# This script ONLY READS. It never creates, plants or removes anything.
#
# Output: one line per finding —
#   SEVERITY | location | rule-id | description
set -u

TARGET="${1:-.}"
TARGET="$(cd "$TARGET" && pwd)" || exit 2

EXCLUDES=(--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor
          --exclude-dir=.venv --exclude-dir=venv --exclude-dir=.mr-robot
          --exclude-dir=dist --exclude-dir=build --exclude-dir=target
          --exclude-dir=.tox --exclude-dir=__pycache__)

hits=0
emit() { # severity location rule description
  printf '%s | %s | %s | %s\n' "$1" "$2" "$3" "$4"
  hits=$((hits + 1))
}

scan() { # severity rule description pattern
  local sev="$1" rule="$2" desc="$3" pattern="$4"
  # -I: skip binaries, -n: line numbers, -E: extended regex
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    emit "$sev" "${line%%:*}" "$rule" "$desc :: $(printf '%s' "$line" | cut -c1-160)"
  done < <(grep -rIEn -E "$pattern" "${EXCLUDES[@]}" \
            --include='*' --exclude='wordlist-common-passwords.txt' \
            "$TARGET" 2>/dev/null | head -n 50)
}

printf '# mr-robot backdoor scan — target: %s\n' "$TARGET"

# --- 1. Active reverse shells / bind shells ---------------------------------
scan critical REVSHELL-BASH \
  'bash TCP reverse shell primitive' \
  '/dev/tcp/[0-9]+/|bash -i >& /dev/tcp|nc .*(-e|/dev/tcp)'
scan critical REVSHELL-PYTHON \
  'python socket shell primitive' \
  'socket\.socket\(.*\).*(connect|makefile)|pty\.spawn\("(/bin/)?(ba)?sh"\)'
scan critical REVSHELL-NETCAT \
  'netcat bind/reverse shell invocation' \
  'nc(\.traditional)? +(-ll?p|-e) *[0-9]+|ncat .*(--exec|-e)'

# --- 2. Remote-code fetch-and-execute ----------------------------------------
scan critical REMOTE-PIPE-EXEC \
  'download piped directly into a shell (curl|wget | sh)' \
  '(curl|wget)[^|;]{0,200}\| *(ba)?sh|(curl|wget)[^|;]{0,200}\| *python'
scan high REMOTE-FETCH-DECODE \
  'remote payload fetched then base64-decoded/executed' \
  '(curl|wget)[^;]{0,160}(base64|openssl enc)'

# --- 3. Obfuscated code ------------------------------------------------------
scan high OBFUSC-EXEC-DECODE \
  'base64/hex decoded directly into an interpreter' \
  'base64 +(-d|--decode)[^;]{0,80}\| *(ba)?sh|atob\([^)]{0,60}\).{0,40}(eval|Function)|Buffer\.from\([^,]{0,80},\s*.base64.\)\.toString\(\).{0,40}eval'
scan high OBFUSC-LONG-BLOB \
  'very long encoded blob passed to eval/exec (packing indicator)' \
  'eval\(\s*(atob|Buffer\.from|base64)' \
scan high OBFUSC-B64-EXEC \
  'python compile/exec of decoded bytes' \
  'compile\(\s*(base64|codecs)\.(b64decode|decode)|exec\(\s*(base64|codecs)\.(b64decode|decode)'
scan medium OBFUSC-UNICODE-ESCAPE \
  'dense unicode-escaped string (packer/obfuscation indicator)' \
  '(\\u00[0-9a-fA-F]{2}){12,}'
scan medium OBFUSC-FROMCHARCODE \
  'dense String.fromCharCode chains (obfuscation indicator)' \
  '(fromCharCode\((0x[0-9a-fA-F]+|\d+)\s*,?\s*){6,}'

# --- 4. Hostile install / lifecycle hooks ------------------------------------
scan high HOOK-POSTINSTALL-REMOTE \
  'package lifecycle hook running remote/unexpected command' \
  '"(pre|post)(install|publish|pack)"\s*:\s*"[^"]*(curl|wget|nc |chmod \+x|/dev/tcp)' \
  && true
scan high HOOK-PIPE-SH \
  'any shell script pipes a download into a shell' \
  '(curl|wget)[^|]{0,120}\|\s*(sudo\s+)?(ba)?sh'

# --- 5. Persistence files ----------------------------------------------------
scan medium PERSIST-CRON-REBOOT \
  'cron persistence entry inside the repository' \
  '@reboot|^\* *\/[0-9]+ *\* *\* *\*' \
  && true
scan high PERSIST-SSH-KEY \
  'SSH private key material inside the repository' \
  'BEGIN (OPENSSH|RSA|EC|DSA|PuTTY) PRIVATE KEY'

# --- 6. Tampered / live git hooks -------------------------------------------
hook_dir="$TARGET/.git/hooks"
if [ -d "$hook_dir" ]; then
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    emit critical "${h#$TARGET/}" GIT-HOOK-PLANTED \
      "non-sample git hook present — verify it is intentional (pre-commit implant vector)"
  done < <(find "$hook_dir" -maxdepth 1 -type f ! -name '*.sample' 2>/dev/null)
fi

# --- 7. Git history signals (passive metadata only) --------------------------
if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  deleted="$(git -C "$TARGET" log --all --diff-filter=D --name-only --format='--%h' 2>/dev/null | head -n 40)"
  if [ -n "$deleted" ]; then
    emit info '(git history)' GIT-DELETED-FILES \
      "files were deleted in history — review for dropped evidence/secrets: $(printf '%s' "$deleted" | tr '\n' ' ' | cut -c1-300)"
  fi
  stashed="$(git -C "$TARGET" stash list 2>/dev/null | head -n 5)"
  if [ -n "$stashed" ]; then
    emit info '(git stash)' GIT-STASH-PRESENT \
      "stashes exist and may contain unreviewed code: $(printf '%s' "$stashed" | tr '\n' ' ' | cut -c1-200)"
  fi
fi

printf '# done — %d signal(s). Treat each as a CANDIDATE: verify in source before reporting.\n' "$hits"
[ "$hits" -eq 0 ] && printf '# no backdoor indicators found in the tree.\n'
exit 0
