# 03h — Memory safety lane (C/C++/Rust/Go · CWE Top 25 #5–#17)

Load only when Phase 1 found C/C++ sources, Rust `unsafe`, or Go `unsafe`/cgo.

## What applies where

| Lang | Exposure | Primary tools (all free) |
|---|---|---|
| C/C++ | buffer overflows (CWE-120/121/122/787), UAF (416), null-deref (476), format strings | cppcheck (in scan-all), flawfinder, ASan/UBSan builds |
| Rust | safe by default → audit `unsafe {}` blocks, FFI, `unsafe impl Send/Sync`, unwrap-in-prod paths (panic→DoS) | cargo audit/geiger, manual `unsafe` review |
| Go | gosec findings (in scan-all), integer conversion truncation, goroutine leaks, `unsafe`/cgo boundaries | gosec, staticcheck, RUSTSEC-style advisories via govulncheck (optional) |

## Detection (automatic in scan-all.sh)

- `cppcheck --enable=warning,performance,portability` on `*.c/cpp/cc/h` → findings.json.
- `gosec` when `go.mod` present → findings.json (incl. `G204` command exec, `G104` ignored
  errors, `G115` integer overflow — CWE-190).
- Add manually if installed: `flawfinder -j .` (C/C++ CWE grep with risk ranks),
  `staticcheck ./...` (Go), `govulncheck ./...` (reachable CVEs — free, local),
  `cargo audit` (Rust advisories, local DB).

## Verification (this is where you add value — tools over-report)

For each candidate:

1. **Reachability:** is the affected function called with attacker-influenced data
   (network packet, file, IPC)? Irreachable → rejected.
2. **Exploitability:** bounded copy (`strncpy`/`sizeof`-checked) vs unbounded
   (`strcpy/sprintf/gets/memcpy(len_from_packet)`)? If bounds provably checked → note
   and reject with evidence.
3. **Mitigations** (affects severity, not existence): stack canaries, ASLR, PIE, FORTIFY,
   `-D_FORTIFY_SOURCE` in the build files — record what the *build* enables.

## Proof discipline (local binaries only)

- Compile with sanitizers and run your input — ASan/UBSan report **is** the PoC:
  ```bash
  cmake -B build -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g" -DCMAKE_BUILD_TYPE=Debug
  cmake --build build && ./build/target < poc-input
  ```
  The ASan trace (heap-buffer-overflow at file:line) proves the class without exploiting it.
- Never produce weaponized shellcode/ROP chains — ASan/UBSan/gdb backtrace is sufficient
  evidence for the report; severity comes from reachability × impact × mitigations.
- Race/UAF candidates: run under `TSAN` (`-fsanitize=thread`) or helgrind, same rule.

## Report mapping (severity anchors from CWE Top 25 2025)

- #5 OOB-write / #9 OS-command / #10 code-injection reachable from input → **critical** candidates (`rce` tag).
- #6 path traversal, #12 unrestricted upload, #15 insecure deserialization → high (→ 03a/03c lanes).
- #7 UAF, #8 OOB-read (info leak), #13 null-deref (DoS) → high/medium by reachability.
- #25 unbounded allocation → medium (CWE-770, → 03g DoS section).
- Rust `unsafe` review findings without a concrete bug → advisory, low, unless data can
  invalidate invariants (then model it as soundness hole, medium-high).
