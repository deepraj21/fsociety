# 09 — Fuzzing & binary hardening (WSTG-ATHZ-02/CRS · CWE-119/122/242 · CWE-693/1190)

Static analysis proves code *can* be wrong; fuzzing proves a specific build *is* —
a crashing input from the app's own parser is the one memory-safety proof that
survives review. This lane covers two questions scanners never touch: **does the
parser survive hostile input**, and **was the binary built to survive it** (PIE,
NX, RELRO, canary). When phase-1 recon finds a native CLI, a file-format parser
(PDF/image/avif/protobuf/serialized model), a C/C++/Rust core behind a service,
or a Go/Rust binary with an exposed socket, this file is live.

**Active-phase file:** local builds + your own machine only. No remote hosts, no
weaponized payloads — the crash input *is* the finding; developing it into an
exploit is out of scope (Phase 0).

## Lane 1 — mutation fuzzing (marker-grade, deterministic)

```bash
# fuzz the app's parser with the built-in seed corpus (stdin delivery)
node skills/mr-robot/scripts/fuzz-lane.mjs --budget 120 --seed 42 -- ./build/my-parser

# file-based input: '@@' in args is replaced by the input file path (AFL-style)
node skills/mr-robot/scripts/fuzz-lane.mjs --budget 300 --corpus ./seeds -- ./build/imgconv @@

# reproduce a crash exactly (same seed ⇒ same input sequence ⇒ same crash)
node skills/mr-robot/scripts/fuzz-lane.mjs --budget 120 --seed 42 --out run.json -- ./build/my-parser
#   → run.json.crashes/crash-<iter>.bin + .log
```

Engine notes:

- **Built-in mutator** (default — zero deps): seeded mulberry32 PRNG drives 2-ops-per-input
  mutations (bit/byte flips, interesting-value inserts, block insert/delete/dup,
  truncation, length-prefix). Raw seeds run first — a corpus that crashes on load
  is proven at iteration 1, deterministically.
- **Escalation, when installed:** `radamsa` (grammar-blind havoc), `AFL++` /
  `honggfuzz` (coverage-guided — use these when the built-in lane plateaus: any
  input this tool produces is a valid AFL seed), libFuzzer for in-process harnesses.
  Same bounds discipline: time-boxed, corpus in a temp dir, crashes archived.
- **Crash classification:** process killed by signal (SIGSEGV/SIGABRT/…), exit
  ≥128, or sanitizer/panic keywords in output (AddressSanitizer, stack smashing
  detected, panicked at, fatal runtime). Per-run timeout = *hang* — recorded and
  reported as potential DoS but never the verdict on its own.
- **First crash stops the run** (bounded by design): reproduce with the same seed,
  then triage — the tool never sprays thousands of near-duplicate crashes.

## Lane 2 — binary hardening (checksec equivalent)

```bash
node skills/mr-robot/scripts/fuzz-lane.mjs --checksec ./build/my-parser --out checksec.json
```

Reads the binary's own headers — `readelf` (Linux/ELF) or `otool`+`nm` (macOS/Mach-O) —
and reports each property **with its evidence line**; `unknown` is reported rather
than guessed (macOS has no per-binary NX/RELRO flag to read).

| Property | Absent means | Attack it defeats |
|---|---|---|
| PIE | code at fixed addresses → ROP with hardcoded gadgets | ASLR is decorative |
| NX | stack/heap executable → shellcode in input buffers | code-injection via overflow |
| RELRO | lazy GOT writes → overwrite a resolved function pointer | GOT hijack after any write-what-where |
| canary | stack smash returns into attacker frame silently | classic stack-buffer overflow (CWE-121) |

Missing properties are **hardening findings** (severity: low-medium standing
alone; they *upgrade* a memory-safety bug's impact — a no-PIE no-canary crash
becomes `critical`-chainable). Cross-link [03h](03h-memory-safety.md): the source
patterns that make an overflow likely + this lane's proof = the report pair.

## Verify → Prove → Impact

- **Detect:** phase-1 recon — native CLI/daemon in the repo (`makefile`, `CMakeLists`,
  `Cargo.toml` with `[[bin]]`, `go build`, Docker `FROM scratch`/distroless), file
  parsers, exposed sockets; also `--checksec` any shipped binary as a quick pass.
- **Verify:** build with sanitizers for triage-grade signal
  (`-fsanitize=address,undefined` clang/gcc; `-Zsanitizer=address` nightly rustc) —
  the tool's keyword classifier then catches overflows that don't crash a release
  build. Reproduce every crash at the same seed before reporting.
- **Prove:** the crashing input + minimized excerpt + stack trace (sanitizer log)
  belong in the report verbatim — `status: candidate` until the crash reproduces
  twice. **Never** convert the input into a working exploit; the crash *is* the
  evidence.
- **Impact:** unauthenticated DoS (any bad file crashes the service) → tag `dos`;
  crash in a network-reachable parser + missing hardening above = chain candidate
  (`tags: memory-safety, rce-chain` when a write primitive is evident — report as
  candidate, the weaponized step is not ours to take).

## Bounds (Phase 0 — enforced in the script)

| Bound | Value |
|---|---|
| Budget | ≤600 s (default 60) · iterations ≤5000 (default 1000) |
| Per-run timeout | ≤10 s (default 2000 ms) |
| Input size | ≤64 KiB per case |
| Corpus | ≤64 seed files from `--corpus` (+6 built-in seeds) |
| Targets | local executables only — URL/cmd transports and non-loopback URL args refused (exit 3); crash inputs archived (or base64 ≤256B), nothing else written |

Exit: `0` no crash · `1` crash found (candidate — reproduce, triage, do not exploit)
· `2` usage · `3` target/tool unavailable (remote, missing binary, no readelf/otool).

## Reporting

Fuzz findings carry the seed, iteration, crash kind and artifact path; checksec
rows carry the evidence line (e.g. `GNU_STACK flags without E`). Pair each memory
finding with its [06](06-remediation.md) remediation class (bounds checks,
`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, full RELRO, rebuild PIE) and
note whether the vendor's shipped binary differs from the source build.

## References

- AFL++ / honggfuzz / radamsa docs (escalation engines) · libFuzzer guide
- `readelf -h/-lW/-d/-sW` semantics (GNU_STACK/GNU_RELRO/BIND_NOW) · `otool -hv` flags column, `nm` undefined-symbol view
- OWASP WSTG-ATHZ-02 (fuzz testing) · CWE-119/122 (overflow) · CWE-693 (protection mechanism failure) · CWE-1190 (weak hash/PRNG-adjacent binary inputs)
- Cross-links: [03h](03h-memory-safety.md) source patterns · [06](06-remediation.md) hardening checklist · [08](08-local-daemons.md) the daemons that expose parsers on loopback
