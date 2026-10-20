# 01 — Reconnaissance: map the attack surface before touching anything

Goal: an **attack-surface map** that tells you where to aim in Phases 2–4. Fast, passive,
no requests sent. Output this as a short section in REPORT.md or your working notes.

## 1. Identify the stack (read manifests, don't guess)

| Signal | Tells you |
|---|---|
| `package.json` (`dependencies`) | Express/Nest/Next/Fastify…; add `lockfile` → supply-chain lane |
| `requirements.txt` / `pyproject.toml` | Django/Flask/FastAPI/asyncio; SQL libs (SQLAlchemy, psycopg) |
| `go.mod` | net/http or gin/echo/chi; gosec lane |
| `Gemfile` | Rails (brakeman lane) or Sinatra |
| `pom.xml` / `build.gradle` | Spring/Java — add deserialization + XML lane |
| `Cargo.toml` | Rust — `unsafe` blocks, RUSTSEC lane |
| `composer.json` | Laravel/Symfony — phar deserialization attention |
| `Dockerfile`, `docker-compose*.yml`, `*.tf`, `k8s/*.yaml` | misconfig/IaC lane (checkov/trivy) |
| `.github/workflows/` | CI/CD tampering, secret exposure, script injection |
| `*.env*`, `config/` | secret handling, debug flags |

Record runtime versions — outdated runtimes (EOL Node/Python/PHP) are findings
themselves (A03:2025).

## 2. Enumerate entry points

Find where attacker input enters:

```bash
# HTTP routes — common frameworks
grep -rnE "app\.(get|post|put|delete|patch|all)\(|@app\.(route|get|post)|@router\.|Route::|router\.(get|post|use)" --include='*.{js,ts,py,rb,go,php}' . | head -50
# Express/Nest controllers, Django urls/views, Flask routes, Rails config/routes.rb
# CLI parsing
grep -rnE "argparse|click\.|commander|yargs|process\.argv|cobra" --include='*.{py,js,ts,go}' . | head -30
# workers / queues / cron / websockets / uploads / webhooks / graphql resolvers
grep -rnE "add_job|celery|bull|sidekiq|worker|ws\.|WebSocket|graphql|resolvers|upload|webhook" . | head -40
```

For each entry point note: method, params (query/body/header/path/cookie/file),
auth required?, and which interpreter it can reach.

## 3. Mark trust boundaries

Where does untrusted data get **interpreted**?

- string-concatenated SQL / ORM raw queries (`.raw(`, `text(`, `execute(f"`, `$query{}`)
- shell/`exec`/`system`/`child_process`/`subprocess`
- template rendering of raw input (`|safe`, `innerHTML`, `{{{ }}}`, `Markup(`)
- deserialization (`pickle`, `yaml.load`, `unserialize`, `ObjectInputStream`)
- URL fetches (`requests.get(user_url)`, `fetch`, `axios.get`, webhook senders)
- file path joins with user input (`open(base + user)`, `path.join`, `send_file`)
- eval-like sinks (`eval`, `Function(`, `vm.runInNewContext`, `assert_equal` no…)

## 4. Inventory the gateways (these are your Phase-4 targets)

| Gateway | Where to look | Bypass test catalog |
|---|---|---|
| Authentication | middleware (`authenticate`, `login_required`, JWT verify), session store | 03b |
| Authorization / RBAC | policy/permission classes, `@roles`, ownership checks | 03b |
| Rate limiting | `express-rate-limit`, nginx `limit_req`, API gateway quotas | 03b |
| CSRF | csrf middleware, SameSite cookies | 03b |
| CORS | `Access-Control` config, wildcard origins | 03b |
| Proxy / WAF / API gateway | nginx/traefik/Cloudflare config in repo | 03b |
| Input validation layer | schema validation (zod, pydantic, marshmallow) — know what it *does* block | 03a |
| Logging & alerting | audit logs, failed-auth logs, alert rules | 03d (A09 check) |

## 5. Detect AI/LLM surfaces (activates 03f)

```bash
grep -rnE "openai|anthropic|claude|langchain|llama|ollama|@ai-sdk|text-generation|embeddings|retriev" . | head -30
```
Note: model calls, tool/function definitions, RAG data sources, agent loops, memory.

## 6. Threat-model on paper (10 min, high leverage)

For each entry point: *what's the worst a malicious user does with it?* Rank by
(impact × reachability). This ranking seeds Phase 3's verification order.

## Output shape

```
STACK: … | ENTRY POINTS: n | GATEWAYS: … | LLM: yes/no
TOP-5 PRIORITIES: (entry → interpreter → why likely)
CATALOGS LOADED: 03a, 03b, 03c, 03g, (03f), (03h)
```
