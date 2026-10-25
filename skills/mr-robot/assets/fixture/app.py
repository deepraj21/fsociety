#!/usr/bin/env python3
"""DEMONSTRATION TARGET — INTENTIONALLY VULNERABLE. NEVER DEPLOY.

Stdlib-only teaching app for rehearsing the mr-robot skill against a safe,
local target. Binds 127.0.0.1 exclusively (see HTTPServer below).

Run:  python3 app.py     →   http://127.0.0.1:8766
Stop: Ctrl-C
"""
import argparse
import base64
import hashlib
import os
import pickle
import random
import ssl
import sqlite3
import subprocess
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# --- planted credentials (FAKE — pattern bait for secret scanners) ---------------
AWS_ACCESS_KEY_ID = "AKIAFAKEFAKEFAKEFAKE"          # pattern bait — inert, clearly fake
DEMO_SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vLXVzZXIiLCJhZG1pbiI6dHJ1ZX0.bm90LWFyZWFsLXNpZbmF0dXJl"  # gitleaks: jwt (fake session token)
ADMIN_PASSWORD = "hunter2-demo-only"                 # generic password rule

HOST, PORT = "127.0.0.1", 8766                       # loopback-only by design
BASE = os.path.dirname(os.path.abspath(__file__))

# --- in-memory data ---------------------------------------------------------------
# check_same_thread=False: ThreadingHTTPServer serves concurrent requests and the
# demo DB is process-local in-memory sqlite (no real concurrency risk to guard)
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, balance INTEGER)")
DB.executemany("INSERT INTO users (name, email, balance) VALUES (?, ?, ?)",
               [("alice", "alice@example.test", 100), ("bob", "bob@example.test", 200)])
DB.commit()


class VulnHandler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200, ctype: str = "text/plain"):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            url = urlparse(self.path)
            q = parse_qs(url.query)

            def arg(name, default=""):
                return q.get(name, [default])[0]

            if url.path == "/search":
                # BUG (demo): SQL injection — string-built query
                cur = DB.execute(
                    "SELECT id, name FROM users WHERE name = '" + arg("q") + "'")
                return self._send(repr(cur.fetchall()))

            if url.path == "/run":
                # BUG (demo): command injection — shell metacharacters pass through
                rc = subprocess.call("echo " + arg("cmd", "hello"), shell=True)
                return self._send(f"exit={rc}")

            if url.path == "/read":
                # BUG (demo): path traversal — no canonicalization/prefix check
                with open(os.path.join(BASE, arg("file", "README.md"))) as fh:
                    return self._send(fh.read())

            if url.path == "/render":
                # BUG (demo): code injection via eval
                return self._send(str(eval("1 + " + arg("expr", "1"))))

            if url.path == "/hash":
                # BUG (demo): MD5 for anything security-adjacent
                return self._send(hashlib.md5(arg("pw", "x").encode()).hexdigest())

            if url.path == "/token":
                # BUG (demo): non-cryptographic RNG for session tokens
                return self._send(format(random.random(), ".16f"))

            if url.path == "/state":
                # BUG (demo): unsafe deserialization of attacker-controlled data
                try:
                    obj = pickle.loads(base64.b64decode(arg("data", "")))
                    return self._send(repr(obj))
                except Exception as exc:
                    return self._send(f"decode error: {exc}", 400)

            if url.path == "/admin":
                # BUG (demo): credential compare straight from source
                if arg("password") == ADMIN_PASSWORD:
                    return self._send(f"ok — quota={arg('quota')}", 200, "application/json")
                return self._send("forbidden", 403)

            if url.path == "/echo":
                # BUG (demo): reflected XSS — input echoed unescaped in an HTML context
                return self._send(f"<h1>Hello {arg('name', 'world')}</h1>", 200, "text/html")

            if url.path == "/fetch":
                # BUG (demo): SSRF — server fetches any URL the client supplies.
                # Bounded for the demo: http(s) only, 3s timeout, 64 KiB cap.
                target = arg("url", "http://127.0.0.1:8766/health")
                if not target.startswith(("http://", "https://")):
                    return self._send("only http(s) in this demo", 400)
                try:
                    with urllib.request.urlopen(target, timeout=3) as r:
                        return self._send(r.read(65536).decode("utf-8", "replace"))
                except Exception as exc:
                    return self._send(f"fetch failed: {exc}", 502)

            if url.path == "/user":
                # BUG (demo): IDOR — object returned by id with no ownership check
                try:
                    uid = int(arg("id", "1"))
                except ValueError:
                    return self._send("bad id", 400)
                row = DB.execute(
                    "SELECT id, name, email, balance FROM users WHERE id = ?", (uid,)).fetchone()
                if row is None:
                    return self._send("no such user", 404)
                return self._send(repr(row), 200, "application/json")

            if url.path == "/transfer":
                # BUG (demo): state-changing GET with no CSRF token / Origin check
                # and no amount validation — negative amount credits the sender
                # (CSRF + business-logic in one route)
                try:
                    to_id, amount = int(arg("to", "2")), int(arg("amount", "0"))
                except ValueError:
                    return self._send("bad args", 400)
                DB.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
                DB.execute("UPDATE users SET balance = balance - ? WHERE id = 1", (amount,))
                DB.commit()
                bal = DB.execute("SELECT balance FROM users WHERE id = 1").fetchone()[0]
                return self._send(f"transferred {amount} to user {to_id}; alice balance now {bal}")

            if url.path == "/health":
                return self._send("ok")

            # BUG (demo): verbose errors leak internals
            return self._send("not found", 404)

        except Exception:
            return self._send(traceback.format_exc(), 500)

    def log_message(self, fmt, *args):  # quiet demo server
        pass


def make_tls_context() -> ssl.SSLContext:
    """Self-signed HTTPS for the TLS-audit rehearsal (--tls).

    Cert is generated once into .tls/ (git-ignored): self-signed + long-lived
    by design — testssl findings material for the demo, not real crypto advice.
    """
    tls_dir = os.path.join(BASE, ".tls")
    cert, key = os.path.join(tls_dir, "cert.pem"), os.path.join(tls_dir, "key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        os.makedirs(tls_dir, exist_ok=True)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "3650",
             "-subj", "/CN=localhost/O=mr-robot-demo-fixture"],
            check=True, capture_output=True,
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="intentionally vulnerable mr-robot demo fixture")
    parser.add_argument("--tls", action="store_true",
                        help="serve HTTPS with an auto-generated self-signed cert")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((HOST, PORT), VulnHandler)
    scheme = "http"
    if args.tls:
        httpd.socket = make_tls_context().wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"[demo] intentionally vulnerable fixture on {scheme}://{HOST}:{PORT} (loopback only)")
    httpd.serve_forever()
