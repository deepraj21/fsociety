#!/usr/bin/env python3
"""DEMONSTRATION TARGET — INTENTIONALLY VULNERABLE. NEVER DEPLOY.

Stdlib-only teaching app for rehearsing the mr-robot skill against a safe,
local target. Binds 127.0.0.1 exclusively (see HTTPServer below).

Run:  python3 app.py     →   http://127.0.0.1:8766
Stop: Ctrl-C
"""
import base64
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# --- planted credentials (FAKE — pattern bait for secret scanners) ---------------
AWS_ACCESS_KEY_ID = "AKIAFAKEFAKEFAKEFAKE"          # pattern bait — inert, clearly fake
DEMO_SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vLXVzZXIiLCJhZG1pbiI6dHJ1ZX0.bm90LWFyZWFsLXNpZbmF0dXJl"  # gitleaks: jwt (fake session token)
ADMIN_PASSWORD = "hunter2-demo-only"                 # generic password rule

HOST, PORT = "127.0.0.1", 8766                       # loopback-only by design
BASE = os.path.dirname(os.path.abspath(__file__))

# --- in-memory data ---------------------------------------------------------------
DB = sqlite3.connect(":memory:")
DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
DB.executemany("INSERT INTO users (name, email) VALUES (?, ?)",
               [("alice", "alice@example.test"), ("bob", "bob@example.test")])
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

            if url.path == "/health":
                return self._send("ok")

            # BUG (demo): verbose errors leak internals
            return self._send("not found", 404)

        except Exception:
            return self._send(traceback.format_exc(), 500)

    def log_message(self, fmt, *args):  # quiet demo server
        pass


if __name__ == "__main__":
    print(f"[demo] intentionally vulnerable fixture on http://{HOST}:{PORT} (loopback only)")
    HTTPServer((HOST, PORT), VulnHandler).serve_forever()
