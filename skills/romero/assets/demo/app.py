#!/usr/bin/env python3
"""DEMONSTRATION TARGET — INTENTIONALLY LOOSE. NEVER DEPLOY.

Stdlib-only fixture for rehearsing the romero skill: one page load exercises
storage writes, JSON/form APIs, an Authorization header, a bearer JWT, a
redirect, SSE, a WebSocket, and a third-party (localhost) subresource.

Binds 127.0.0.1 exclusively. Port 8767 (mr-robot's fixture uses 8766).

Run:  python3 app.py       →   http://127.0.0.1:8767
Stop: Ctrl-C
"""
import argparse
import base64
import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST, PORT = "127.0.0.1", 8767
BASE = os.path.dirname(os.path.abspath(__file__))
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept(key: str) -> str:
    dig = hashlib.sha1((key + WS_GUID).encode()).digest()
    return base64.b64encode(dig).decode()


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):  # quiet
        pass

    def _send(self, body, ctype="text/html", status=200, extra=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------- WebSocket
    def _ws_send(self, payload: bytes):
        hdr = bytes([0x81])
        n = len(payload)
        if n < 126:
            hdr += bytes([n])
        elif n < 65536:
            hdr += bytes([126]) + n.to_bytes(2, "big")
        else:
            hdr += bytes([127]) + n.to_bytes(8, "big")
        self.wfile.write(hdr + payload)
        self.wfile.flush()

    def _ws_session(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept(key))
        self.end_headers()
        self._ws_send(b"hello-from-server")
        self.connection.settimeout(6)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                hdr = self.rfile.read(2)
                if len(hdr) < 2:
                    break
                opcode = hdr[0] & 0x0F
                ln = hdr[1] & 0x7F
                if ln == 126:
                    ln = int.from_bytes(self.rfile.read(2), "big")
                elif ln == 127:
                    ln = int.from_bytes(self.rfile.read(8), "big")
                masked = (hdr[1] & 0x80) != 0
                mask = self.rfile.read(4) if masked else b""
                data = self.rfile.read(ln) if ln else b""
                if masked and data:
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                if opcode == 0x8:      # close
                    break
                if opcode == 0x1:      # text → echo (marker round-trip)
                    self._ws_send(b"echo:" + data[:120])
            except Exception:
                break
        self.close_connection = True

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        url = urlparse(self.path)
        p, qs = url.path, parse_qs(url.query)

        if self.headers.get("Upgrade", "").lower() == "websocket":
            if p == "/ws":
                self._ws_session()
                return
            self._send("bad ws path", status=400)
            return

        if p == "/":
            self._send(open(os.path.join(BASE, "index.html"), "rb").read(),
                       extra=[("Set-Cookie", "demo_sid=loose-cookie; Path=/"),
                              ("Set-Cookie", "trackid=abc-demo; Path=/; SameSite=Lax")])
        elif p == "/api/user":
            self._send(json.dumps({"user": "alice", "role": "admin",
                                   "auth": (self.headers.get("Authorization") or "")[:40]}),
                       "application/json",
                       extra=[("Set-Cookie", "session=demo-session-token; Path=/")])
        elif p == "/api/ping":
            self._send(json.dumps({"pong": int(time.time())}), "application/json")
        elif p == "/events":                      # SSE — 3 events then close
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for i in range(3):
                self.wfile.write(
                    f"id: {i}\nevent: demo\ndata: {{\"seq\": {i}, \"note\": \"romero-sse\"}}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.15)
            self.close_connection = True
        elif p == "/redir":
            self._send("", status=302, extra=[("Location", "/final-page")])
        elif p == "/final-page":
            self._send("<h1>you were redirected</h1>")
        elif p == "/pixel.gif":
            self._send(b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00!", "image/gif")
        else:
            self._send("not found", status=404)

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        url = urlparse(self.path)
        if url.path == "/api/track":
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            fields = parse_qs(body)
            self._send(json.dumps({"ok": True, "seen": sorted(fields.keys())}),
                       "application/json")
        else:
            self._send("not found", status=404)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="romero demo fixture (loose by design)")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    print(f"[demo] romero fixture on http://{HOST}:{args.port} (loopback only)", flush=True)
    ThreadingHTTPServer((HOST, args.port), DemoHandler).serve_forever()
