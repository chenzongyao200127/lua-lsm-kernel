#!/usr/bin/env python3
"""Credential-injecting proxy for the sandboxed reviewer.

Listens on a private unix socket, forwards each HTTP request to the model
endpoint with the real API key attached, and streams the response back. The
sandbox only ever sees a dummy key and a unix socket, never this process's
environment.
"""

import http.client
import os
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

UPSTREAM_HOST = "dashscope.aliyuncs.com"
UPSTREAM_PORT = 443
TIMEOUT = 900

# Only the OpenAI-compatible endpoint is reachable; anything else is a bug
# or an attempt to spend the credential on some other API.
ALLOWED_PREFIX = "/compatible-mode/v1/"
MAX_BODY = 64 << 20
IDLE_TIMEOUT = 1800

# Request headers we must not copy: the credential is ours to add, and
# framing and connection management are the client library's business.
DROP_REQUEST = {
    "host", "authorization", "content-length", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailer", "transfer-encoding", "upgrade",
}
# Response headers we must not copy: framing and connection management are
# ours to decide.
DROP_RESPONSE = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding",
    "upgrade",
}

_last_activity = time.monotonic()


def touch():
    global _last_activity
    _last_activity = time.monotonic()


class BodyTooLarge(Exception):
    pass


class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("proxy: " + fmt % args + "\n")

    def _body(self):
        length = self.headers.get("Content-Length")
        if length is not None:
            if int(length) > MAX_BODY:
                raise BodyTooLarge
            return self.rfile.read(int(length))
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks, total = [], 0
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                total += size
                if total > MAX_BODY:
                    raise BodyTooLarge
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        return None

    def _reject(self, status):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def _relay(self):
        touch()
        base = ALLOWED_PREFIX.rstrip("/")
        if self.path != base and not self.path.startswith(ALLOWED_PREFIX):
            sys.stderr.write("proxy: refused path %s\n" % self.path)
            self._reject(403)
            return
        try:
            body = self._body()
        except BodyTooLarge:
            self._reject(413)
            return

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in DROP_REQUEST}
        headers["Authorization"] = "Bearer " + API_KEY

        conn = http.client.HTTPSConnection(
            UPSTREAM_HOST, UPSTREAM_PORT, timeout=TIMEOUT)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for key, value in resp.getheaders():
                if key.lower() not in DROP_RESPONSE and \
                        key.lower() != "content-length":
                    self.send_header(key, value)
            self._stream(resp)
        finally:
            conn.close()

    def _stream(self, resp):
        length = resp.getheader("Content-Length")
        if length is not None:
            self.send_header("Content-Length", length)
            self.end_headers()
            while True:
                chunk = resp.read1(65536)
                if not chunk:
                    return
                touch()
                self.wfile.write(chunk)
                self.wfile.flush()
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        while True:
            chunk = resp.read1(65536)
            if not chunk:
                break
            touch()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    do_GET = _relay
    do_POST = _relay


def watch_idle():
    while True:
        time.sleep(30)
        if time.monotonic() - _last_activity > IDLE_TIMEOUT:
            sys.stderr.write("proxy: idle for %ds, exiting\n" % IDLE_TIMEOUT)
            os._exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: proxy.py <unix-socket>\n")
        sys.exit(2)
    sock_path = sys.argv[1]
    API_KEY = os.environ["DASHSCOPE_API_KEY"]
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass
    os.umask(0o077)
    server = UnixHTTPServer(sock_path, Handler)
    os.chmod(sock_path, 0o600)
    threading.Thread(target=watch_idle, daemon=True).start()
    sys.stderr.write("proxy: listening on %s\n" % sock_path)
    server.serve_forever()
