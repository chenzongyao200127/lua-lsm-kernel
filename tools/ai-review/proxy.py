#!/usr/bin/env python3
"""Credential-injecting proxy for the sandboxed reviewer.

Listens on a unix socket, forwards each HTTP request to the model endpoint
with the real API key attached, and streams the response back. The sandbox
only ever sees a dummy key and a unix socket, never this process's env.
"""

import http.client
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler

UPSTREAM_HOST = "dashscope.aliyuncs.com"
UPSTREAM_PORT = 443
TIMEOUT = 900

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


class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("proxy: " + fmt % args + "\n")

    def _body(self):
        length = self.headers.get("Content-Length")
        if length is not None:
            return self.rfile.read(int(length))
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        return None

    def _relay(self):
        body = self._body()
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
                self.wfile.write(chunk)
                self.wfile.flush()
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        while True:
            chunk = resp.read1(65536)
            if not chunk:
                break
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    do_GET = _relay
    do_POST = _relay


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
    server = UnixHTTPServer(sock_path, Handler)
    sys.stderr.write("proxy: listening on %s\n" % sock_path)
    server.serve_forever()
