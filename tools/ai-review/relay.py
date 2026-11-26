#!/usr/bin/env python3
"""TCP-to-unix relay that runs inside the sandbox.

The sandbox has no network route; this exposes the host-side proxy's unix
socket as 127.0.0.1:<port> so the agent can reach the model endpoint and
nothing else.
"""

import socket
import sys
import threading


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: relay.py <port> <unix-socket>\n")
        return 2
    port, path = int(sys.argv[1]), sys.argv[2]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            up.connect(path)
        except OSError:
            conn.close()
            continue
        threading.Thread(target=pump, args=(conn, up), daemon=True).start()
        threading.Thread(target=pump, args=(up, conn), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
