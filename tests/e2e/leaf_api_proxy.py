import http.client
import http.server
import socket
import ssl
import sys

listen_ip, token, unix_path, cert, key = sys.argv[1:6]


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=30)
        self.unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.unix_path)
        self.sock = sock


class Handler(http.server.BaseHTTPRequestHandler):
    def forward(self):
        if self.headers.get("Authorization") != "Bearer " + token:
            self.send_error(401)
            return
        if not self.path.startswith("/plugins/mesh/"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        conn = UnixConnection(unix_path)
        conn.request(self.command, self.path[len("/plugins/mesh"):], body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.getheader("Content-Type", "text/plain"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = forward
    do_PUT = forward
    do_DELETE = forward

    def log_message(self, fmt, *args):
        sys.stderr.write("proxy: " + fmt % args + "\n")


server = http.server.ThreadingHTTPServer((listen_ip, 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
