#!/usr/bin/env python3
"""Local lab server for DOXA tests. Binds to 127.0.0.1 only.

It is intentionally misconfigured (missing headers, insecure cookies, exposed files,
directory listing, TRACE, reflective CORS, off-site redirects). Nothing here is a real
vulnerability scanner target outside the loopback interface.
"""
import argparse
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOME = b"""<html><head><title>DOXA Lab</title><meta name="generator" content="LabCMS 1.0"></head>
<body><h1>Lab</h1><a href="/item.php?id=1&amp;q=x">item</a> <a href="/search?q=test">search</a></body></html>"""


class Lab(BaseHTTPRequestHandler):
    server_version = "LabServer/1.2.3"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    requests_seen = []
    root_redirect = False

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body=b"", ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        Lab.requests_seen.append(self.path)
        q = parse_qs(u.query)
        if p == "/" and Lab.root_redirect:
            self._send(302, b"", extra=[("Location", "home"), ("Set-Cookie", "PHPSESSID=REDIRSECRET1; path=/"),
                                          ("Set-Cookie", "PHPSESSID=REDIRSECRET2; path=/"), ("Set-Cookie", "security=low")])
        elif p == "/home":
            self._send(200, HOME)
        elif p == "/":
            self._send(200, HOME, extra=[("Set-Cookie", "sid=SECRETVALUE123; Path=/"),
                                           ("Set-Cookie", "pref=1; Path=/; HttpOnly; Secure; SameSite=Lax"),
                                           ("X-Powered-By", "PHP/5.6.40")])
        elif p == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", "text/plain")
        elif p == "/sitemap.xml":
            self._send(200, b"<urlset><url><loc>http://lab/a</loc></url></urlset>", "application/xml")
        elif p == "/.env":
            self._send(200, b"DB_PASSWORD=hunter2hunter2\nAPP_KEY=base64:abcdef\nDEBUG=true\n", "text/plain")
        elif p == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n", "text/plain")
        elif p == "/phpinfo.php":
            self._send(200, b"<html><title>phpinfo()</title><body>PHP Version 5.6.40</body></html>")
        elif p == "/backup/":
            self._send(200, b"<html><head><title>Index of /backup/</title></head><body><h1>Index of /backup/</h1>"
                            b"<a href='old.zip'>old.zip</a></body></html>")
        elif p == "/redirect-in":
            self._send(302, b"", extra=[("Location", "/")])
        elif p == "/redirect-out":
            self._send(302, b"", extra=[("Location", "http://evil.invalid/steal")])
        elif p == "/redirect-port":
            self._send(302, b"", extra=[("Location", "http://127.0.0.1:1/other-port")])
        elif p == "/redirect-loop":
            self._send(302, b"", extra=[("Location", "/redirect-loop")])
        elif p == "/redirect-chain":
            n = int(q.get("n", ["0"])[0])
            self._send(302, b"", extra=[("Location", "/redirect-chain?n=%d" % (n + 1))])
        elif p == "/slow":
            time.sleep(6)
            self._send(200, b"slow")
        elif p == "/item.php":
            ident = q.get("id", [""])[0]
            if "'" in ident:
                self._send(200, b"You have an error in your SQL syntax; check the manual near ''' at line 1")
            else:
                self._send(200, b"<html>item " + ident.encode() + b"</html>")
        elif p == "/search":
            term = q.get("q", [""])[0]
            self._send(200, ("<html>results for " + term + "</html>").encode())
        else:
            self._send(404, b"<html>not found</html>")

    def do_OPTIONS(self):
        self._send(200, b"", extra=[("Allow", "GET, HEAD, OPTIONS, PUT, DELETE")])

    def do_TRACE(self):
        body = ("TRACE %s\r\n" % self.path).encode()
        for k, v in self.headers.items():
            body += ("%s: %s\r\n" % (k, v)).encode()
        self._send(200, body, "message/http")

    do_HEAD = do_GET


def serve(port, ctx=None):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Lab)
    if ctx:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--http-port", type=int, required=True)
    ap.add_argument("--https-port", type=int)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--root-redirect", action="store_true")
    a = ap.parse_args()
    Lab.root_redirect = a.root_redirect
    serve(a.http_port)
    if a.https_port:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.key)
        serve(a.https_port, ctx)
    print("ready", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
