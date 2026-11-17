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
<body><h1>Lab</h1><a href="/item.php?id=1&amp;q=x">item</a> <a href="/search?q=test">search</a>
<script src="/static/app.js"></script>
<script src="/static/lib/jquery.min.js"></script>
<script src="https://cdn.example.org/lib.js"></script>
<script src="https://cdn.example.org/sri.js" integrity="sha384-abc" crossorigin="anonymous"></script>
<script src="http://cdn.example.org/mixed.js"></script>
</body></html>"""

APP_JS = b"""// lab application bundle (intentionally contains fake secrets for DOXA tests)
const aws = "AKIAABCDEFGHIJKLMNOP";
const stripe = "sk_live_abcdefghijklmnop1234";
const cfg = { password: "S3cr3tPassw0rd!", apiKey: "YOUR_API_KEY_HERE" };
const tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";
const gkey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
fetch("/api/Challenges");
fetch("/api/private");
const adminCfg = "/api/admin/config";
axios.get("/rest/products/search?q=");
const loginUrl = "/rest/user/login";
const templ = "/api/users/{id}";
const assetPath = "/assets/logo.png";
const t = "http://insecure.example.org/track.js";
eval(userInput);
document.write("<b>x</b>");
document.getElementById("o").innerHTML = location.hash;
//# sourceMappingURL=app.js.map
"""

JQUERY = b"/*! jQuery v1.12.4 */ function f(a){ return eval(a); } el.innerHTML = x; document.write('x');"

SWAGGER = b"""{"openapi":"3.0.0","info":{"title":"Lab API","version":"1"},
"paths":{"/api/users":{"get":{}},"/api/orders/{id}":{"get":{}},"/api/Challenges":{"get":{}}}}"""


class Lab(BaseHTTPRequestHandler):
    server_version = "LabServer/1.2.3"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    requests_seen = []
    root_redirect = False
    request_log = None

    def log_message(self, *a):  # quiet
        pass

    def parse_request(self):
        ok = super().parse_request()
        if ok and Lab.request_log:
            with open(Lab.request_log, "a") as fh:
                fh.write("%s %s\n" % (self.command, self.path))
        return ok

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
        elif p == "/static/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif p == "/static/app.js.map":
            self._send(200, b'{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}', "application/json")
        elif p == "/static/lib/jquery.min.js":
            self._send(200, JQUERY, "application/javascript")
        elif p == "/api/" or p == "/api":
            self._send(200, b'{"message":"Lab API","version":1}', "application/json")
        elif p == "/api/users":
            self._send(200, b'[{"id":1,"email":"admin@x.test","role":"admin"}]', "application/json")
        elif p == "/api/admin/config":
            self._send(200, b'{"debug":true,"secretName":"x","dbHost":"internal-db"}', "application/json")
        elif p == "/api/Challenges":
            self._send(200, b'{"status":"success","data":[{"name":"c1"}]}', "application/json")
        elif p == "/rest/products/search":
            self._send(200, b'{"status":"success","data":[]}', "application/json")
        elif p == "/api/private":
            self._send(401, b'{"error":"unauthorized"}', "application/json", extra=[("WWW-Authenticate", 'Basic realm="lab"')])
        elif p == "/swagger.json":
            self._send(200, SWAGGER, "application/json")
        elif p == "/graphql":
            qs = q.get("query", [""])[0]
            if "__schema" in qs:
                self._send(200, b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}', "application/json")
            elif "__typename" in qs:
                self._send(200, b'{"data":{"__typename":"Query"}}', "application/json")
            else:
                self._send(400, b'{"errors":[{"message":"Must provide query string."}]}', "application/json")
        elif p.startswith("/api/") or p.startswith("/rest/"):
            self._send(404, b'{"error":"Not Found","stack":"Error: Not Found\\n    at Layer.handle (/app/node_modules/express/lib/router/layer.js:95:5)"}', "application/json")
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
    ap.add_argument("--request-log")
    a = ap.parse_args()
    Lab.root_redirect = a.root_redirect
    Lab.request_log = a.request_log
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
