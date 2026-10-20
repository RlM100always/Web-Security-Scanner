from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import urlsplit,parse_qs
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        p=urlsplit(self.path); secure=p.path.startswith('/secure'); q=parse_qs(p.query).get('q',[''])[0]
        body=f'''<!doctype html><html><head><title>{'Secure' if secure else 'Insecure'} Demo</title></head><body><h1>{'Secure' if secure else 'Insecure'} demo</h1><a href="/{'secure' if secure else 'insecure'}/about">About</a><form method="post"><input name="csrf_token" value="demo" type="hidden"><input name="name"></form>{('<p>'+q+'</p>') if (q and not secure) else ''}{'<!-- TODO remove demo comment -->' if not secure else ''}</body></html>'''.encode()
        self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
        if secure:
            self.send_header('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'");self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','strict-origin-when-cross-origin');self.send_header('Permissions-Policy','camera=(), microphone=()');self.send_header('Set-Cookie','session=demo; HttpOnly; SameSite=Strict; Secure')
        else:self.send_header('Server','DemoServer/0.1')
        self.end_headers();self.wfile.write(body)
    def do_POST(self): self.do_GET()
print('Demo targets: http://127.0.0.1:8090/secure and /insecure')
HTTPServer(('127.0.0.1',8090),H).serve_forever()
