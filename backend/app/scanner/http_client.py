import requests
from urllib.parse import urljoin
from ..security.targets import validate_target

class SafeHttpClient:
    def __init__(self, timeout=8, max_bytes=2_000_000, allow_private=False):
        self.timeout=timeout; self.max_bytes=max_bytes; self.allow_private=allow_private
        self.session=requests.Session(); self.session.headers.update({"User-Agent":"Academic-Web-Security-Scanner/1.0 (+authorised-testing-only)"})
    def get(self,url,**kwargs): return self._request("GET",url,**kwargs)
    def head(self,url,**kwargs): return self._request("HEAD",url,**kwargs)
    def options(self,url,**kwargs): return self._request("OPTIONS",url,**kwargs)
    def _request(self,method,url,**kwargs):
        current=validate_target(url,self.allow_private)
        for _ in range(6):
            r=self.session.request(method,current,timeout=self.timeout,allow_redirects=False,stream=True,**kwargs)
            if r.is_redirect or r.is_permanent_redirect:
                nxt=urljoin(current,r.headers.get("Location","")); current=validate_target(nxt,self.allow_private); continue
            if method=="HEAD": return r
            chunks=[]; total=0
            for chunk in r.iter_content(65536,decode_unicode=False):
                total+=len(chunk)
                if total>self.max_bytes: break
                chunks.append(chunk)
            r._content=b"".join(chunks); r._content_consumed=True
            return r
        raise requests.TooManyRedirects("Too many redirects")
