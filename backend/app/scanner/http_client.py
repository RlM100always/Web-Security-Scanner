import time
import requests
from urllib.parse import urljoin
from ..security.targets import validate_target

class SafeHttpClient:
    def __init__(self,timeout=8,max_bytes=2_000_000,allow_private=False):
        self.timeout=timeout;self.max_bytes=max(1,int(max_bytes));self.allow_private=allow_private
        self.session=requests.Session()
        self.session.headers.update({"User-Agent":"SentinelScope/1.0 authorised-security-assessment"})
    def get(self,url,**kwargs):return self._request("GET",url,**kwargs)
    def head(self,url,**kwargs):return self._request("HEAD",url,**kwargs)
    def options(self,url,**kwargs):return self._request("OPTIONS",url,**kwargs)
    def close(self):self.session.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def _request(self,method,url,**kwargs):
        started=time.perf_counter();current=validate_target(url,self.allow_private);redirects=[]
        for _ in range(6):
            # Revalidate immediately before every network hop, not only the original URL.
            current=validate_target(current,self.allow_private)
            r=self.session.request(method,current,timeout=self.timeout,allow_redirects=False,stream=True,**kwargs)
            if r.is_redirect or r.is_permanent_redirect:
                try:
                    location=r.headers.get("Location","")
                    if not location:raise requests.TooManyRedirects("Redirect response did not include a Location header")
                    nxt=validate_target(urljoin(current,location),self.allow_private)
                    redirects.append({"status":r.status_code,"from":current,"to":nxt});current=nxt
                finally:
                    r.close()
                continue
            truncated=False
            if method!="HEAD":
                chunks=[];total=0
                try:
                    for chunk in r.iter_content(65536,decode_unicode=False):
                        if not chunk:continue
                        remaining=self.max_bytes-total
                        if remaining<=0:
                            truncated=True;break
                        if len(chunk)>remaining:
                            chunks.append(chunk[:remaining]);total+=remaining;truncated=True;break
                        chunks.append(chunk);total+=len(chunk)
                finally:
                    if truncated:r.close()
                r._content=b"".join(chunks);r._content_consumed=True
            r._sentinel_redirects=redirects
            r._sentinel_truncated=truncated
            r._sentinel_elapsed_ms=round((time.perf_counter()-started)*1000)
            r._sentinel_captured_bytes=len(getattr(r,"_content",b"") or b"")
            return r
        raise requests.TooManyRedirects("Too many redirects")
