import re
import time
from collections import deque
from urllib.parse import urljoin, urldefrag, urlsplit
from bs4 import BeautifulSoup
from ..security.targets import same_origin

SKIP_SCHEMES={"mailto","tel","javascript","data"}

def _allowed(url, include_paths, exclude_paths):
    path=urlsplit(url).path or "/"
    if exclude_paths and any(re.search(p,path) for p in exclude_paths):
        return False
    if include_paths and not any(re.search(p,path) for p in include_paths):
        return False
    return True

def crawl(start_url,client,max_pages=12,max_depth=2,include_paths=None,exclude_paths=None,delay_ms=0):
    include_paths=include_paths or []
    exclude_paths=exclude_paths or []
    seen=set();out=[];q=deque([(start_url,0,None)])
    while q and len(out)<max_pages:
        url,depth,source=q.popleft();url=urldefrag(url)[0]
        if url in seen or not same_origin(start_url,url) or not _allowed(url,include_paths,exclude_paths):continue
        seen.add(url)
        if delay_ms and out:time.sleep(min(delay_ms,5000)/1000)
        try:
            r=client.get(url)
            ctype=r.headers.get("Content-Type","")
            out.append((url,r,depth,source))
            if depth>=max_depth or "text/html" not in ctype.lower():continue
            soup=BeautifulSoup(r.text,"html.parser")
            discovered=[]
            for tag,attr in [("a","href"),("form","action"),("iframe","src")]:
                for node in soup.find_all(tag):
                    raw=node.get(attr)
                    if not raw:continue
                    parsed=urlsplit(raw)
                    if parsed.scheme.lower() in SKIP_SCHEMES:continue
                    nxt=urldefrag(urljoin(url,raw))[0]
                    if same_origin(start_url,nxt) and nxt not in seen and _allowed(nxt,include_paths,exclude_paths):
                        discovered.append(nxt)
            for nxt in discovered:q.append((nxt,depth+1,url))
        except Exception:
            continue
    return out
