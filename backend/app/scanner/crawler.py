import re
import time
from collections import deque
from urllib.parse import urljoin, urldefrag, urlsplit
from bs4 import BeautifulSoup
from ..security.targets import same_origin

SKIP_SCHEMES={"mailto","tel","javascript","data"}

def _allowed(url, include_paths, exclude_paths):
    try:path=urlsplit(url).path or "/"
    except (ValueError,UnicodeError):return False
    if exclude_paths and any(re.search(p,path) for p in exclude_paths):
        return False
    if include_paths and not any(re.search(p,path) for p in include_paths):
        return False
    return True

def crawl(start_url,client,max_pages=12,max_depth=2,include_paths=None,exclude_paths=None,delay_ms=0):
    include_paths=include_paths or []
    exclude_paths=exclude_paths or []
    max_pages=max(1,int(max_pages))
    # Failed URLs also consume budget. This prevents a page with thousands of
    # broken links from bypassing the configured successful-page ceiling.
    attempt_limit=max_pages*3
    seen=set();out=[];errors=[];q=deque([(start_url,0,None)]);attempted=0
    while q and len(out)<max_pages and attempted<attempt_limit:
        url,depth,source=q.popleft();url=urldefrag(url)[0]
        if url in seen or not same_origin(start_url,url) or not _allowed(url,include_paths,exclude_paths):continue
        seen.add(url);attempted+=1
        if delay_ms and attempted>1:time.sleep(min(delay_ms,5000)/1000)
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
                    try:
                        parsed=urlsplit(raw)
                        if parsed.scheme.lower() in SKIP_SCHEMES:continue
                        nxt=urldefrag(urljoin(url,raw))[0]
                    except (ValueError,UnicodeError):
                        continue
                    if same_origin(start_url,nxt) and nxt not in seen and _allowed(nxt,include_paths,exclude_paths):
                        discovered.append(nxt)
            # Preserve deterministic discovery order but avoid queue amplification.
            for nxt in dict.fromkeys(discovered):
                if len(q)<attempt_limit*4:q.append((nxt,depth+1,url))
        except Exception as e:
            errors.append({"url":url,"depth":depth,"source_url":source,"error":str(e)[:500]})
    meta={
        "attempted":attempted,
        "successful":len(out),
        "failed":len(errors),
        "attempt_limit":attempt_limit,
        "remaining_discovered":len(q),
        "budget_exhausted":bool(q and attempted>=attempt_limit),
    }
    return out,errors,meta
