from collections import deque
from urllib.parse import urljoin, urldefrag
from bs4 import BeautifulSoup
from ..security.targets import same_origin

def crawl(start_url, client, max_pages=12, max_depth=2):
    seen=set(); out=[]; q=deque([(start_url,0)])
    while q and len(out)<max_pages:
        url,depth=q.popleft(); url=urldefrag(url)[0]
        if url in seen or not same_origin(start_url,url): continue
        seen.add(url)
        try:
            r=client.get(url)
            ctype=r.headers.get("Content-Type","")
            out.append((url,r))
            if depth>=max_depth or "text/html" not in ctype: continue
            soup=BeautifulSoup(r.text,"html.parser")
            for tag in soup.find_all("a",href=True):
                nxt=urldefrag(urljoin(url,tag.get("href")))[0]
                if same_origin(start_url,nxt) and nxt not in seen: q.append((nxt,depth+1))
        except Exception:
            continue
    return out
