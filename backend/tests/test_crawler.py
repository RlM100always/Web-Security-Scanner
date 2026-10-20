import os,sys
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app.scanner.crawler import crawl

class Response:
    def __init__(self,text="",ctype="text/html"):
        self.text=text;self.headers={"Content-Type":ctype}

class Client:
    def __init__(self):self.calls=[]
    def get(self,url):
        self.calls.append(url)
        if url.endswith("/"):
            links="".join(f'<a href="/broken-{i}">x</a>' for i in range(50))
            return Response("<html><body>"+links+"</body></html>")
        raise RuntimeError("simulated route failure")

def test_failed_routes_consume_crawler_attempt_budget():
    client=Client()
    pages,errors,meta=crawl("https://example.com/",client,max_pages=2,max_depth=2)
    assert len(pages)==1
    assert len(errors)==5
    assert meta["attempted"]==6
    assert meta["attempt_limit"]==6
    assert meta["budget_exhausted"] is True
    assert meta["remaining_discovered"]>0
    assert len(client.calls)==6

def test_crawler_ignores_malformed_and_duplicate_discovery():
    class SafeClient:
        def __init__(self):self.calls=[]
        def get(self,url):
            self.calls.append(url)
            if len(self.calls)==1:
                return Response('<a href="/next">one</a><a href="/next">dup</a><a href="https://example.com:not-a-port/bad">bad</a>')
            return Response("done","text/plain")
    client=SafeClient()
    pages,errors,meta=crawl("https://example.com/",client,max_pages=5,max_depth=2)
    assert len(pages)==2
    assert not errors
    assert client.calls==["https://example.com/","https://example.com/next"]
