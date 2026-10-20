import os,sys
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

import app.scanner.http_client as hc

class FakeResponse:
    def __init__(self,status=200,headers=None,chunks=None,redirect=False):
        self.status_code=status
        self.headers=headers or {}
        self._chunks=list(chunks or [])
        self.is_redirect=redirect
        self.is_permanent_redirect=False
        self.closed=False
        self._content=b""
        self._content_consumed=False
    def iter_content(self,size,decode_unicode=False):
        yield from self._chunks
    def close(self):
        self.closed=True

class FakeSession:
    def __init__(self,responses):
        self.responses=list(responses);self.headers={};self.closed=False;self.requests=[]
    def request(self,method,url,**kwargs):
        self.requests.append((method,url,kwargs))
        return self.responses.pop(0)
    def close(self):self.closed=True

def test_safe_http_client_closes_redirect_and_truncated_response(monkeypatch):
    monkeypatch.setattr(hc,"validate_target",lambda url,allow_private=False:url)
    redirect=FakeResponse(302,{"Location":"/next"},redirect=True)
    final=FakeResponse(200,{"Content-Type":"text/plain"},[b"abc",b"defgh"])
    client=hc.SafeHttpClient(max_bytes=5)
    fake=FakeSession([redirect,final]);client.session=fake

    response=client.get("https://safe.test/start")
    assert redirect.closed is True
    assert final.closed is True
    assert response._content==b"abcde"
    assert response._sentinel_truncated is True
    assert response._sentinel_captured_bytes==5
    assert response._sentinel_redirects==[{"status":302,"from":"https://safe.test/start","to":"https://safe.test/next"}]
    client.close()
    assert fake.closed is True

def test_safe_http_client_context_manager_closes_session(monkeypatch):
    monkeypatch.setattr(hc,"validate_target",lambda url,allow_private=False:url)
    response=FakeResponse(200,{},[b"ok"])
    client=hc.SafeHttpClient(max_bytes=8)
    fake=FakeSession([response]);client.session=fake
    with client as managed:
        result=managed.get("https://safe.test/")
        assert result._content==b"ok"
    assert fake.closed is True
