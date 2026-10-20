import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

import app.preflight as pf
from app.repository import Repository

class FakeResponse:
    def __init__(self,status=200,ctype="text/html"):
        self.status_code=status
        self.url="https://example.com/app"
        self.headers={"Content-Type":ctype}
        self._sentinel_redirects=[{"status":301,"from":"https://example.com/","to":"https://example.com/app"}]
        self._sentinel_elapsed_ms=87
        self._sentinel_truncated=False

class FakeClient:
    def __init__(self,*a,**k):pass
    def get(self,url):return FakeResponse()

def patch_network(monkeypatch,status=200,ctype="text/html"):
    monkeypatch.setattr(pf,"validate_target",lambda url,allow_private=False:url)
    monkeypatch.setattr(pf.socket,"getaddrinfo",lambda *a,**k:[(2,1,6,"",("93.184.216.34",0))])
    class Client(FakeClient):
        def __init__(self,*args,**kwargs):self.closed=False
        def get(self,url):return FakeResponse(status,ctype)
        def close(self):self.closed=True
    monkeypatch.setattr(pf,"SafeHttpClient",Client)
    monkeypatch.setattr(pf,"_tls_details",lambda *a,**k:{"protocol":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384","expires_at":"Jan 1 00:00:00 2028 GMT","days_remaining":400})

def test_ready_preflight_is_bounded_and_explainable(monkeypatch):
    patch_network(monkeypatch)
    result=pf.run_target_preflight({"url":"https://example.com/","verified":True},"standard")
    assert result["status"]=="READY"
    assert result["status_code"]==200
    assert result["resolved_addresses"]==["93.184.216.34"]
    keys={x["key"] for x in result["checks"]}
    assert {"safe_destination","dns","reachability","redirects","https","tls","profile_eligibility","response_budget"}<=keys

def test_lab_preflight_blocks_unverified_target(monkeypatch):
    patch_network(monkeypatch)
    result=pf.run_target_preflight({"url":"https://example.com/","verified":False},"lab")
    assert result["status"]=="BLOCKED"
    row=next(x for x in result["checks"] if x["key"]=="lab_eligibility")
    assert row["status"]=="BLOCKED"

def test_restricted_http_visibility_is_warning_not_fake_failure(monkeypatch):
    patch_network(monkeypatch,status=403)
    result=pf.run_target_preflight({"url":"https://example.com/","verified":True},"standard")
    assert result["status"]=="WARN"
    reach=next(x for x in result["checks"] if x["key"]=="reachability")
    assert reach["status"]=="WARN" and "restricted" in reach["evidence"]

def test_preflight_history_is_workspace_scoped():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"preflight.sqlite3"));r.init_schema()
        from app.crypto import hash_password
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
        project=r.create_project("Production","",owner["organization_id"],owner["user_id"])
        target=r.create_target(project["id"],"https://example.com/","Portal",True,True,owner["user_id"])
        saved=r.save_target_preflight(target["id"],owner["organization_id"],owner["user_id"],"standard",{"status":"READY","checks":[]})
        latest=r.latest_target_preflight(target["id"],owner["organization_id"],"standard")
        assert latest and latest["id"]==saved["id"] and latest["status"]=="READY"
        other=r.create_signup("other@example.com","Other",hash_password("correct-horse-battery"),"Other")
        assert r.target_preflights(target["id"],other["organization_id"])==[]
