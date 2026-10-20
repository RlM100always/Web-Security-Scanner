import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app import create_app
from app.repository import Repository
from app.crypto import hash_password
from app.scanner.models import Finding,Asset
from app.scanner.engine import normalize_policy

class DeepConfig:
    CORS_ORIGINS="http://localhost"
    SCANNER_ALLOW_PRIVATE=False
    MAX_CONTENT_BYTES=2000000
    REQUEST_TIMEOUT=3
    SESSION_TTL_HOURS=24
    SESSION_COOKIE_SECURE=False
    SESSION_COOKIE_SAMESITE="Lax"
    AUTH_MAX_ATTEMPTS=8
    AUTH_WINDOW_MINUTES=15
    MAX_ZAP_UPLOAD_BYTES=5000000
    TRUST_PROXY_HEADERS=False
    EMAIL_FROM="SentinelScope <no-reply@localhost>"
    SMTP_HOST=""
    SMTP_PORT=587
    SMTP_USERNAME=""
    SMTP_PASSWORD=""
    SMTP_USE_TLS=True
    PUBLIC_APP_URL="http://localhost:8080"
    EMAIL_VERIFY_TTL_MINUTES=60
    PASSWORD_RESET_TTL_MINUTES=30
    INVITE_TTL_HOURS=48
    MFA_ISSUER="SentinelScope"
    SYSTEM_ADMIN_EMAILS=[]
    BACKUP_DIR=""

def app_for(path):
    DeepConfig.DATABASE_PATH=path
    DeepConfig.BACKUP_DIR=os.path.join(os.path.dirname(path),"backups")
    app=create_app(DeepConfig);app.testing=True
    return app

def active_finding(url="https://example.com/"):
    return Finding(
        "header.content-security-policy","Content Security Policy","Security Headers","FAIL","MEDIUM","HIGH",url,
        "Content-Security-Policy: not present","Checks CSP","Missing CSP increases client-side risk",
        "Deploy a restrictive CSP",["OWASP ASVS V14"],"fingerprint-csp",{}
    )

def test_policy_asset_and_finding_lifecycle_persist_across_scans():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"deep.sqlite3"));r.init_schema()
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
        p=r.create_project("Web","",owner["organization_id"],owner["user_id"])
        t=r.create_target(p["id"],"https://example.com/","Example",True,True,owner["user_id"])
        policy=r.set_project_policy(p["id"],{"max_pages":40,"max_depth":3,"request_delay_ms":250,"include_paths":["^/app"],"exclude_paths":["^/logout"],"disabled_checks":["browser.sri"]},owner["user_id"])
        assert policy["max_pages"]==40 and policy["exclude_paths"]==["^/logout"]

        s1=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],policy)
        r.add_findings(s1["id"],[active_finding()])
        r.add_assets(s1["id"],t["id"],[Asset(t["url"],"html",200,"text/html","Home",0,1234,None,{"server":"test"})])
        r.sync_finding_states(s1["id"])
        states=r.list_finding_states(owner["organization_id"])
        assert len(states)==1 and states[0]["state"]=="OPEN" and states[0]["occurrences"]==1
        assert r.assets(s1["id"])[0]["title"]=="Home"

        state_id=states[0]["id"]
        r.update_finding_state(state_id,owner["organization_id"],{"state":"IN_PROGRESS","risk_reason":"Investigating","due_at":"2027-01-10"},owner["user_id"])
        r.add_finding_comment(state_id,owner["organization_id"],owner["user_id"],"Assigned for remediation")
        assert r.finding_comments(state_id,owner["organization_id"])[0]["body"]=="Assigned for remediation"

        s2=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],policy)
        verification=r.create_remediation_verification(state_id,s2["id"],owner["user_id"])
        r.add_findings(s2["id"],[])
        r.sync_finding_states(s2["id"]);r.finalize_remediation_verifications(s2["id"])
        state=r.get_finding_state(state_id,owner["organization_id"])
        history=r.remediation_history(state_id,owner["organization_id"])
        assert state["state"]=="REMEDIATED"
        assert history[0]["id"]==verification["id"] and history[0]["status"]=="VERIFIED_FIXED"

def test_policy_normalization_has_safety_caps():
    p=normalize_policy("lab",{"max_pages":9999,"max_depth":99,"request_delay_ms":99999,"include_paths":["^/app"]})
    assert p["max_pages"]==200 and p["max_depth"]==5 and p["request_delay_ms"]==5000

def test_scoped_api_key_and_scan_quota():
    with tempfile.TemporaryDirectory() as d:
        path=os.path.join(d,"deep.sqlite3");app=app_for(path)
        client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        assert signup.status_code==201
        body=signup.get_json();csrf=body["csrf_token"];ident=body["user"]
        repo=app.extensions["repo"]
        p=repo.create_project("Web","",ident["organization_id"],ident["user_id"])
        t=repo.create_target(p["id"],"https://example.com/","Example",True,True,ident["user_id"])

        key=client.post("/api/v1/api-keys",json={"name":"Read automation","scopes":["read"],"expires_in_days":30},headers={"X-CSRF-Token":csrf})
        assert key.status_code==201
        raw=key.get_json()["token"]
        bearer={"Authorization":"Bearer "+raw}
        assert app.test_client().get("/api/v1/projects",headers=bearer).status_code==200
        assert app.test_client().post("/api/v1/projects",json={"name":"Blocked"},headers=bearer).status_code==403

        scan_key=client.post("/api/v1/api-keys",json={"name":"Scanner","scopes":["read","scan"],"expires_in_days":30},headers={"X-CSRF-Token":csrf})
        raw_scan=scan_key.get_json()["token"];headers={"Authorization":"Bearer "+raw_scan}
        first=app.test_client().post("/api/v1/scans",json={"target_id":t["id"],"profile":"quick"},headers=headers)
        assert first.status_code==202
        repo.set_system_setting("scan_quota_per_day",1,ident["user_id"])
        second=app.test_client().post("/api/v1/scans",json={"target_id":t["id"],"profile":"quick"},headers=headers)
        assert second.status_code==429
