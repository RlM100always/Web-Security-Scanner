import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app import create_app
from app.crypto import hash_password,token_hash
from app.scanner.models import Finding

class GovernanceConfig:
    CORS_ORIGINS="http://localhost"
    SCANNER_ALLOW_PRIVATE=False
    MAX_CONTENT_BYTES=2_000_000
    REQUEST_TIMEOUT=3
    SESSION_TTL_HOURS=24
    SESSION_COOKIE_SECURE=False
    SESSION_COOKIE_SAMESITE="Lax"
    AUTH_MAX_ATTEMPTS=8
    AUTH_MAX_IP_ATTEMPTS=50
    AUTH_WINDOW_MINUTES=15
    MAX_ZAP_UPLOAD_BYTES=5_000_000
    MAX_BACKUP_UPLOAD_BYTES=50_000_000
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
    APP_ENCRYPTION_KEY=""
    SYSTEM_ADMIN_EMAILS=[]
    BACKUP_DIR=""

def build(path):
    GovernanceConfig.DATABASE_PATH=path
    GovernanceConfig.BACKUP_DIR=os.path.join(os.path.dirname(path),"backups")
    app=create_app(GovernanceConfig);app.testing=True
    return app

def signup(client):
    res=client.post("/api/v1/auth/signup",json={
        "name":"Owner User","email":"owner@example.com","password":"correct-horse-battery",
        "organization_name":"Acme Security"
    })
    assert res.status_code==201
    body=res.get_json()
    return body["user"],body["csrf_token"]

def ready_preflight(target,profile,*args,**kwargs):
    return {
        "status":"READY","profile":profile,"requested_url":target["url"],"final_url":target["url"],
        "checks":[{"key":"safe_destination","label":"Safe destination","status":"PASS","evidence":"test"}]
    }

def blocked_preflight(target,profile,*args,**kwargs):
    return {
        "status":"BLOCKED","profile":profile,"requested_url":target["url"],
        "checks":[{"key":"reachability","label":"HTTP reachability","status":"BLOCKED","evidence":"test blocked"}]
    }

def test_rerun_requires_current_authorization_and_preflight(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"rerun.sqlite3"));client=app.test_client()
        user,csrf=signup(client);repo=app.extensions["repo"]
        p=repo.create_project("Production","",user["organization_id"],user["user_id"])
        t=repo.create_target(p["id"],"https://example.com/","Portal",True,True,user["user_id"])
        old=repo.create_scan(t["id"],t["url"],"standard",user["user_id"],{"max_pages":7})
        repo.update_scan(old["id"],status="COMPLETED",stage="COMPLETED",progress=100,completed_at=repo.now())

        import app.api as api_module
        monkeypatch.setattr(api_module,"run_target_preflight",blocked_preflight)
        blocked=client.post("/api/v1/scans/"+old["id"]+"/rerun",json={},headers={"X-CSRF-Token":csrf})
        assert blocked.status_code==409 and blocked.get_json()["preflight"]["status"]=="BLOCKED"

        with repo.conn() as db:db.execute("delete from target_preflights where target_id=?",(t["id"],))
        monkeypatch.setattr(api_module,"run_target_preflight",ready_preflight)
        ok=client.post("/api/v1/scans/"+old["id"]+"/rerun",json={},headers={"X-CSRF-Token":csrf})
        assert ok.status_code==202
        assert ok.get_json()["preflight"]["status"]=="READY"
        with repo.conn() as db:db.execute("update targets set authorized=0 where id=?",(t["id"],))
        denied=client.post("/api/v1/scans/"+old["id"]+"/rerun",json={},headers={"X-CSRF-Token":csrf})
        assert denied.status_code==403

def test_remediation_verification_obeys_archive_and_quota(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"verify.sqlite3"));client=app.test_client()
        user,csrf=signup(client);repo=app.extensions["repo"]
        p=repo.create_project("Production","",user["organization_id"],user["user_id"])
        t=repo.create_target(p["id"],"https://example.com/","Portal",True,True,user["user_id"])
        scan=repo.create_scan(t["id"],t["url"],"standard",user["user_id"],{})
        finding=Finding("header.csp","Content Security Policy","Headers","FAIL","HIGH","HIGH",t["url"],"missing",
                        "Checks CSP","Weak browser policy","Deploy CSP",["OWASP ASVS V14"],"governance-fp",{})
        repo.add_findings(scan["id"],[finding]);repo.sync_finding_states(scan["id"])
        repo.update_scan(scan["id"],status="COMPLETED",stage="COMPLETED",progress=100,completed_at=repo.now())
        state=repo.list_finding_states(user["organization_id"])[0]

        repo.update_project(p["id"],user["organization_id"],{"status":"archived"})
        archived=client.post("/api/v1/finding-states/"+state["id"]+"/verify",json={},headers={"X-CSRF-Token":csrf})
        assert archived.status_code==409

        repo.update_project(p["id"],user["organization_id"],{"status":"active"})
        import app.api as api_module
        monkeypatch.setattr(api_module,"run_target_preflight",ready_preflight)
        repo.set_system_setting("scan_quota_per_day",1,user["user_id"])
        quota=client.post("/api/v1/finding-states/"+state["id"]+"/verify",json={},headers={"X-CSRF-Token":csrf})
        assert quota.status_code==429

def test_schedule_run_now_uses_bound_profile_and_scan_scope(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"schedule.sqlite3"));client=app.test_client()
        user,csrf=signup(client);repo=app.extensions["repo"]
        p=repo.create_project("Production","",user["organization_id"],user["user_id"])
        t=repo.create_target(p["id"],"https://example.com/","Portal",True,True,user["user_id"])
        profile=repo.create_scan_profile(p["id"],"Lab baseline","controlled","lab",repo.get_project_policy(p["id"]),False,user["user_id"])
        schedule=repo.create_schedule(t["id"],"standard",1440,user["user_id"],scan_profile_id=profile["id"])

        import app.api as api_module
        monkeypatch.setattr(api_module,"run_target_preflight",ready_preflight)

        raw="wss_scan_scope_regression"
        repo.create_api_key(user["user_id"],user["organization_id"],"Scanner",token_hash(raw),"wss_scan",["read","scan"],None)
        bearer={"Authorization":"Bearer "+raw}
        run=app.test_client().post("/api/v1/schedules/"+schedule["id"]+"/run-now",json={},headers=bearer)
        assert run.status_code==202
        assert run.get_json()["profile"]=="lab"

        profile2=repo.create_scan_profile(p["id"],"Retired","old","standard",repo.get_project_policy(p["id"]),False,user["user_id"])
        schedule2=repo.create_schedule(t["id"],"standard",1440,user["user_id"],scan_profile_id=profile2["id"])
        repo.update_scan_profile(p["id"],profile2["id"],{"active":False},user["user_id"],"Retire profile")
        blocked=client.post("/api/v1/schedules/"+schedule2["id"]+"/run-now",json={},headers={"X-CSRF-Token":csrf})
        assert blocked.status_code==409

def test_read_only_api_key_cannot_trigger_scan_actions(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"scope.sqlite3"));client=app.test_client()
        user,_=signup(client);repo=app.extensions["repo"]
        p=repo.create_project("Production","",user["organization_id"],user["user_id"])
        t=repo.create_target(p["id"],"https://example.com/","Portal",True,True,user["user_id"])
        scan=repo.create_scan(t["id"],t["url"],"standard",user["user_id"],{})
        repo.update_scan(scan["id"],status="COMPLETED",stage="COMPLETED",progress=100,completed_at=repo.now())
        raw="wss_read_only_regression"
        repo.create_api_key(user["user_id"],user["organization_id"],"Read only",token_hash(raw),"wss_read",["read"],None)
        import app.api as api_module
        monkeypatch.setattr(api_module,"run_target_preflight",ready_preflight)
        denied=app.test_client().post("/api/v1/scans/"+scan["id"]+"/rerun",json={},headers={"Authorization":"Bearer "+raw})
        assert denied.status_code==403
        assert "scan scope required" in denied.get_json()["error"]


def test_schedule_creation_and_update_validate_governance():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"schedule-validation.sqlite3"));client=app.test_client()
        user,csrf=signup(client);repo=app.extensions["repo"]
        p=repo.create_project("Production","",user["organization_id"],user["user_id"])
        t=repo.create_target(p["id"],"https://example.com/","Portal",True,False,user["user_id"])

        malformed=client.post("/api/v1/schedules",json={"target_id":t["id"],"interval_minutes":"tomorrow"},headers={"X-CSRF-Token":csrf})
        assert malformed.status_code==400

        lab=repo.create_scan_profile(p["id"],"Lab profile","lab","lab",repo.get_project_policy(p["id"]),False,user["user_id"])
        unverified=client.post("/api/v1/schedules",json={"target_id":t["id"],"scan_profile_id":lab["id"],"interval_minutes":1440},headers={"X-CSRF-Token":csrf})
        assert unverified.status_code==403

        with repo.conn() as db:db.execute("update targets set verified=1 where id=?",(t["id"],))
        created=client.post("/api/v1/schedules",json={"target_id":t["id"],"profile":"standard","interval_minutes":1440},headers={"X-CSRF-Token":csrf})
        assert created.status_code==201
        schedule_id=created.get_json()["id"]

        with repo.conn() as db:db.execute("update targets set verified=0 where id=?",(t["id"],))
        bind=client.patch("/api/v1/schedules/"+schedule_id,json={"scan_profile_id":lab["id"]},headers={"X-CSRF-Token":csrf})
        assert bind.status_code==403

        with repo.conn() as db:db.execute("update targets set authorized=0 where id=?",(t["id"],))
        unauthorized=client.post("/api/v1/schedules",json={"target_id":t["id"],"profile":"standard","interval_minutes":1440},headers={"X-CSRF-Token":csrf})
        assert unauthorized.status_code==403

        with repo.conn() as db:
            db.execute("update targets set authorized=1 where id=?",(t["id"],))
            db.execute("update projects set status='archived' where id=?",(p["id"],))
        archived=client.post("/api/v1/schedules",json={"target_id":t["id"],"profile":"standard","interval_minutes":1440},headers={"X-CSRF-Token":csrf})
        assert archived.status_code==409
