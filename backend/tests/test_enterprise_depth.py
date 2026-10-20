import json,os,sys,tempfile
from datetime import datetime,timezone,timedelta

import pyotp
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app import create_app
from app.crypto import hash_password,encrypt_secret,decrypt_secret
from app.repository import Repository
from app.reports import as_json,as_html,as_pdf
from app.scanner.models import Finding,Asset

class EnterpriseDepthConfig:
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

def build(path):
    EnterpriseDepthConfig.DATABASE_PATH=path
    EnterpriseDepthConfig.BACKUP_DIR=os.path.join(os.path.dirname(path),"backups")
    app=create_app(EnterpriseDepthConfig);app.testing=True
    return app

def issue(url="https://example.com/account",severity="HIGH"):
    return Finding("header.hsts","HTTP Strict Transport Security","Security Headers","FAIL",severity,"HIGH",url,
                   "Strict-Transport-Security: not present","Checks HSTS","Transport downgrade exposure",
                   "Deploy HSTS after validating HTTPS coverage",["OWASP ASVS V9"],"stable-hsts",{})

def test_membership_disable_is_workspace_scoped_not_global_account_disable():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"tenant.sqlite3"));r.init_schema()
        a=r.create_signup("a@example.com","A",hash_password("password-password"),"Workspace A")
        b=r.create_signup("b@example.com","B",hash_password("password-password"),"Workspace B")
        user=r.get_user_by_id(a["user_id"])
        r.add_member(b["organization_id"],user["email"],user["name"],user["password_hash"],"analyst")
        r.create_session(a["user_id"],a["organization_id"],"token-a","csrf-a",24,"test","127.0.0.1")
        r.create_session(a["user_id"],b["organization_id"],"token-b","csrf-b",24,"test","127.0.0.1")
        assert r.session_identity("token-a")
        assert r.session_identity("token-b")
        assert r.deactivate_member(b["organization_id"],a["user_id"],False)
        assert r.get_user_by_id(a["user_id"])["active"]==1
        assert r.session_identity("token-a")
        assert r.session_identity("token-b") is None
        memberships=r.list_memberships_for_user(a["user_id"])
        assert [m["organization_id"] for m in memberships]==[a["organization_id"]]

def test_mfa_recovery_code_is_one_time():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"mfa.sqlite3"));client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        csrf=signup.get_json()["csrf_token"]
        setup=client.post("/api/v1/auth/mfa/setup",json={},headers={"X-CSRF-Token":csrf}).get_json()
        code=pyotp.TOTP(setup["secret"]).now()
        confirmed=client.post("/api/v1/auth/mfa/confirm",json={"secret":setup["secret"],"code":code},headers={"X-CSRF-Token":csrf})
        assert confirmed.status_code==200
        recovery=confirmed.get_json()["recovery_codes"][0]
        client.post("/api/v1/auth/logout",json={},headers={"X-CSRF-Token":csrf})
        first=client.post("/api/v1/auth/login",json={"email":"owner@example.com","password":"correct-horse-battery","mfa_code":recovery})
        assert first.status_code==200
        csrf2=first.get_json()["csrf_token"]
        client.post("/api/v1/auth/logout",json={},headers={"X-CSRF-Token":csrf2})
        reused=client.post("/api/v1/auth/login",json={"email":"owner@example.com","password":"correct-horse-battery","mfa_code":recovery})
        assert reused.status_code==401

def test_target_context_risk_scoring_schedule_history_and_notifications():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"ops.sqlite3"));r.init_schema()
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
        p=r.create_project("Customer Portal","",owner["organization_id"],owner["user_id"])
        t=r.create_target(p["id"],"https://example.com/","Portal",True,True,owner["user_id"],"critical","production",["customer-facing"])
        s=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
        r.add_findings(s["id"],[issue()]);r.sync_finding_states(s["id"])
        state=r.list_finding_states(owner["organization_id"])[0]
        assert state["target_criticality"]=="critical"
        assert state["effective_severity"]=="HIGH"
        assert state["risk_score"]>=80

        expired=(datetime.now(timezone.utc)-timedelta(days=1)).date().isoformat()
        r.update_finding_state(state["id"],owner["organization_id"],{"state":"ACCEPTED_RISK","risk_reason":"Temporary exception","risk_expires_at":expired},owner["user_id"])
        accepted=r.list_finding_states(owner["organization_id"])[0]
        assert accepted["risk_acceptance_expired"] is True

        schedule=r.create_schedule(t["id"],"standard",1440,owner["user_id"],"Daily production baseline",True)
        queued=r.run_schedule_now(schedule["id"],owner["organization_id"],owner["user_id"])
        history=r.schedule_history(schedule["id"],owner["organization_id"])
        assert history and history[0]["scan_id"]==queued["id"] and history[0]["status"]=="QUEUED"
        r.finalize_schedule_run(queued["id"],"COMPLETED")
        assert r.schedule_history(schedule["id"],owner["organization_id"])[0]["status"]=="COMPLETED"

        r.add_notification(owner["organization_id"],owner["user_id"],"scan","Scan complete","Baseline finished")
        assert r.notification_counts(owner["organization_id"],owner["user_id"])["unread"]==1
        assert r.mark_all_notifications_read(owner["organization_id"],owner["user_id"])==1
        assert r.notification_counts(owner["organization_id"],owner["user_id"])["unread"]==0

def test_audit_ready_report_formats_include_scope_assets_and_standards():
    scan={"id":"scan1","target_id":"target1","target_url":"https://example.com/","profile":"standard","score":72,"pages_scanned":2,"duration_ms":1400}
    finding={**issue().to_dict(),"id":"f1","lifecycle_state":"OPEN","occurrences":2}
    context={
      "target":{"name":"Portal","url":"https://example.com/","criticality":"critical","environment":"production","verified":True},
      "policy":{"max_pages":20,"max_depth":2,"request_delay_ms":100,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},
      "assets":[Asset("https://example.com/","html",200,"text/html","Home",0,1000,None,{"elapsed_ms":120}).to_dict()],
      "asset_comparison":{"summary":{"added":1,"removed":0,"changed":0}},
      "standards_summary":[{"standard":"OWASP ASVS V9","mapped_checks":1,"PASS":0,"WARNING":0,"FAIL":1,"ERROR":0,"INFO":0,"NOT_APPLICABLE":0}],
      "zap":None,
    }
    comparison={"new":1,"fixed":0,"unchanged":0}
    j=json.loads(as_json(scan,[finding],comparison,context))
    assert j["executive_summary"]["active_findings"]==1
    assert j["target"]["criticality"]=="critical"
    assert j["assets"][0]["title"]=="Home"
    h=as_html(scan,[finding],comparison,context)
    assert "Executive summary" in h and "Standards-mapped evidence" in h and "Assessment policy" in h
    pdf=as_pdf(scan,[finding],comparison,context)
    assert pdf.startswith(b"%PDF") and len(pdf)>1500


def test_project_archive_and_verified_email_are_enforced_by_api():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"governance.sqlite3"));client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        body=signup.get_json();csrf=body["csrf_token"];uid=body["user"]["user_id"]
        headers={"X-CSRF-Token":csrf}
        p=client.post("/api/v1/projects",json={"name":"Production","tags":["internet-facing"]},headers=headers).get_json()
        t=client.post("/api/v1/targets",json={"project_id":p["id"],"name":"Portal","url":"https://example.com/","authorized":True,"criticality":"critical","environment":"production"},headers=headers)
        assert t.status_code==201
        target=t.get_json()

        app.extensions["repo"].set_system_setting("require_verified_email_for_scans",True,uid)
        blocked=client.post("/api/v1/scans",json={"target_id":target["id"],"profile":"quick"},headers=headers)
        assert blocked.status_code==403
        app.extensions["repo"].set_email_verified(uid,True)
        allowed=client.post("/api/v1/scans",json={"target_id":target["id"],"profile":"quick"},headers=headers)
        assert allowed.status_code==202

        archived=client.patch("/api/v1/projects/"+p["id"],json={"status":"archived"},headers=headers)
        assert archived.status_code==200 and archived.get_json()["status"]=="archived"
        target_blocked=client.post("/api/v1/targets",json={"project_id":p["id"],"name":"Other","url":"https://example.org/","authorized":True},headers=headers)
        scan_blocked=client.post("/api/v1/scans",json={"target_id":target["id"],"profile":"quick"},headers=headers)
        assert target_blocked.status_code==409
        assert scan_blocked.status_code==409

def test_encrypted_secret_round_trip_and_schedule_failure_notification():
    from cryptography.fernet import Fernet
    key=Fernet.generate_key().decode()
    encrypted=encrypt_secret("JBSWY3DPEHPK3PXP",key)
    assert encrypted.startswith("fernet$")
    assert decrypt_secret(encrypted,key)=="JBSWY3DPEHPK3PXP"

    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"schedule-alert.sqlite3"));r.init_schema()
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
        p=r.create_project("Production","",owner["organization_id"],owner["user_id"])
        t=r.create_target(p["id"],"https://example.com/","Portal",True,True,owner["user_id"])
        schedule=r.create_schedule(t["id"],"standard",1440,owner["user_id"],"Daily baseline",True)
        scan=r.run_schedule_now(schedule["id"],owner["organization_id"],owner["user_id"])
        assert r.finalize_schedule_run(scan["id"],"FAILED")
        notifications=r.list_notifications(owner["organization_id"],owner["user_id"])
        assert any(n["type"]=="schedule_failure" and "failed" in n["title"].lower() for n in notifications)


def test_stale_worker_lease_recovery_requeues_interrupted_scan():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"recovery.sqlite3"));r.init_schema()
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
        p=r.create_project("Production","",owner["organization_id"],owner["user_id"])
        t=r.create_target(p["id"],"https://example.com/","Portal",True,True,owner["user_id"])
        scan=r.create_scan(t["id"],t["url"],"quick",owner["user_id"],{})
        job=r.enqueue_job("scan",{"scan_id":scan["id"],"target_id":t["id"]})
        claimed=r.claim_job("dead-worker:123")
        assert claimed and claimed["id"]==job["id"]
        stale=(datetime.now(timezone.utc)-timedelta(minutes=30)).isoformat()
        with r.conn() as conn:
            conn.execute("update jobs set locked_at=? where id=?",(stale,job["id"]))
            conn.execute("update scans set status='SCANNING',stage='SCANNING',progress=50 where id=?",(scan["id"],))
        result=r.recover_stale_jobs(10)
        assert job["id"] in result["recovered"]
        jobs=r.admin_list_jobs()
        recovered=next(x for x in jobs if x["id"]==job["id"])
        assert recovered["status"]=="QUEUED" and recovered["locked_by"] is None
        assert r.get_scan(scan["id"])["stage"]=="RECOVERED"


def test_schedule_cannot_bypass_verified_lab_or_archived_project_controls():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"schedule-safety.sqlite3"));client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        csrf=signup.get_json()["csrf_token"];headers={"X-CSRF-Token":csrf}
        p=client.post("/api/v1/projects",json={"name":"Production"},headers=headers).get_json()
        t=client.post("/api/v1/targets",json={"project_id":p["id"],"name":"Portal","url":"https://example.com/","authorized":True},headers=headers).get_json()
        schedule=client.post("/api/v1/schedules",json={"target_id":t["id"],"profile":"standard","interval_minutes":1440},headers=headers)
        assert schedule.status_code==201
        sid=schedule.get_json()["id"]

        lab=client.patch("/api/v1/schedules/"+sid,json={"profile":"lab"},headers=headers)
        assert lab.status_code==403

        archived=client.patch("/api/v1/projects/"+p["id"],json={"status":"archived"},headers=headers)
        assert archived.status_code==200
        run=client.post("/api/v1/schedules/"+sid+"/run-now",json={},headers=headers)
        edit=client.patch("/api/v1/schedules/"+sid,json={"interval_minutes":10080},headers=headers)
        assert run.status_code==409
        assert edit.status_code==409
