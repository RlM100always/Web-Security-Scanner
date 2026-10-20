import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
from app import create_app

class TestConfig:
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
    BACKUP_DIR=""

def build(path):
    TestConfig.DATABASE_PATH=path
    TestConfig.BACKUP_DIR=os.path.join(os.path.dirname(path),"backups")
    return create_app(TestConfig)

def test_signup_session_csrf_and_project_rbac():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"api.sqlite3"));app.testing=True
        client=app.test_client()
        secret="correct-horse-battery"
        res=client.post("/api/v1/auth/signup",json={"name":"Owner User","email":"owner@example.com","password":secret,"organization_name":"Acme Security"})
        assert res.status_code==201
        payload=res.get_json();csrf=payload["csrf_token"]
        assert payload["user"]["role"]=="owner"
        assert client.get("/api/v1/auth/me").status_code==200
        assert client.post("/api/v1/projects",json={"name":"Blocked"}).status_code==403
        created=client.post("/api/v1/projects",json={"name":"Web Estate"},headers={"X-CSRF-Token":csrf})
        assert created.status_code==201
        member=client.post("/api/v1/team",json={"name":"View User","email":"viewer@example.com","temporary_password":"viewer-account-secret","role":"viewer"},headers={"X-CSRF-Token":csrf})
        assert member.status_code==201


def test_email_verification_and_password_reset(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"api.sqlite3"));app.testing=True
        client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner User","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        payload=signup.get_json()
        token=payload["development_verification_link"].split("token=",1)[1]
        verified=client.post("/api/v1/auth/email-verification/confirm",json={"token":token})
        assert verified.status_code==200
        captured={}
        def fake_send(config,to_address,subject,text_body):
            captured.update({"to":to_address,"subject":subject,"body":text_body})
            return {"delivered":True,"mode":"smtp"}
        import app.api as api_module
        monkeypatch.setattr(api_module,"send_email",fake_send)
        forgot=client.post("/api/v1/auth/forgot-password",json={"email":"owner@example.com"})
        assert forgot.status_code==200 and "development_reset_link" not in forgot.get_json()
        unknown=client.post("/api/v1/auth/forgot-password",json={"email":"missing@example.com"})
        assert unknown.get_json()==forgot.get_json()
        reset_token=captured["body"].split("token=",1)[1].strip()
        reset=client.post("/api/v1/auth/reset-password",json={"token":reset_token,"new_password":"new-secure-password-123"})
        assert reset.status_code==200
        login=client.post("/api/v1/auth/login",json={"email":"owner@example.com","password":"new-secure-password-123"})
        assert login.status_code==200

def test_mfa_setup_and_login_requirement():
    import pyotp
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"api.sqlite3"));app.testing=True
        client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner User","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        csrf=signup.get_json()["csrf_token"]
        setup=client.post("/api/v1/auth/mfa/setup",json={},headers={"X-CSRF-Token":csrf})
        secret=setup.get_json()["secret"]
        code=pyotp.TOTP(secret).now()
        confirm=client.post("/api/v1/auth/mfa/confirm",json={"secret":secret,"code":code},headers={"X-CSRF-Token":csrf})
        assert confirm.status_code==200
        client.post("/api/v1/auth/logout",json={},headers={"X-CSRF-Token":csrf})
        no_code=client.post("/api/v1/auth/login",json={"email":"owner@example.com","password":"correct-horse-battery"})
        assert no_code.status_code==401 and no_code.get_json()["mfa_required"] is True
        yes_code=client.post("/api/v1/auth/login",json={"email":"owner@example.com","password":"correct-horse-battery","mfa_code":pyotp.TOTP(secret).now()})
        assert yes_code.status_code==200

def test_invitation_and_tenant_backup_isolation():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"api.sqlite3"));app.testing=True
        client=app.test_client()
        signup=client.post("/api/v1/auth/signup",json={"name":"Owner User","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        csrf=signup.get_json()["csrf_token"]
        invite=client.post("/api/v1/team/invitations",json={"email":"analyst@example.com","role":"analyst"},headers={"X-CSRF-Token":csrf})
        assert invite.status_code==201
        invite_token=invite.get_json()["development_invite_link"].split("token=",1)[1]
        info=client.get("/api/v1/auth/invitations/info",query_string={"token":invite_token})
        assert info.status_code==200 and info.get_json()["existing_account"]==0 and info.get_json()["organization_name"]=="Acme"
        incomplete=client.post("/api/v1/auth/invitations/accept",json={"token":invite_token,"name":"Analyst User","password":"short"})
        assert incomplete.status_code==400
        assert client.get("/api/v1/auth/invitations/info",query_string={"token":invite_token}).status_code==200
        accepted=client.post("/api/v1/auth/invitations/accept",json={"token":invite_token,"name":"Analyst User","password":"analyst-password-123"})
        assert accepted.status_code==200 and accepted.get_json()["existing_account"] is False
        backup=client.post("/api/v1/backups",json={},headers={"X-CSRF-Token":csrf})
        assert backup.status_code==403
        assert "System Administrator" in backup.get_json()["error"]
        assert client.get("/api/v1/metrics").status_code==403
        export=client.get("/api/v1/export/workspace.json")
        assert export.status_code==200
        payload=export.get_json()
        assert payload["organization"]["id"]==signup.get_json()["user"]["organization_id"]


def test_shared_ip_failures_do_not_lock_unrelated_account():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"shared-ip.sqlite3"));app.testing=True
        owner=app.test_client()
        signup=owner.post("/api/v1/auth/signup",json={"name":"Owner User","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"})
        csrf=signup.get_json()["csrf_token"]
        owner.post("/api/v1/auth/logout",json={},headers={"X-CSRF-Token":csrf})
        attacker=app.test_client()
        for i in range(9):
            res=attacker.post("/api/v1/auth/login",json={"email":f"missing-{i}@example.com","password":"wrong-password"})
            assert res.status_code==401
        login=app.test_client().post("/api/v1/auth/login",json={"email":"owner@example.com","password":"correct-horse-battery"})
        assert login.status_code==200


def test_existing_account_invitation_does_not_reset_password():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"existing-invite.sqlite3"));app.testing=True
        owner=app.test_client();existing=app.test_client()
        owner_signup=owner.post("/api/v1/auth/signup",json={"name":"Owner","email":"owner@example.com","password":"owner-password-123","organization_name":"Owner Workspace"})
        owner_csrf=owner_signup.get_json()["csrf_token"]
        existing_signup=existing.post("/api/v1/auth/signup",json={"name":"Existing User","email":"existing@example.com","password":"existing-password-123","organization_name":"Existing Workspace"})
        existing_csrf=existing_signup.get_json()["csrf_token"]
        existing.post("/api/v1/auth/logout",json={},headers={"X-CSRF-Token":existing_csrf})

        invite=owner.post("/api/v1/team/invitations",json={"email":"existing@example.com","role":"analyst"},headers={"X-CSRF-Token":owner_csrf})
        token=invite.get_json()["development_invite_link"].split("token=",1)[1]
        info=app.test_client().get("/api/v1/auth/invitations/info",query_string={"token":token})
        assert info.status_code==200 and info.get_json()["existing_account"]==1

        accepted=app.test_client().post("/api/v1/auth/invitations/accept",json={"token":token})
        assert accepted.status_code==200 and accepted.get_json()["existing_account"] is True
        login=app.test_client().post("/api/v1/auth/login",json={"email":"existing@example.com","password":"existing-password-123"})
        assert login.status_code==200
        workspaces=login.get_json()["workspaces"]
        assert {w["organization_name"] for w in workspaces}=={"Existing Workspace","Owner Workspace"}
