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

def build(path):
    TestConfig.DATABASE_PATH=path
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
