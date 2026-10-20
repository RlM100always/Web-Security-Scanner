import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
from app import create_app
from app.repository import Repository

class AdminConfig:
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
    MAX_BACKUP_UPLOAD_BYTES=50*1024*1024
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
    SYSTEM_ADMIN_EMAILS=["root@example.com"]
    BACKUP_DIR=""

def build(path):
    AdminConfig.DATABASE_PATH=path
    AdminConfig.BACKUP_DIR=os.path.join(os.path.dirname(path),"backups")
    app=create_app(AdminConfig);app.testing=True
    return app

def signup(client,email,name="User"):
    return client.post("/api/v1/auth/signup",json={
        "name":name,"email":email,"password":"correct-horse-battery","organization_name":name+" Workspace"
    })

def test_system_admin_bootstrap_and_access_boundary():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"admin.sqlite3"))
        admin=app.test_client();normal=app.test_client()
        a=signup(admin,"root@example.com","Root")
        assert a.status_code==201 and a.get_json()["user"]["system_admin"]==1
        assert admin.get("/api/v1/admin/overview").status_code==200
        n=signup(normal,"user@example.com","Normal")
        assert n.status_code==201 and not n.get_json()["user"]["system_admin"]
        assert normal.get("/api/v1/admin/overview").status_code==403

def test_admin_settings_registration_and_broadcast():
    with tempfile.TemporaryDirectory() as d:
        app=build(os.path.join(d,"admin.sqlite3"));admin=app.test_client()
        a=signup(admin,"root@example.com","Root");csrf=a.get_json()["csrf_token"]
        changed=admin.put("/api/v1/admin/settings",json={"settings":{"registration_enabled":False,"admin_banner":"Planned maintenance"}},
                          headers={"X-CSRF-Token":csrf})
        assert changed.status_code==200
        blocked=app.test_client().post("/api/v1/auth/signup",json={
            "name":"Blocked User","email":"blocked@example.com","password":"correct-horse-battery","organization_name":"Blocked"
        })
        assert blocked.status_code==403
        b=admin.post("/api/v1/admin/broadcast",json={"title":"Security notice","body":"Platform notice"},
                     headers={"X-CSRF-Token":csrf})
        assert b.status_code==201

def test_admin_user_workspace_and_queue_repository_controls():
    with tempfile.TemporaryDirectory() as d:
        path=os.path.join(d,"admin.sqlite3");app=build(path);admin=app.test_client();user=app.test_client()
        a=signup(admin,"root@example.com","Root");csrf=a.get_json()["csrf_token"]
        u=signup(user,"member@example.com","Member");uid=u.get_json()["user"]["user_id"];org=u.get_json()["user"]["organization_id"]
        disabled=admin.patch("/api/v1/admin/users/"+uid,json={"active":False},headers={"X-CSRF-Token":csrf})
        assert disabled.status_code==200
        enabled=admin.patch("/api/v1/admin/users/"+uid,json={"active":True},headers={"X-CSRF-Token":csrf})
        assert enabled.status_code==200
        suspended=admin.patch("/api/v1/admin/organizations/"+org,json={"active":False},headers={"X-CSRF-Token":csrf})
        assert suspended.status_code==200
        repo=Repository(path);repo.init_schema()
        job=repo.enqueue_job("scan",{"scan_id":"missing","target_id":"missing"})
        assert repo.admin_cancel_job(job["id"])
        assert repo.admin_retry_job(job["id"])
        repo.worker_heartbeat("worker:test","worker",123,"IDLE")
        workers=repo.admin_list_workers()
        assert workers and workers[0]["worker_id"]=="worker:test"


def test_system_admin_restore_requires_maintenance_workers_offline_and_idle_queue():
    with tempfile.TemporaryDirectory() as d:
        path=os.path.join(d,"admin.sqlite3");app=build(path);admin=app.test_client()
        signup_result=signup(admin,"root@example.com","Root")
        csrf=signup_result.get_json()["csrf_token"]

        created=admin.post("/api/v1/admin/backups",json={},headers={"X-CSRF-Token":csrf})
        assert created.status_code==201
        backup_path=os.path.join(AdminConfig.BACKUP_DIR,created.get_json()["filename"])
        assert os.path.exists(backup_path)

        def restore():
            with open(backup_path,"rb") as fh:
                return admin.post(
                    "/api/v1/admin/backups/restore",
                    data={"file":(fh,"platform.sqlite3")},
                    content_type="multipart/form-data",
                    headers={"X-CSRF-Token":csrf},
                )

        blocked=restore()
        assert blocked.status_code==409
        assert "maintenance" in blocked.get_json()["error"].lower()

        enabled=admin.put(
            "/api/v1/admin/settings",
            json={"settings":{"maintenance_mode":True}},
            headers={"X-CSRF-Token":csrf},
        )
        assert enabled.status_code==200

        repo=Repository(path);repo.init_schema()
        repo.worker_heartbeat("worker:test","worker",123,"IDLE")
        blocked=restore()
        assert blocked.status_code==409
        assert "worker" in blocked.get_json()["error"].lower()

        with repo.conn() as conn:
            conn.execute("delete from worker_heartbeats")

        job=repo.enqueue_job("webhook",{"delivery_id":"missing"})
        blocked=restore()
        assert blocked.status_code==409
        assert "queue" in blocked.get_json()["error"].lower()
        assert repo.admin_cancel_job(job["id"])

        restored=restore()
        assert restored.status_code==200
        assert restored.get_json()["ok"] is True
