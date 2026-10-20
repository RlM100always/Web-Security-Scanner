import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

import pytest
from app import create_app

class ProxyConfig:
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
    TRUST_PROXY_HEADERS=True
    TRUST_PROXY_HOPS=1
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

def test_trusted_proxy_uses_rightmost_configured_hop_for_audit_ip():
    with tempfile.TemporaryDirectory() as d:
        ProxyConfig.DATABASE_PATH=os.path.join(d,"proxy.sqlite3")
        ProxyConfig.BACKUP_DIR=os.path.join(d,"backups")
        app=create_app(ProxyConfig);app.testing=True
        client=app.test_client()
        res=client.post("/api/v1/auth/signup",
            json={"name":"Owner","email":"owner@example.com","password":"correct-horse-battery","organization_name":"Acme"},
            headers={"X-Forwarded-For":"198.51.100.77, 203.0.113.9","X-Forwarded-Proto":"https"})
        assert res.status_code==201
        ident=res.get_json()["user"]
        audit=app.extensions["repo"].list_audit(ident["organization_id"])
        signup=next(x for x in audit if x["event"]=="ACCOUNT_SIGNUP")
        assert signup["ip"]=="203.0.113.9"

def test_wildcard_credentialed_cors_is_rejected():
    class Bad(ProxyConfig):
        CORS_ORIGINS="*"
        TRUST_PROXY_HEADERS=False
    with tempfile.TemporaryDirectory() as d:
        Bad.DATABASE_PATH=os.path.join(d,"bad.sqlite3")
        Bad.BACKUP_DIR=os.path.join(d,"backups")
        with pytest.raises(RuntimeError,match="Wildcard CORS"):
            create_app(Bad)
