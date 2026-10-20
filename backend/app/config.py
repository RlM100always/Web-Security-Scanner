import os
from pathlib import Path

class Config:
    BASE_DIR=Path(__file__).resolve().parents[1]
    DATABASE_PATH=os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "scanner.sqlite3"))
    CORS_ORIGINS=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    SCANNER_ALLOW_PRIVATE=os.getenv("SCANNER_ALLOW_PRIVATE", "0") == "1"
    MAX_CONTENT_BYTES=int(os.getenv("MAX_CONTENT_BYTES", "2000000"))
    REQUEST_TIMEOUT=float(os.getenv("REQUEST_TIMEOUT", "8"))
    SESSION_TTL_HOURS=int(os.getenv("SESSION_TTL_HOURS","24"))
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE","0")=="1"
    SESSION_COOKIE_SAMESITE=os.getenv("SESSION_COOKIE_SAMESITE","Lax")
    AUTH_MAX_ATTEMPTS=int(os.getenv("AUTH_MAX_ATTEMPTS","8"))
    AUTH_WINDOW_MINUTES=int(os.getenv("AUTH_WINDOW_MINUTES","15"))
    MAX_ZAP_UPLOAD_BYTES=int(os.getenv("MAX_ZAP_UPLOAD_BYTES","5000000"))
    TRUST_PROXY_HEADERS=os.getenv("TRUST_PROXY_HEADERS","0")=="1"

    EMAIL_FROM=os.getenv("EMAIL_FROM","SentinelScope <no-reply@localhost>")
    SMTP_HOST=os.getenv("SMTP_HOST","")
    SMTP_PORT=int(os.getenv("SMTP_PORT","587"))
    SMTP_USERNAME=os.getenv("SMTP_USERNAME","")
    SMTP_PASSWORD=os.getenv("SMTP_PASSWORD","")
    SMTP_USE_TLS=os.getenv("SMTP_USE_TLS","1")=="1"
    PUBLIC_APP_URL=os.getenv("PUBLIC_APP_URL","http://localhost:8080")
    EMAIL_VERIFY_TTL_MINUTES=int(os.getenv("EMAIL_VERIFY_TTL_MINUTES","60"))
    PASSWORD_RESET_TTL_MINUTES=int(os.getenv("PASSWORD_RESET_TTL_MINUTES","30"))
    INVITE_TTL_HOURS=int(os.getenv("INVITE_TTL_HOURS","48"))
    MFA_ISSUER=os.getenv("MFA_ISSUER","SentinelScope")
    BACKUP_DIR=os.getenv("BACKUP_DIR", str(BASE_DIR / "instance" / "backups"))
