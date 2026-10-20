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
