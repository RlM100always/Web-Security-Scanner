import os
from pathlib import Path
class Config:
    BASE_DIR=Path(__file__).resolve().parents[1]
    DATABASE_PATH=os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "scanner.sqlite3"))
    CORS_ORIGINS=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    SCANNER_ALLOW_PRIVATE=os.getenv("SCANNER_ALLOW_PRIVATE", "0") == "1"
    MAX_CONTENT_BYTES=int(os.getenv("MAX_CONTENT_BYTES", "2000000"))
    REQUEST_TIMEOUT=float(os.getenv("REQUEST_TIMEOUT", "8"))
