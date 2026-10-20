import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

def create_sqlite_backup(database_path, backup_dir):
    Path(backup_dir).mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename=f"sentinelscope-{stamp}.sqlite3"
    destination=str(Path(backup_dir)/filename)
    src=sqlite3.connect(database_path,timeout=30)
    dst=sqlite3.connect(destination)
    try:
        src.backup(dst)
        row=dst.execute("pragma integrity_check").fetchone()
        if not row or row[0]!="ok": raise RuntimeError("Backup integrity check failed")
    finally:
        dst.close();src.close()
    return destination,os.path.getsize(destination)

def validate_sqlite_backup(path):
    c=sqlite3.connect(path)
    try:
        integrity=c.execute("pragma integrity_check").fetchone()
        required={"users","organizations","memberships","projects","targets","scans","findings"}
        tables={r[0] for r in c.execute("select name from sqlite_master where type='table'")}
        return bool(integrity and integrity[0]=="ok" and required.issubset(tables))
    finally:c.close()

def restore_sqlite_backup(database_path, uploaded_path):
    if not validate_sqlite_backup(uploaded_path): raise ValueError("Invalid SentinelScope SQLite backup")
    Path(database_path).parent.mkdir(parents=True,exist_ok=True)
    temp=str(Path(database_path).with_suffix(".restore.tmp"))
    shutil.copy2(uploaded_path,temp)
    os.replace(temp,database_path)
