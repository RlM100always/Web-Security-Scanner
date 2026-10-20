import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

def create_sqlite_backup(database_path, backup_dir):
    Path(backup_dir).mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    filename=f"sentinelscope-{stamp}-{uuid4().hex[:8]}.sqlite3"
    destination=str(Path(backup_dir)/filename)
    src=sqlite3.connect(database_path,timeout=30)
    dst=sqlite3.connect(destination)
    try:
        src.execute("pragma wal_checkpoint(PASSIVE)")
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
    finally:
        c.close()

def restore_sqlite_backup(database_path, uploaded_path):
    if not validate_sqlite_backup(uploaded_path):
        raise ValueError("Invalid SentinelScope SQLite backup")
    db=Path(database_path)
    db.parent.mkdir(parents=True,exist_ok=True)

    # Flush the live WAL before replacing the primary database file.
    if db.exists():
        current=sqlite3.connect(str(db),timeout=30)
        try:
            current.execute("pragma wal_checkpoint(TRUNCATE)")
        finally:
            current.close()

    temp=db.with_name(db.name+f".restore-{uuid4().hex}.tmp")
    try:
        shutil.copy2(uploaded_path,temp)
        check=sqlite3.connect(str(temp))
        try:
            row=check.execute("pragma integrity_check").fetchone()
            if not row or row[0]!="ok":
                raise ValueError("Restored database failed integrity check")
        finally:
            check.close()
        os.replace(temp,db)
        # Sidecars belong to the previous database generation and must not be reused.
        for suffix in ("-wal","-shm"):
            sidecar=Path(str(db)+suffix)
            try:
                sidecar.unlink()
            except FileNotFoundError:
                pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
