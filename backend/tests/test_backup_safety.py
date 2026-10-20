import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app.repository import Repository
from app.crypto import hash_password
from app.backup import create_sqlite_backup,restore_sqlite_backup,validate_sqlite_backup

def test_backups_are_unique_and_restore_consistently():
    with tempfile.TemporaryDirectory() as d:
        db=os.path.join(d,"scanner.sqlite3")
        backup_dir=os.path.join(d,"backups")
        repo=Repository(db);repo.init_schema()
        repo.create_signup("first@example.com","First",hash_password("correct-horse-battery"),"First Workspace")
        first,size1=create_sqlite_backup(db,backup_dir)
        second,size2=create_sqlite_backup(db,backup_dir)

        assert first!=second
        assert os.path.exists(first) and os.path.exists(second)
        assert size1>0 and size2>0
        assert validate_sqlite_backup(first)

        repo.create_signup("second@example.com","Second",hash_password("correct-horse-battery"),"Second Workspace")
        assert repo.user_count()==2

        restore_sqlite_backup(db,first)
        restored=Repository(db)
        assert restored.user_count()==1
        assert restored.get_user_by_email("first@example.com") is not None
        assert restored.get_user_by_email("second@example.com") is None
