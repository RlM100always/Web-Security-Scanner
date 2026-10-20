from app.config import Config
from app.repository import Repository
from app.worker import worker_loop

repo=Repository(Config.DATABASE_PATH)
repo.init_schema()
print(f"SQLite worker started: {Config.DATABASE_PATH}")
worker_loop(repo,Config)
