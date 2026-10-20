import os
import time

STARTED_AT=time.time()

def snapshot(repo):
    scans=repo.list_scans(1000)
    statuses={}
    for s in scans:statuses[s["status"]]=statuses.get(s["status"],0)+1
    queue=repo.queue_stats()
    return {
        "uptime_seconds":round(time.time()-STARTED_AT),
        "database_size_bytes":os.path.getsize(repo.path) if os.path.exists(repo.path) else 0,
        "scan_statuses":statuses,
        "queue":queue,
        "recent_scan_count":len(scans),
    }

def prometheus(repo):
    m=snapshot(repo);lines=[
        "# HELP sentinelscope_uptime_seconds Process uptime",
        "# TYPE sentinelscope_uptime_seconds gauge",
        f"sentinelscope_uptime_seconds {m['uptime_seconds']}",
        "# HELP sentinelscope_database_size_bytes SQLite database size",
        "# TYPE sentinelscope_database_size_bytes gauge",
        f"sentinelscope_database_size_bytes {m['database_size_bytes']}",
    ]
    for k,v in m["queue"].items():lines.append(f'sentinelscope_jobs{{status="{k.lower()}"}} {v}')
    for k,v in m["scan_statuses"].items():lines.append(f'sentinelscope_scans{{status="{k.lower()}"}} {v}')
    return "\n".join(lines)+"\n"
