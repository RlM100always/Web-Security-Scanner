import os
import socket
import time
from .scanner.engine import run_scan

def process_scan(repo, config, payload):
    scan=repo.get_scan(payload["scan_id"])
    if not scan: raise ValueError("Scan does not exist")
    target=repo.get_target(scan["target_id"])
    if not target: raise ValueError("Target does not exist")
    repo.update_scan(scan['id'],status='SCANNING',stage='VALIDATING_TARGET',progress=1)
    repo.add_scan_event(scan['id'],'STATE','VALIDATING_TARGET',1,'Worker started scan')
    def progress(stage,pct,msg):
        repo.update_scan(scan['id'],stage=stage,progress=pct,status='SCANNING')
        repo.add_scan_event(scan['id'],'PROGRESS',stage,pct,msg)
    try:
        result=run_scan(target['url'],scan['profile'],config.SCANNER_ALLOW_PRIVATE,progress)
        repo.add_findings(scan['id'],result.findings)
        repo.update_scan(scan['id'],status='COMPLETED',stage='COMPLETED',progress=100,score=result.score,
                         pages_scanned=result.pages_scanned,duration_ms=result.duration_ms,completed_at=repo.now())
        repo.add_scan_event(scan['id'],'STATE','COMPLETED',100,'Scan completed',{"score":result.score,"checks_run":result.checks_run})
    except Exception as e:
        repo.update_scan(scan['id'],status='FAILED',stage='FAILED',progress=100,error=str(e)[:1000],completed_at=repo.now())
        repo.add_scan_event(scan['id'],'STATE','FAILED',100,'Scan failed',{"error":str(e)[:1000]})
        raise

def process_one(repo, config, worker_id):
    job=repo.claim_job(worker_id)
    if not job:return False
    try:
        if job['kind']=='scan':process_scan(repo,config,job['payload'])
        else:raise ValueError(f"Unknown job kind: {job['kind']}")
        repo.finish_job(job['id'])
    except Exception as e:
        repo.fail_job(job['id'],str(e),retry=True)
    return True

def worker_loop(repo, config, poll_seconds=1.0):
    worker_id=f"{socket.gethostname()}:{os.getpid()}"
    while True:
        try:
            repo.enqueue_due_schedules()
            if not process_one(repo,config,worker_id):time.sleep(poll_seconds)
        except KeyboardInterrupt:return
        except Exception:time.sleep(poll_seconds)
