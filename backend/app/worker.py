import os
import socket
import time
from .scanner.engine import run_scan
from .mailer import send_email

class ScanCancelled(Exception): pass

def process_scan(repo, config, payload):
    scan=repo.get_scan(payload["scan_id"])
    if not scan: raise ValueError("Scan does not exist")
    target=repo.get_target(scan["target_id"])
    if not target: raise ValueError("Target does not exist")
    if repo.scan_cancel_requested(scan['id']): raise ScanCancelled("Scan cancellation requested")
    repo.update_scan(scan['id'],status='SCANNING',stage='VALIDATING_TARGET',progress=1)
    repo.add_scan_event(scan['id'],'STATE','VALIDATING_TARGET',1,'Worker started scan')
    def progress(stage,pct,msg):
        if repo.scan_cancel_requested(scan['id']): raise ScanCancelled("Scan cancellation requested")
        repo.update_scan(scan['id'],stage=stage,progress=pct,status='SCANNING')
        repo.add_scan_event(scan['id'],'PROGRESS',stage,pct,msg)
    try:
        policy=repo.scan_policy(scan['id'])
        result=run_scan(target['url'],scan['profile'],config.SCANNER_ALLOW_PRIVATE,progress,policy=policy)
        repo.add_findings(scan['id'],result.findings)
        repo.add_assets(scan['id'],target['id'],result.assets)
        repo.sync_finding_states(scan['id'])
        repo.finalize_remediation_verifications(scan['id'])
        repo.update_scan(scan['id'],status='COMPLETED',stage='COMPLETED',progress=100,score=result.score,
                         pages_scanned=result.pages_scanned,duration_ms=result.duration_ms,completed_at=repo.now())
        repo.finalize_schedule_run(scan['id'],'COMPLETED')
        repo.add_scan_event(scan['id'],'STATE','COMPLETED',100,'Scan completed',{"score":result.score,"checks_run":result.checks_run})
        if scan.get('created_by'):
            target_title=target.get('name') or target.get('url')
            repo.add_notification(None,scan['created_by'],'scan_completed','Scan completed',f"{target_title} scored {result.score}/100",{"scan_id":scan['id']})
            user=repo.get_user_by_id(scan['created_by'])
            if user:
                try:send_email(vars(config),user['email'],'SentinelScope scan completed',f"{target_title}\nSecurity score: {result.score}/100")
                except Exception:pass
    except ScanCancelled:
        repo.update_scan(scan['id'],status='CANCELLED',stage='CANCELLED',progress=100,completed_at=repo.now(),error=None)
        repo.finalize_schedule_run(scan['id'],'CANCELLED')
        repo.add_scan_event(scan['id'],'STATE','CANCELLED',100,'Scan cancelled by administrator')
        return
    except Exception as e:
        repo.update_scan(scan['id'],status='FAILED',stage='FAILED',progress=100,error=str(e)[:1000],completed_at=repo.now())
        repo.finalize_schedule_run(scan['id'],'FAILED')
        repo.add_scan_event(scan['id'],'STATE','FAILED',100,'Scan failed',{"error":str(e)[:1000]})
        if scan.get('created_by'):
            repo.add_notification(None,scan['created_by'],'scan_failed','Scan failed',str(e)[:300],{"scan_id":scan['id']})
        raise

def process_one(repo, config, worker_id):
    job=repo.claim_job(worker_id)
    if not job:
        repo.worker_heartbeat(worker_id,worker_id.split(':')[0],int(worker_id.split(':')[-1]),'IDLE')
        return False
    repo.worker_heartbeat(worker_id,worker_id.split(':')[0],int(worker_id.split(':')[-1]),'BUSY',job['id'])
    try:
        if job['kind']=='scan':process_scan(repo,config,job['payload'])
        else:raise ValueError(f"Unknown job kind: {job['kind']}")
        repo.finish_job(job['id'])
    except Exception as e:
        repo.fail_job(job['id'],str(e),retry=True)
    finally:
        repo.worker_heartbeat(worker_id,worker_id.split(':')[0],int(worker_id.split(':')[-1]),'IDLE')
    return True

def worker_loop(repo, config, poll_seconds=1.0):
    worker_id=f"{socket.gethostname()}:{os.getpid()}"
    started=repo.now()
    repo.worker_heartbeat(worker_id,socket.gethostname(),os.getpid(),'STARTING',started_at=started)
    repo.recover_stale_jobs(10)
    last_recovery=time.monotonic()
    while True:
        try:
            if time.monotonic()-last_recovery>=60:
                repo.recover_stale_jobs(10);last_recovery=time.monotonic()
            repo.enqueue_due_schedules()
            if not process_one(repo,config,worker_id):time.sleep(poll_seconds)
        except KeyboardInterrupt:return
        except Exception:time.sleep(poll_seconds)
