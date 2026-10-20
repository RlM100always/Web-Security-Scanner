import os
import socket
import time
import json
import hmac
import hashlib
import requests
from .scanner.engine import run_scan
from .mailer import send_email
from .crypto import decrypt_secret
from .security.targets import validate_target

class ScanCancelled(Exception): pass

def process_scan(repo, config, payload):
    scan=repo.get_scan(payload["scan_id"])
    if not scan: raise ValueError("Scan does not exist")
    if scan.get('status')=='COMPLETED':return "COMPLETED"
    if scan.get('status')=='CANCELLED':return "CANCELLED"
    target=repo.get_target(scan["target_id"])
    if not target: raise ValueError("Target does not exist")
    if repo.scan_cancel_requested(scan['id']):
        repo.update_scan(scan['id'],status='CANCELLED',stage='CANCELLED',progress=100,completed_at=repo.now(),error=None)
        repo.finalize_schedule_run(scan['id'],'CANCELLED')
        repo.add_scan_event(scan['id'],'STATE','CANCELLED',100,'Scan cancelled before execution')
        return 'CANCELLED'
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
        org_id=repo.target_organization(target['id'])
        if org_id:
            repo.emit_webhook_event(org_id,'scan.completed',{"scan_id":scan['id'],"target_id":target['id'],"target_url":target['url'],"score":result.score,"checks_run":result.checks_run,"pages_scanned":result.pages_scanned})
        if scan.get('created_by'):
            target_title=target.get('name') or target.get('url');org_id=repo.target_organization(target['id'])
            repo.add_notification(org_id,scan['created_by'],'scan_completed','Scan completed',f"{target_title} scored {result.score}/100",{"scan_id":scan['id']})
            user=repo.get_user_by_id(scan['created_by'])
            if user and (not org_id or repo.notification_enabled(scan['created_by'],org_id,'scan_completed','email')):
                try:send_email(vars(config),user['email'],'SentinelScope scan completed',f"{target_title}\nSecurity score: {result.score}/100")
                except Exception:pass
        return 'COMPLETED'
    except ScanCancelled:
        repo.update_scan(scan['id'],status='CANCELLED',stage='CANCELLED',progress=100,completed_at=repo.now(),error=None)
        repo.finalize_schedule_run(scan['id'],'CANCELLED')
        repo.add_scan_event(scan['id'],'STATE','CANCELLED',100,'Scan cancelled by administrator')
        return 'CANCELLED'
    except Exception as e:
        repo.update_scan(scan['id'],status='FAILED',stage='FAILED',progress=100,error=str(e)[:1000],completed_at=repo.now())
        schedule_ctx=repo.schedule_notification_context(scan['id'])
        repo.finalize_schedule_run(scan['id'],'FAILED')
        if schedule_ctx and schedule_ctx.get('notify_on_failure'):
            user=repo.get_user_by_id(schedule_ctx.get('created_by'))
            if user and repo.notification_enabled(schedule_ctx['created_by'],schedule_ctx['organization_id'],'schedule_failure','email'):
                try:send_email(vars(config),user['email'],'SentinelScope recurring assessment failed',f"{schedule_ctx.get('name') or schedule_ctx.get('target_name') or 'Scheduled assessment'} failed.\n\n{str(e)[:500]}")
                except Exception:pass
        repo.add_scan_event(scan['id'],'STATE','FAILED',100,'Scan failed',{"error":str(e)[:1000]})
        org_id=repo.target_organization(target['id'])
        if org_id:
            repo.emit_webhook_event(org_id,'scan.failed',{"scan_id":scan['id'],"target_id":target['id'],"target_url":target['url'],"error":str(e)[:500]})
        if scan.get('created_by'):
            org_id=repo.target_organization(target['id'])
            repo.add_notification(org_id,scan['created_by'],'scan_failed','Scan failed',str(e)[:300],{"scan_id":scan['id']})
            user=repo.get_user_by_id(scan['created_by'])
            if user and (not org_id or repo.notification_enabled(scan['created_by'],org_id,'scan_failed','email')):
                try:send_email(vars(config),user['email'],'SentinelScope scan failed',f"{target.get('name') or target.get('url')}\n\n{str(e)[:500]}")
                except Exception:pass
        raise


def process_webhook(repo, config, payload):
    delivery=repo.get_webhook_delivery(payload["delivery_id"])
    if not delivery: raise ValueError("Webhook delivery does not exist")
    if delivery.get("status")=="DELIVERED":return "DELIVERED"
    if delivery.get("status")=="CANCELLED":return "CANCELLED"
    if not delivery.get("endpoint_active"):
        repo.mark_webhook_delivery_cancelled(delivery["id"],"Webhook endpoint was paused before delivery")
        return "CANCELLED"
    repo.mark_webhook_delivery_running(delivery["id"])
    raw=json.dumps(delivery["payload"],separators=(",",":"),sort_keys=True).encode()
    try:
        secret=decrypt_secret(delivery.get("secret_ciphertext") or "",getattr(config,"APP_ENCRYPTION_KEY",""))
        signature=hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
        safe_url=validate_target(delivery["url"],getattr(config,"SCANNER_ALLOW_PRIVATE",False))
        response=requests.post(
            safe_url,data=raw,timeout=10,allow_redirects=False,stream=True,
            headers={
              "Content-Type":"application/json",
              "User-Agent":"SentinelScope-Webhooks/1.0",
              "X-SentinelScope-Event":delivery["event"],
              "X-SentinelScope-Delivery":delivery["id"],
              "X-SentinelScope-Signature":"sha256="+signature,
            }
        )
        cap=16_384;chunks=[];total=0;truncated=False
        for chunk in response.iter_content(4096,decode_unicode=False):
            total+=len(chunk)
            if total>cap:
                remaining=max(0,cap-sum(len(x) for x in chunks))
                if remaining:chunks.append(chunk[:remaining])
                truncated=True;break
            chunks.append(chunk)
        body=b"".join(chunks).decode(response.encoding or "utf-8",errors="replace")
        if truncated:body+="\n[SentinelScope: response body truncated at 16384 bytes]"
        if response.status_code<200 or response.status_code>=300:
            repo.mark_webhook_delivery_failure(delivery["id"],f"HTTP {response.status_code}",response.status_code,body)
            raise ValueError(f"Webhook endpoint returned HTTP {response.status_code}")
        repo.mark_webhook_delivery_success(delivery["id"],response.status_code,body)
        return "DELIVERED"
    except Exception as e:
        current=repo.get_webhook_delivery(delivery["id"])
        if current and current.get("status")!="DELIVERED":
            repo.mark_webhook_delivery_failure(delivery["id"],str(e),current.get("response_code"),current.get("response_body"))
        raise


def process_sla_escalations(repo,config):
    events=repo.process_overdue_finding_escalations()
    webhook_groups={}
    for event in events:
        uid=event.get('user_id');org_id=event.get('organization_id')
        user=repo.get_user_by_id(uid) if uid else None
        if user and repo.notification_enabled(uid,org_id,'finding_overdue','email'):
            try:send_email(vars(config),user['email'],'SentinelScope issue overdue',event['body'])
            except Exception:pass
        key=(org_id,event['finding_state_id'])
        webhook_groups[key]=event
    for (org_id,_),event in webhook_groups.items():
        repo.emit_webhook_event(org_id,'finding.overdue',{
          'finding_state_id':event['finding_state_id'],'target_id':event['target_id'],'title':event['title'],
          'severity':event['severity'],'due_at':event['due_at']
        })
    return len(events)

def process_one(repo, config, worker_id):
    job=repo.claim_job(worker_id)
    if not job:
        repo.worker_heartbeat(worker_id,worker_id.split(':')[0],int(worker_id.split(':')[-1]),'IDLE')
        return False
    repo.worker_heartbeat(worker_id,worker_id.split(':')[0],int(worker_id.split(':')[-1]),'BUSY',job['id'])
    try:
        if job['kind']=='scan':
            outcome=process_scan(repo,config,job['payload'])
            if outcome=='CANCELLED':repo.cancel_job(job['id'],'Scan cancelled')
            else:repo.finish_job(job['id'])
        elif job['kind']=='webhook':
            outcome=process_webhook(repo,config,job['payload'])
            if outcome=='CANCELLED':repo.cancel_job(job['id'],'Webhook delivery cancelled because endpoint is paused')
            else:repo.finish_job(job['id'])
        else:raise ValueError(f"Unknown job kind: {job['kind']}")
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
    last_recovery=time.monotonic();last_escalation=0.0
    while True:
        try:
            if time.monotonic()-last_recovery>=60:
                repo.recover_stale_jobs(10);last_recovery=time.monotonic()
            if time.monotonic()-last_escalation>=60:
                process_sla_escalations(repo,config);last_escalation=time.monotonic()
            repo.enqueue_due_schedules()
            if not process_one(repo,config,worker_id):time.sleep(poll_seconds)
        except KeyboardInterrupt:return
        except Exception:time.sleep(poll_seconds)
