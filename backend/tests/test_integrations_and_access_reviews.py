import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from cryptography.fernet import Fernet
from app.repository import Repository
from app.crypto import hash_password,encrypt_secret
from app.worker import process_webhook

class FakeResponse:
    status_code=204
    text=""

def setup_repo(path):
    r=Repository(path);r.init_schema()
    owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
    analyst=r.add_member(owner["organization_id"],"analyst@example.com","Analyst",hash_password("analyst-password-123"),"analyst")
    return r,owner,analyst

def test_access_review_snapshot_decisions_and_enforcement():
    with tempfile.TemporaryDirectory() as d:
        r,owner,analyst=setup_repo(os.path.join(d,"access.sqlite3"))
        review=r.create_access_review(owner["organization_id"],"Quarterly access certification",owner["user_id"])
        assert review["summary"]["total"]==2 and review["summary"]["pending"]==2
        owner_item=next(x for x in review["items"] if x["user_id"]==owner["user_id"])
        analyst_item=next(x for x in review["items"] if x["user_id"]==analyst["user_id"])

        r.decide_access_review_item(review["id"],owner_item["id"],owner["organization_id"],"APPROVE","Owner retained",owner["user_id"])
        r.decide_access_review_item(review["id"],analyst_item["id"],owner["organization_id"],"REVOKE","Contract ended",owner["user_id"])
        completed=r.complete_access_review(review["id"],owner["organization_id"],owner["user_id"])
        assert completed["status"]=="COMPLETED" and completed["summary"]["revoke"]==1

        members={m["id"]:m for m in r.list_members(owner["organization_id"])}
        assert members[analyst["user_id"]]["active"]==0
        assert members[owner["user_id"]]["active"]==1

def test_access_review_owner_cannot_be_revoked():
    with tempfile.TemporaryDirectory() as d:
        r,owner,_=setup_repo(os.path.join(d,"owner.sqlite3"))
        review=r.create_access_review(owner["organization_id"],"Owner safety",owner["user_id"])
        owner_item=next(x for x in review["items"] if x["role_snapshot"]=="owner")
        try:
            r.decide_access_review_item(review["id"],owner_item["id"],owner["organization_id"],"REVOKE","No",owner["user_id"])
            assert False,"owner revocation should fail"
        except ValueError:
            pass

def test_webhook_queue_signing_delivery_and_history(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        r,owner,_=setup_repo(os.path.join(d,"webhook.sqlite3"))
        key=Fernet.generate_key().decode()
        secret="whsec_test_secret"
        endpoint=r.create_webhook_endpoint(owner["organization_id"],"SOC","https://example.com/hooks",
                                           encrypt_secret(secret,key),["scan.completed"],owner["user_id"])
        queued=r.emit_webhook_event(owner["organization_id"],"scan.completed",{"scan_id":"abc","score":91})
        assert len(queued)==1
        delivery=r.get_webhook_delivery(queued[0])
        assert delivery["status"]=="QUEUED"

        captured={}
        def fake_post(url,data,timeout,allow_redirects,headers):
            captured.update({"url":url,"data":data,"headers":headers,"allow_redirects":allow_redirects})
            return FakeResponse()
        import app.worker as worker
        monkeypatch.setattr(worker.requests,"post",fake_post)

        class Config:
            APP_ENCRYPTION_KEY=key
        process_webhook(r,Config,{"delivery_id":delivery["id"]})
        after=r.get_webhook_delivery(delivery["id"])
        assert after["status"]=="DELIVERED" and after["response_code"]==204 and after["attempts"]==1
        assert captured["allow_redirects"] is False
        assert captured["headers"]["X-SentinelScope-Event"]=="scan.completed"
        assert captured["headers"]["X-SentinelScope-Signature"].startswith("sha256=")
        history=r.list_webhook_deliveries(owner["organization_id"])
        assert history[0]["id"]==delivery["id"] and history[0]["status"]=="DELIVERED"


def test_report_export_ledger_preserves_hash_actor_and_scan_context():
    with tempfile.TemporaryDirectory() as d:
        r,owner,_=setup_repo(os.path.join(d,"reports.sqlite3"))
        p=r.create_project("Production","",owner["organization_id"],owner["user_id"])
        t=r.create_target(p["id"],"https://example.com/","Portal",True,True,owner["user_id"])
        scan=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
        r.update_scan(scan["id"],status="COMPLETED",score=88,completed_at=r.now())
        row=r.record_report_export(owner["organization_id"],scan["id"],"pdf",owner["user_id"],"a"*64,4096)
        history=r.list_report_exports(owner["organization_id"])
        assert history[0]["id"]==row["id"]
        assert history[0]["sha256"]=="a"*64 and history[0]["size_bytes"]==4096
        assert history[0]["user_email"]=="owner@example.com" and history[0]["target_url"]=="https://example.com/"
