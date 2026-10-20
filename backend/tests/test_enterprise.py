import json, os, sys, tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
from app.repository import Repository
from app.crypto import hash_password,verify_password
from app.zap import parse_zap_json,compare_with_scanner
from app.verification import make_verification
from app import worker as worker_module

def test_password_hash_roundtrip():
    h=hash_password('correct-horse-battery')
    assert verify_password('correct-horse-battery',h)
    assert not verify_password('wrong-password',h)

def test_sqlite_rbac_queue_and_audit():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,'db.sqlite3'));r.init_schema()
        owner=r.create_bootstrap_owner('owner@example.com','Owner',hash_password('very-secure-password'))
        p=r.create_project('P','',owner['organization_id'],owner['user_id'])
        t=r.create_target(p['id'],'https://example.com/','Example',True,False,owner['user_id'])
        s=r.create_scan(t['id'],t['url'],'quick',owner['user_id'])
        j=r.enqueue_job('scan',{'scan_id':s['id'],'target_id':t['id']})
        claimed=r.claim_job('test-worker')
        assert claimed['id']==j['id'] and claimed['payload']['scan_id']==s['id']
        r.finish_job(j['id']);assert r.queue_stats()['COMPLETED']==1
        r.audit(owner['organization_id'],owner['user_id'],'TEST','scan',s['id'],{'ok':True},'127.0.0.1')
        assert r.list_audit(owner['organization_id'])[0]['event']=='TEST'

def test_verification_challenge():
    token,instructions=make_verification('https://example.com','file')
    assert token.startswith('sentinelscope-verification=') and '.well-known' in instructions

def test_zap_parser_and_comparison():
    data={'site':[{'@name':'https://example.com','alerts':[{'pluginid':'10038','alert':'Content Security Policy (CSP) Header Not Set','riskdesc':'Medium','instances':[{'uri':'https://example.com/'}]}]}]}
    items=parse_zap_json(data)
    assert items[0]['mapped_check_id']=='header.content-security-policy'
    ours=[{'check_id':'header.content-security-policy','status':'FAIL'}]
    comp=compare_with_scanner(ours,items)
    assert comp['summary']['mapped_overlap']==1


def test_worker_preserves_cancelled_job_state(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,'cancel.sqlite3'));r.init_schema()
        owner=r.create_bootstrap_owner('owner2@example.com','Owner',hash_password('very-secure-password'))
        p=r.create_project('P','',owner['organization_id'],owner['user_id'])
        t=r.create_target(p['id'],'https://example.com/','Example',True,False,owner['user_id'])
        s=r.create_scan(t['id'],t['url'],'quick',owner['user_id'])
        job=r.enqueue_job('scan',{'scan_id':s['id'],'target_id':t['id']})

        def fake_process_scan(repo,config,payload):
            repo.update_scan(payload['scan_id'],status='CANCELLED',stage='CANCELLED',progress=100,completed_at=repo.now())
            return 'CANCELLED'

        monkeypatch.setattr(worker_module,'process_scan',fake_process_scan)
        class Config: pass
        assert worker_module.process_one(r,Config,'testhost:123') is True

        jobs={x['id']:x for x in r.admin_list_jobs()}
        assert jobs[job['id']]['status']=='CANCELLED'
        assert jobs[job['id']]['locked_by'] is None
        assert jobs[job['id']]['locked_at'] is None
        assert r.get_scan(s['id'])['status']=='CANCELLED'
