import os,sys,tempfile
from datetime import datetime,timezone,timedelta
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

import pytest
from app.repository import Repository
from app.crypto import hash_password,token_hash

def setup_repo():
    td=tempfile.TemporaryDirectory()
    r=Repository(os.path.join(td.name,"bugs.sqlite3"));r.init_schema()
    owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
    p=r.create_project("Web","",owner["organization_id"],owner["user_id"])
    t=r.create_target(p["id"],"https://example.com/","Example",True,True,owner["user_id"])
    return td,r,owner,p,t

def test_permanent_target_delete_blocks_active_scan_and_schedule():
    td,r,owner,p,t=setup_repo()
    try:
        scan=r.create_scan(t["id"],t["url"],"quick",owner["user_id"],{})
        with pytest.raises(ValueError,match="queued or running"):
            r.delete_target(t["id"],owner["organization_id"])
        r.update_scan(scan["id"],status="COMPLETED",completed_at=r.now())
        schedule=r.create_schedule(t["id"],"quick",1440,owner["user_id"])
        with pytest.raises(ValueError,match="active schedules"):
            r.delete_target(t["id"],owner["organization_id"])
        assert r.set_schedule_enabled(schedule["id"],owner["organization_id"],False)
        assert r.delete_target(t["id"],owner["organization_id"])
        assert r.get_target(t["id"]) is None
    finally:
        td.cleanup()

def test_project_delete_cascades_profiles_and_enterprise_evidence():
    td,r,owner,p,t=setup_repo()
    try:
        profile=r.create_scan_profile(p["id"],"Production baseline","baseline","standard",r.get_project_policy(p["id"]),True,owner["user_id"])
        scan=r.create_scan(t["id"],t["url"],"quick",owner["user_id"],{})
        r.update_scan(scan["id"],status="COMPLETED",completed_at=r.now())
        with r.conn() as c:
            state_id="state-regression"
            c.execute("""insert into finding_states(
              id,target_id,fingerprint,check_id,title,state,severity_override,assignee_user_id,due_at,risk_reason,
              first_seen_at,last_seen_at,occurrences,last_scan_id,updated_by,updated_at,base_severity
            ) values(?,?,?,?,?,'OPEN',null,null,null,null,?,?,1,?,null,?,'MEDIUM')""",
            (state_id,t["id"],"fp","check.id","Issue",r.now(),r.now(),scan["id"],r.now()))
            c.execute("insert into finding_activity values(?,?,?,?,?,?)",("act",state_id,owner["user_id"],"CREATED","{}",r.now()))
            c.execute("insert into finding_escalations values(?,?,?,?,?,?)",("esc",state_id,owner["organization_id"],owner["user_id"],"overdue:test",r.now()))
            c.execute("insert into report_exports values(?,?,?,?,?,?,?)",("rep",owner["organization_id"],scan["id"],"json",owner["user_id"],"abc",10,r.now()))
        assert r.delete_project(p["id"],owner["organization_id"])
        with r.conn() as c:
            assert c.execute("select count(*) from scan_profiles where project_id=?",(p["id"],)).fetchone()[0]==0
            assert c.execute("select count(*) from scan_profile_versions where profile_id=?",(profile["id"],)).fetchone()[0]==0
            assert c.execute("select count(*) from finding_activity where finding_state_id='state-regression'").fetchone()[0]==0
            assert c.execute("select count(*) from finding_escalations where finding_state_id='state-regression'").fetchone()[0]==0
            assert c.execute("select count(*) from report_exports where scan_id=?",(scan["id"],)).fetchone()[0]==0
    finally:
        td.cleanup()

def test_member_deactivation_revokes_workspace_credentials_and_stale_ownership():
    td,r,owner,p,t=setup_repo()
    try:
        member=r.add_member(owner["organization_id"],"analyst@example.com","Analyst",hash_password("analyst-password-123"),"analyst")
        uid=member["user_id"]
        r.create_api_key(uid,owner["organization_id"],"automation",token_hash("wss_test_token"),"wss_test",["read"],None)
        with r.conn() as c:
            c.execute("update targets set owner_user_id=? where id=?",(uid,t["id"]))
            c.execute("""insert into finding_states(
              id,target_id,fingerprint,check_id,title,state,severity_override,assignee_user_id,due_at,risk_reason,
              first_seen_at,last_seen_at,occurrences,last_scan_id,updated_by,updated_at,base_severity
            ) values(?,?,?,?,?,'OPEN',null,?,null,null,?,?,1,null,null,?,'HIGH')""",
            ("state-member",t["id"],"fp-member","check.member","Issue",uid,r.now(),r.now(),r.now()))
        assert r.deactivate_member(owner["organization_id"],uid,False)
        with r.conn() as c:
            assert c.execute("select active from memberships where organization_id=? and user_id=?",(owner["organization_id"],uid)).fetchone()[0]==0
            assert c.execute("select revoked_at from api_keys where user_id=? and organization_id=?",(uid,owner["organization_id"])).fetchone()[0] is not None
            assert c.execute("select owner_user_id from targets where id=?",(t["id"],)).fetchone()[0] is None
            assert c.execute("select assignee_user_id from finding_states where id='state-member'").fetchone()[0] is None
    finally:
        td.cleanup()

def test_last_system_admin_cannot_delete_account():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"admin.sqlite3"));r.init_schema()
        owner=r.create_signup("root@example.com","Root",hash_password("correct-horse-battery"),"Root")
        r.set_system_admin(owner["user_id"],True)
        with pytest.raises(ValueError,match="last active system administrator"):
            r.delete_account(owner["user_id"])
        assert r.get_user_by_id(owner["user_id"]) is not None

def test_retention_clears_schedule_and_lifecycle_scan_references():
    td,r,owner,p,t=setup_repo()
    try:
        scan=r.create_scan(t["id"],t["url"],"quick",owner["user_id"],{})
        old=(datetime.now(timezone.utc)-timedelta(days=100)).isoformat()
        r.update_scan(scan["id"],status="COMPLETED",completed_at=old)
        schedule=r.create_schedule(t["id"],"quick",1440,owner["user_id"])
        with r.conn() as c:
            c.execute("update schedules set enabled=0 where id=?",(schedule["id"],))
            c.execute("insert into schedule_runs values(?,?,?,?,?,?)",("run-retention",schedule["id"],scan["id"],"COMPLETED",old,old))
            c.execute("""insert into finding_states(
              id,target_id,fingerprint,check_id,title,state,severity_override,assignee_user_id,due_at,risk_reason,
              first_seen_at,last_seen_at,occurrences,last_scan_id,updated_by,updated_at,base_severity
            ) values(?,?,?,?,?,'REMEDIATED',null,null,null,null,?,?,1,?,null,?,'LOW')""",
            ("state-retention",t["id"],"fp-retention","check.retention","Issue",old,old,scan["id"],old))
        assert r.purge_retention(90)==1
        with r.conn() as c:
            assert c.execute("select count(*) from schedule_runs where scan_id=?",(scan["id"],)).fetchone()[0]==0
            assert c.execute("select last_scan_id from finding_states where id='state-retention'").fetchone()[0] is None
    finally:
        td.cleanup()
