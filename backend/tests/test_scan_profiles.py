import os,sys,tempfile
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app.repository import Repository
from app.crypto import hash_password

def setup(path):
    r=Repository(path);r.init_schema()
    owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
    p=r.create_project("Production","Customer-facing estate",owner["organization_id"],owner["user_id"],["production"])
    t=r.create_target(p["id"],"https://example.com/","Portal",True,True,owner["user_id"],"critical","production",["customer-facing"])
    return r,owner,p,t

def test_scan_profiles_are_versioned_and_scans_keep_immutable_provenance():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,"profiles.sqlite3"))
        profile=r.create_scan_profile(
            p["id"],"Production baseline","Low-impact production profile","standard",
            {"max_pages":25,"max_depth":2,"request_delay_ms":250,"include_paths":[],"exclude_paths":["^/logout$"],"disabled_checks":[]},
            True,owner["user_id"])
        assert profile["version"]==1 and profile["is_default"] is True

        updated=r.update_scan_profile(profile["id"],p["id"],{"policy":{**profile["policy"],"max_pages":30}},owner["user_id"])
        assert updated["version"]==2 and updated["policy"]["max_pages"]==30

        scan=r.create_scan(t["id"],t["url"],updated["scan_mode"],owner["user_id"],updated["policy"],updated["id"])
        stored=r.get_scan(scan["id"],owner["organization_id"])
        assert stored["scan_profile_name"]=="Production baseline"
        assert stored["scan_profile_version"]==2

        latest=r.update_scan_profile(profile["id"],p["id"],{"name":"Production baseline vNext"},owner["user_id"])
        assert latest["version"]==3
        historical=r.get_scan(scan["id"],owner["organization_id"])
        assert historical["scan_profile_name"]=="Production baseline"
        assert historical["scan_profile_version"]==2

def test_schedule_uses_current_named_profile_but_each_scan_snapshots_version():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,"schedule-profile.sqlite3"))
        profile=r.create_scan_profile(p["id"],"Daily baseline","Recurring safe profile","standard",
            {"max_pages":12,"max_depth":1,"request_delay_ms":400,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},
            True,owner["user_id"])
        schedule=r.create_schedule(t["id"],"standard",1440,owner["user_id"],"Daily baseline",True,profile["id"])
        first=r.run_schedule_now(schedule["id"],owner["organization_id"],owner["user_id"])
        first_stored=r.get_scan(first["id"],owner["organization_id"])
        assert first_stored["scan_profile_name"]=="Daily baseline"
        assert first_stored["scan_profile_version"]==1

        r.update_scan_profile(profile["id"],p["id"],{"description":"Updated recurring safe profile"},owner["user_id"])
        second=r.run_schedule_now(schedule["id"],owner["organization_id"],owner["user_id"])
        second_stored=r.get_scan(second["id"],owner["organization_id"])
        assert second_stored["scan_profile_version"]==2
        assert r.get_scan(first["id"],owner["organization_id"])["scan_profile_version"]==1

def test_target_accountability_metadata_is_persistent():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,"target-owner.sqlite3"))
        saved=r.update_target_metadata(t["id"],owner["organization_id"],{
            "owner_user_id":owner["user_id"],"notes":"Payments release window: Sundays 02:00 UTC","tags":["payments","customer-facing"]
        })
        assert saved["owner_user_id"]==owner["user_id"]
        assert "Payments release" in saved["notes"]
        assert sorted(saved["tags"])==["customer-facing","payments"]


def test_workspace_readiness_is_derived_from_real_persisted_state():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"readiness.sqlite3"));r.init_schema()
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
        initial=r.onboarding_state(owner["user_id"],owner["organization_id"])
        assert initial["percent"]==0 and initial["completed"] is False

        r.set_email_verified(owner["user_id"],True)
        p=r.create_project("Production","",owner["organization_id"],owner["user_id"],[])
        profile=r.ensure_default_scan_profile(p["id"],owner["user_id"])
        t=r.create_target(p["id"],"https://example.com/","Portal",True,False,owner["user_id"],"high","production",[])
        r.update_target_metadata(t["id"],owner["organization_id"],{"owner_user_id":owner["user_id"]})
        s=r.create_scan(t["id"],t["url"],profile["scan_mode"],owner["user_id"],profile["policy"],profile["id"])
        r.update_scan(s["id"],status="COMPLETED",stage="COMPLETED",progress=100,completed_at=r.now())

        ready=r.onboarding_state(owner["user_id"],owner["organization_id"])
        assert ready["completed"] is True and ready["percent"]==100
        hidden=r.set_onboarding_dismissed(owner["user_id"],owner["organization_id"],True)
        assert hidden["dismissed"] is True


def test_profile_version_ledger_restore_and_schedule_drift_guard():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,"profile-history.sqlite3"))
        profile=r.create_scan_profile(
            p["id"],"Release Gate","Governed release profile","standard",
            {"max_pages":18,"max_depth":2,"request_delay_ms":300,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},
            True,owner["user_id"])
        versions=r.scan_profile_versions(profile["id"],p["id"])
        assert [x["version"] for x in versions]==[1]

        v2=r.update_scan_profile(profile["id"],p["id"],{"policy":{**profile["policy"],"max_pages":28},"change_note":"Increase release coverage"},owner["user_id"])
        assert v2["version"]==2
        versions=r.scan_profile_versions(profile["id"],p["id"])
        assert [x["version"] for x in versions]==[2,1]
        assert versions[0]["change_note"]=="Increase release coverage"

        restored=r.restore_scan_profile_version(profile["id"],p["id"],1,owner["user_id"])
        assert restored["version"]==3
        assert restored["policy"]["max_pages"]==18
        assert r.scan_profile_versions(profile["id"],p["id"])[0]["change_note"]=="Restored from v1"

        schedule=r.create_schedule(t["id"],"standard",60,owner["user_id"],"Release hourly",True,profile["id"])
        usage=r.scan_profile_usage(profile["id"],p["id"])
        assert usage["enabled_schedules"]==1
        try:
            r.delete_scan_profile(profile["id"],p["id"],owner["user_id"])
            assert False,"archive should be blocked while schedule is enabled"
        except ValueError:
            pass

        r.set_schedule_enabled(schedule["id"],owner["organization_id"],False)
        assert r.delete_scan_profile(profile["id"],p["id"],owner["user_id"])
        archived=r.get_scan_profile(profile["id"])
        assert archived["active"] is False
        versions=r.scan_profile_versions(profile["id"],p["id"])
        assert versions[0]["active"] is False

def test_due_schedule_never_silently_falls_back_from_inactive_named_profile():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,"schedule-drift.sqlite3"))
        profile=r.create_scan_profile(
            p["id"],"Daily Safe","Bound recurring profile","standard",
            {"max_pages":10,"max_depth":1,"request_delay_ms":500,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},
            True,owner["user_id"])
        schedule=r.create_schedule(t["id"],"standard",60,owner["user_id"],"Daily Safe",True,profile["id"])
        r.create_scan_profile(p["id"],"Fallback","Keeps project configuration valid","quick",
            {"max_pages":1,"max_depth":0,"request_delay_ms":100,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},
            False,owner["user_id"])
        r.update_scan_profile(profile["id"],p["id"],{"active":False,"change_note":"Test drift guard"},owner["user_id"])
        with r.conn() as db:db.execute("update schedules set next_run_at=? where id=?",("2000-01-01T00:00:00+00:00",schedule["id"]))
        before=len(r.list_scans(100,owner["organization_id"]))
        r.enqueue_due_schedules()
        after=len(r.list_scans(100,owner["organization_id"]))
        current=r.get_schedule(schedule["id"],owner["organization_id"])
        assert after==before
        assert current["failure_count"]==1
        assert "inactive or missing" in current["last_error"]


def test_user_notifications_do_not_leak_between_workspaces():
    with tempfile.TemporaryDirectory() as d:
        r=Repository(os.path.join(d,"notification-isolation.sqlite3"));r.init_schema()
        owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Workspace A")
        org_a=owner["organization_id"];uid=owner["user_id"]
        org_b="org-secondary";membership="membership-secondary"
        with r.conn() as db:
            db.execute("insert into organizations(id,name,created_at,active) values(?,?,?,1)",(org_b,"Workspace B",r.now()))
            db.execute("insert into memberships(id,organization_id,user_id,role,created_at,active) values(?,?,?,?,?,1)",(membership,org_b,uid,"admin",r.now()))
        nid=r.add_notification(org_a,uid,"scan_failed","A-only alert","Only Workspace A should see this")
        assert nid
        assert any(x["id"]==nid for x in r.list_notifications(org_a,uid))
        assert not any(x["id"]==nid for x in r.list_notifications(org_b,uid))

def test_schedule_rebind_clears_configuration_drift_error():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,"schedule-rebind.sqlite3"))
        p1=r.create_scan_profile(p["id"],"Profile A","A","standard",{"max_pages":8,"max_depth":1,"request_delay_ms":200,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},True,owner["user_id"])
        p2=r.create_scan_profile(p["id"],"Profile B","B","standard",{"max_pages":12,"max_depth":1,"request_delay_ms":250,"include_paths":[],"exclude_paths":[],"disabled_checks":[]},False,owner["user_id"])
        s=r.create_schedule(t["id"],"standard",60,owner["user_id"],"Recurring",True,p1["id"])
        with r.conn() as db:db.execute("update schedules set last_error=? where id=?",("Schedule blocked: bound scan profile is inactive or missing",s["id"]))
        r.update_schedule(s["id"],owner["organization_id"],{"scan_profile_id":p2["id"],"profile":"standard"})
        current=r.get_schedule(s["id"],owner["organization_id"])
        assert current["last_error"] is None


def test_profile_active_invariant():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup(os.path.join(d,'active-profile.sqlite3'))
        first=r.ensure_default_scan_profile(p['id'],owner['user_id'])
        raised=False
        try:
            r.update_scan_profile(first['id'],p['id'],{'active':False},owner['user_id'])
        except ValueError:
            raised=True
        assert raised is True
        second=r.create_scan_profile(p['id'],'Secondary','Fallback','quick',{'max_pages':1,'max_depth':0,'request_delay_ms':100,'include_paths':[],'exclude_paths':[],'disabled_checks':[]},False,owner['user_id'])
        changed=r.update_scan_profile(first['id'],p['id'],{'active':False},owner['user_id'])
        assert changed['active'] is False
        assert r.get_scan_profile(second['id'])['is_default'] is True
