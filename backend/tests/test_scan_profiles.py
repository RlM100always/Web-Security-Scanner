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
