import os,sys,tempfile
from datetime import datetime,timezone,timedelta
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from app.repository import Repository
from app.crypto import hash_password
from app.scanner.models import Finding

def finding(severity="HIGH",fingerprint="sla-hsts"):
    return Finding(
        "header.hsts","HTTP Strict Transport Security","Security Headers","FAIL",severity,"HIGH",
        "https://example.com/account","Strict-Transport-Security: not present","Checks HSTS",
        "Missing HSTS weakens downgrade protection","Deploy HSTS",["OWASP ASVS V9"],fingerprint,{}
    )

def setup_repo(path):
    r=Repository(path);r.init_schema()
    owner=r.create_signup("owner@example.com","Owner",hash_password("correct-horse-battery"),"Acme")
    p=r.create_project("Production","",owner["organization_id"],owner["user_id"])
    t=r.create_target(p["id"],"https://example.com/","Portal",True,True,owner["user_id"],"critical","production",["customer-facing"])
    return r,owner,p,t

def test_workspace_sla_policy_assigns_due_date_to_new_findings():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup_repo(os.path.join(d,"sla.sqlite3"))
        policy=r.set_workspace_security_policy(owner["organization_id"],{
            "sla_days":{"HIGH":9},"auto_due_dates":True,"require_owner_for_risk_acceptance":True
        },owner["user_id"])
        assert policy["sla_days"]["HIGH"]==9
        scan=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
        r.add_findings(scan["id"],[finding()])
        before=datetime.now(timezone.utc).date()
        r.sync_finding_states(scan["id"])
        row=r.list_finding_states(owner["organization_id"])[0]
        due=datetime.fromisoformat(row["due_at"]).date()
        assert 8 <= (due-before).days <= 9
        activity=r.finding_activity(row["id"],owner["organization_id"])
        assert activity and activity[0]["event"]=="CREATED"
        assert activity[0]["details"]["sla_due_at"]==row["due_at"]

def test_saved_views_bulk_triage_and_activity_are_persistent():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup_repo(os.path.join(d,"views.sqlite3"))
        for i,severity in enumerate(["HIGH","MEDIUM"]):
            scan=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
            r.add_findings(scan["id"],[finding(severity,f"issue-{i}")])
            r.sync_finding_states(scan["id"])
        rows=r.list_finding_states(owner["organization_id"])
        assert len(rows)==2

        view=r.create_issue_saved_view(owner["organization_id"],owner["user_id"],"High priority",{"severity":"HIGH","state":"ACTIVE"},True)
        listed=r.list_issue_saved_views(owner["organization_id"],owner["user_id"])
        assert listed[0]["id"]==view["id"] and listed[0]["is_shared"] is True
        updated_view=r.update_issue_saved_view(view["id"],owner["organization_id"],owner["user_id"],{"name":"High priority queue"},True)
        assert updated_view["name"]=="High priority queue"

        due=(datetime.now(timezone.utc)+timedelta(days=5)).date().isoformat()
        result=r.bulk_update_finding_states([x["id"] for x in rows],owner["organization_id"],{"state":"IN_PROGRESS","due_at":due},owner["user_id"])
        assert result["count"]==2
        after=r.list_finding_states(owner["organization_id"])
        assert all(x["state"]=="IN_PROGRESS" and x["due_at"]==due for x in after)
        assert all(any(a["event"]=="TRIAGE_UPDATED" for a in r.finding_activity(x["id"],owner["organization_id"])) for x in after)
        assert r.delete_issue_saved_view(view["id"],owner["organization_id"],owner["user_id"],True)

def test_activity_records_reopen_comment_and_auto_remediation():
    with tempfile.TemporaryDirectory() as d:
        r,owner,p,t=setup_repo(os.path.join(d,"activity.sqlite3"))
        s1=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
        r.add_findings(s1["id"],[finding()])
        r.sync_finding_states(s1["id"])
        state=r.list_finding_states(owner["organization_id"])[0]
        r.add_finding_comment(state["id"],owner["organization_id"],owner["user_id"],"Developer investigating")

        s2=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
        r.add_findings(s2["id"],[])
        r.sync_finding_states(s2["id"])
        assert r.get_finding_state(state["id"],owner["organization_id"])["state"]=="REMEDIATED"

        s3=r.create_scan(t["id"],t["url"],"standard",owner["user_id"],{})
        r.add_findings(s3["id"],[finding()])
        r.sync_finding_states(s3["id"])
        assert r.get_finding_state(state["id"],owner["organization_id"])["state"]=="OPEN"
        events=[x["event"] for x in r.finding_activity(state["id"],owner["organization_id"])]
        assert "COMMENT_ADDED" in events and "AUTO_REMEDIATED" in events and "REOPENED" in events
