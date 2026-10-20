import json, sqlite3, uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta

class Repository:
    def __init__(self,path):
        self.path=path
        Path(path).parent.mkdir(parents=True,exist_ok=True)
    def conn(self):
        c=sqlite3.connect(self.path,check_same_thread=False,timeout=30)
        c.row_factory=sqlite3.Row
        c.execute("pragma journal_mode=WAL")
        c.execute("pragma foreign_keys=ON")
        c.execute("pragma busy_timeout=5000")
        return c
    def now(self): return datetime.now(timezone.utc).isoformat()
    def _id(self): return uuid.uuid4().hex
    def _ensure_column(self,c,table,column,ddl):
        cols={r["name"] for r in c.execute(f"pragma table_info({table})")}
        if column not in cols:c.execute(f"alter table {table} add column {column} {ddl}")
    def init_schema(self):
        with self.conn() as c:
            c.executescript("""
            create table if not exists users(
              id text primary key,email text not null unique,name text not null,password_hash text not null,
              active integer not null default 1,email_verified integer not null default 1,
              failed_logins integer not null default 0,locked_until text,last_login_at text,created_at text not null);
            create table if not exists organizations(id text primary key,name text not null,created_at text not null);
            create table if not exists memberships(
              id text primary key,organization_id text not null,user_id text not null,role text not null,
              created_at text not null,unique(organization_id,user_id),
              foreign key(organization_id) references organizations(id) on delete cascade,
              foreign key(user_id) references users(id) on delete cascade);
            create table if not exists sessions(
              id text primary key,user_id text not null,organization_id text not null,token_hash text not null unique,
              csrf_token text not null,expires_at text not null,created_at text not null,last_seen_at text not null,
              user_agent text,ip text,revoked_at text,
              foreign key(user_id) references users(id) on delete cascade);
            create table if not exists projects(
              id text primary key,name text not null,description text default '',organization_id text,created_by text,created_at text not null);
            create table if not exists targets(
              id text primary key,project_id text,url text not null,name text not null,authorized integer not null default 0,
              verified integer not null default 0,created_by text,created_at text not null);
            create table if not exists target_verifications(
              id text primary key,target_id text not null,method text not null,token text not null,instructions text,
              status text not null default 'PENDING',evidence text,created_by text,created_at text not null,verified_at text,
              foreign key(target_id) references targets(id) on delete cascade);
            create table if not exists scans(
              id text primary key,target_id text,target_url text,profile text,status text,progress integer default 0,stage text,
              score integer,pages_scanned integer,duration_ms integer,created_by text,created_at text,completed_at text,error text);
            create table if not exists findings(
              id text primary key,scan_id text,fingerprint text,check_id text,title text,category text,status text,severity text,
              confidence text,url text,evidence text,description text,impact text,remediation text,standards_json text,metadata_json text);
            create table if not exists scan_events(
              id integer primary key autoincrement,scan_id text not null,event_type text not null,stage text,progress integer,
              message text,data_json text,created_at text not null);
            create table if not exists jobs(
              id text primary key,kind text not null,payload_json text not null,status text not null default 'QUEUED',
              attempts integer not null default 0,max_attempts integer not null default 3,run_after text not null,
              locked_by text,locked_at text,last_error text,created_at text not null,completed_at text);
            create table if not exists schedules(
              id text primary key,target_id text not null,profile text not null,interval_minutes integer not null,
              enabled integer not null default 1,next_run_at text not null,created_by text,created_at text not null);
            create table if not exists schedule_runs(
              id text primary key,schedule_id text not null,scan_id text not null,status text not null,
              created_at text not null,completed_at text);
            create table if not exists zap_imports(
              id text primary key,scan_id text not null,filename text,items_json text not null,comparison_json text not null,
              created_by text,created_at text not null);
            create table if not exists audit_logs(
              id text primary key,organization_id text,user_id text,event text,resource_type text,resource_id text,
              details_json text,ip text,created_at text not null);
            create table if not exists auth_attempts(
              id integer primary key autoincrement,email text,ip text,success integer not null,created_at text not null);
            create table if not exists auth_tokens(
              id text primary key,user_id text not null,purpose text not null,token_hash text not null unique,
              expires_at text not null,used_at text,meta_json text,created_at text not null);
            create table if not exists mfa_recovery_codes(
              id text primary key,user_id text not null,code_hash text not null unique,used_at text,created_at text not null);
            create table if not exists invitations(
              id text primary key,organization_id text not null,email text not null,role text not null,token_hash text not null unique,
              status text not null default 'PENDING',invited_by text,expires_at text not null,accepted_at text,created_at text not null);
            create table if not exists notifications(
              id text primary key,organization_id text,user_id text,type text not null,title text not null,body text not null,
              read_at text,meta_json text,created_at text not null);
            create table if not exists notification_preferences(
              user_id text not null,organization_id text not null,preferences_json text not null,updated_at text not null,
              primary key(user_id,organization_id));
            create table if not exists backup_history(
              id text primary key,organization_id text,user_id text,filename text not null,size_bytes integer not null,
              created_at text not null);
            create table if not exists scan_policies(
              project_id text primary key,policy_json text not null,updated_by text,updated_at text not null);
            create table if not exists scan_profiles(
              id text primary key,project_id text not null,name text not null,description text not null default '',
              scan_mode text not null default 'standard',policy_json text not null,version integer not null default 1,
              is_default integer not null default 0,active integer not null default 1,created_by text,updated_by text,
              created_at text not null,updated_at text not null);
            create table if not exists sla_policies(
              organization_id text not null,severity text not null,due_hours integer not null,updated_by text,updated_at text not null,
              primary key(organization_id,severity));
            create table if not exists assets(
              id text primary key,scan_id text not null,target_id text not null,url text not null,kind text not null,
              status_code integer,content_type text,title text,depth integer not null,size_bytes integer not null,
              source_url text,metadata_json text not null,created_at text not null);
            create table if not exists finding_states(
              id text primary key,target_id text not null,fingerprint text not null,check_id text not null,title text not null,
              state text not null default 'OPEN',severity_override text,assignee_user_id text,due_at text,risk_reason text,
              first_seen_at text not null,last_seen_at text not null,occurrences integer not null default 1,
              last_scan_id text,updated_by text,updated_at text not null,unique(target_id,fingerprint));
            create table if not exists finding_comments(
              id text primary key,finding_state_id text not null,user_id text not null,body text not null,created_at text not null);
            create table if not exists finding_activity(
              id text primary key,finding_state_id text not null,user_id text,event text not null,details_json text not null,created_at text not null);
            create table if not exists workspace_security_policies(
              organization_id text primary key,policy_json text not null,updated_by text,updated_at text not null);
            create table if not exists issue_saved_views(
              id text primary key,organization_id text not null,user_id text not null,name text not null,filters_json text not null,
              is_shared integer not null default 0,created_at text not null,updated_at text not null);
            create table if not exists remediation_verifications(
              id text primary key,finding_state_id text not null,scan_id text not null,requested_by text not null,
              status text not null default 'QUEUED',created_at text not null,completed_at text);
            create table if not exists api_keys(
              id text primary key,user_id text not null,organization_id text not null,name text not null,token_hash text not null unique,
              prefix text not null,scopes_json text not null,expires_at text,last_used_at text,revoked_at text,created_at text not null);
            create table if not exists system_settings(
              key text primary key,value_json text not null,updated_by text,updated_at text not null);
            create table if not exists finding_escalations(
              id text primary key,finding_state_id text not null,organization_id text not null,user_id text not null,
              escalation_key text not null,created_at text not null,unique(finding_state_id,user_id,escalation_key));
            create table if not exists report_exports(
              id text primary key,organization_id text not null,scan_id text not null,format text not null,
              user_id text not null,sha256 text not null,size_bytes integer not null,created_at text not null);
            create table if not exists access_reviews(
              id text primary key,organization_id text not null,name text not null,status text not null default 'OPEN',
              created_by text not null,created_at text not null,completed_at text);
            create table if not exists access_review_items(
              id text primary key,review_id text not null,user_id text not null,role_snapshot text not null,
              decision text not null default 'PENDING',note text,reviewed_by text,reviewed_at text);
            create table if not exists webhook_endpoints(
              id text primary key,organization_id text not null,name text not null,url text not null,
              secret_ciphertext text not null,events_json text not null,active integer not null default 1,
              created_by text,created_at text not null,updated_at text not null);
            create table if not exists webhook_deliveries(
              id text primary key,endpoint_id text not null,event text not null,payload_json text not null,
              status text not null default 'QUEUED',response_code integer,response_body text,
              attempts integer not null default 0,last_error text,created_at text not null,completed_at text);
            create table if not exists worker_heartbeats(
              worker_id text primary key,hostname text,pid integer,status text,current_job_id text,
              started_at text not null,last_seen_at text not null);
            """)
            self._ensure_column(c,"memberships","active","integer not null default 1")
            self._ensure_column(c,"projects","organization_id","text")
            self._ensure_column(c,"projects","status","text not null default 'active'")
            self._ensure_column(c,"projects","tags_json","text not null default '[]'")
            self._ensure_column(c,"projects","created_by","text")
            self._ensure_column(c,"targets","created_by","text")
            self._ensure_column(c,"targets","environment","text not null default 'production'")
            self._ensure_column(c,"targets","criticality","text not null default 'medium'")
            self._ensure_column(c,"targets","owner_user_id","text")
            self._ensure_column(c,"targets","tags_json","text not null default '[]'")
            self._ensure_column(c,"targets","notes","text not null default ''")
            self._ensure_column(c,"targets","criticality","text not null default 'medium'")
            self._ensure_column(c,"targets","environment","text not null default 'production'")
            self._ensure_column(c,"targets","tags_json","text not null default '[]'")
            self._ensure_column(c,"scans","created_by","text")
            self._ensure_column(c,"users","mfa_enabled","integer not null default 0")
            self._ensure_column(c,"users","mfa_secret","text")
            self._ensure_column(c,"users","system_admin","integer not null default 0")
            self._ensure_column(c,"organizations","active","integer not null default 1")
            self._ensure_column(c,"scans","cancel_requested","integer not null default 0")
            self._ensure_column(c,"scans","policy_json","text")
            self._ensure_column(c,"scans","scan_profile_id","text")
            self._ensure_column(c,"schedules","scan_profile_id","text")
            self._ensure_column(c,"schedules","name","text")
            self._ensure_column(c,"schedules","last_run_at","text")
            self._ensure_column(c,"schedules","last_scan_id","text")
            self._ensure_column(c,"schedules","run_count","integer not null default 0")
            self._ensure_column(c,"schedules","failure_count","integer not null default 0")
            self._ensure_column(c,"schedules","notify_on_failure","integer not null default 1")
            self._ensure_column(c,"finding_states","base_severity","text not null default 'INFO'")
            self._ensure_column(c,"finding_states","risk_expires_at","text")
            self._ensure_column(c,"finding_states","risk_accepted_by","text")
            self._ensure_column(c,"audit_logs","organization_id","text")
            self._ensure_column(c,"audit_logs","user_id","text")
            self._ensure_column(c,"audit_logs","resource_type","text")
            self._ensure_column(c,"audit_logs","resource_id","text")
            self._ensure_column(c,"audit_logs","ip","text")
            c.execute("create index if not exists idx_projects_org on projects(organization_id)")
            c.execute("create index if not exists idx_jobs_queue on jobs(status,run_after)")
            c.execute("create index if not exists idx_events_scan on scan_events(scan_id,id)")
            c.execute("create index if not exists idx_schedule_runs_schedule on schedule_runs(schedule_id,created_at)")
            c.execute("create index if not exists idx_schedule_runs_scan on schedule_runs(scan_id)")
            c.execute("create index if not exists idx_audit_org on audit_logs(organization_id,created_at)")
            c.execute("create index if not exists idx_auth_attempts on auth_attempts(email,created_at)")
            c.execute("create index if not exists idx_auth_tokens on auth_tokens(user_id,purpose,expires_at)")
            c.execute("create index if not exists idx_mfa_recovery_user on mfa_recovery_codes(user_id,used_at)")
            c.execute("create index if not exists idx_invites_org on invitations(organization_id,status)")
            c.execute("create index if not exists idx_notifications_user on notifications(user_id,created_at)")
            c.execute("create index if not exists idx_finding_escalations_org on finding_escalations(organization_id,created_at)")
            c.execute("create index if not exists idx_report_exports_org on report_exports(organization_id,created_at)")
            c.execute("create index if not exists idx_report_exports_scan on report_exports(scan_id,created_at)")
            c.execute("create index if not exists idx_access_reviews_org on access_reviews(organization_id,created_at)")
            c.execute("create index if not exists idx_access_review_items_review on access_review_items(review_id,decision)")
            c.execute("create index if not exists idx_webhooks_org on webhook_endpoints(organization_id,active)")
            c.execute("create index if not exists idx_webhook_deliveries_endpoint on webhook_deliveries(endpoint_id,created_at)")
            c.execute("create index if not exists idx_scan_profiles_project on scan_profiles(project_id,active)")
            c.execute("create index if not exists idx_assets_scan on assets(scan_id)")
            c.execute("create index if not exists idx_assets_target on assets(target_id,url)")
            c.execute("create index if not exists idx_finding_states_target on finding_states(target_id,state,last_seen_at)")
            c.execute("create index if not exists idx_finding_comments_state on finding_comments(finding_state_id,created_at)")
            c.execute("create index if not exists idx_finding_activity_state on finding_activity(finding_state_id,created_at)")
            c.execute("create index if not exists idx_issue_saved_views_org on issue_saved_views(organization_id,user_id,updated_at)")
            c.execute("create index if not exists idx_remediation_scan on remediation_verifications(scan_id,status)")
            c.execute("create index if not exists idx_api_keys_org on api_keys(organization_id,revoked_at)")
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('registration_enabled','true',null,?)",(self.now(),))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('maintenance_mode','false',null,?)",(self.now(),))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('maintenance_message',?,null,?)",(json.dumps("SentinelScope is temporarily under maintenance."),self.now()))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('platform_name',?,null,?)",(json.dumps("SentinelScope"),self.now()))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('admin_banner',?,null,?)",(json.dumps(""),self.now()))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('scan_quota_per_day','100',null,?)",(self.now(),))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('max_concurrent_scans_per_org','3',null,?)",(self.now(),))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('scan_retention_days','90',null,?)",(self.now(),))
            c.execute("insert or ignore into system_settings(key,value_json,updated_by,updated_at) values('require_verified_email_for_scans','false',null,?)",(self.now(),))
    # auth / org
    def user_count(self):
        with self.conn() as c:return c.execute("select count(*) from users").fetchone()[0]
    def create_signup(self,email,name,password_hash,org_name):
        uid,oid,mid=self._id(),self._id(),self._id(); now=self.now()
        with self.conn() as c:
            c.execute("""insert into users(id,email,name,password_hash,active,email_verified,failed_logins,locked_until,last_login_at,created_at,mfa_enabled,mfa_secret)
            values(?,?,?,?,1,0,0,null,null,?,0,null)""",(uid,email.lower(),name,password_hash,now))
            c.execute("insert into organizations(id,name,created_at,active) values(?,?,?,1)",(oid,org_name,now))
            c.execute("insert into memberships(id,organization_id,user_id,role,created_at,active) values(?,?,?,?,?,1)",(mid,oid,uid,"owner",now))
        return {"user_id":uid,"organization_id":oid}
    def create_bootstrap_owner(self,email,name,password_hash):
        return self.create_signup(email,name,password_hash,"Default Workspace")
    def get_user_by_id(self,user_id):
        with self.conn() as c:r=c.execute("select * from users where id=?",(user_id,)).fetchone()
        return dict(r) if r else None

    def get_user_by_email(self,email):
        with self.conn() as c:r=c.execute("select * from users where lower(email)=lower(?)",(email,)).fetchone()
        return dict(r) if r else None
    def record_login_attempt(self,email,ip,success):
        with self.conn() as c:
            c.execute("insert into auth_attempts(email,ip,success,created_at) values(?,?,?,?)",(email.lower(),ip,int(success),self.now()))
    def recent_failed_attempts(self,email,ip,minutes=15):
        since=(datetime.now(timezone.utc)-timedelta(minutes=minutes)).isoformat()
        with self.conn() as c:
            return c.execute("select count(*) from auth_attempts where success=0 and created_at>=? and (lower(email)=lower(?) or ip=?)",(since,email,ip)).fetchone()[0]
    def set_login_success(self,user_id):
        with self.conn() as c:c.execute("update users set failed_logins=0,locked_until=null,last_login_at=? where id=?",(self.now(),user_id))
    def set_login_failure(self,user_id,lock=False):
        until=(datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat() if lock else None
        with self.conn() as c:c.execute("update users set failed_logins=failed_logins+1,locked_until=coalesce(?,locked_until) where id=?",(until,user_id))
    def create_session(self,user_id,organization_id,token_hash,csrf_token,ttl_hours,user_agent,ip):
        sid=self._id();now=self.now();exp=(datetime.now(timezone.utc)+timedelta(hours=ttl_hours)).isoformat()
        with self.conn() as c:c.execute("insert into sessions values(?,?,?,?,?,?,?,?,?,?,null)",(sid,user_id,organization_id,token_hash,csrf_token,exp,now,now,user_agent,ip))
        return {"id":sid,"expires_at":exp,"csrf_token":csrf_token}
    def session_identity(self,token_hash):
        now=self.now()
        with self.conn() as c:
            r=c.execute("""select s.id session_id,s.csrf_token,s.expires_at,u.id user_id,u.email,u.name,u.email_verified,u.mfa_enabled,u.system_admin,m.organization_id,m.role,o.name organization_name,o.active organization_active
            from sessions s join users u on u.id=s.user_id join memberships m on m.user_id=u.id and m.organization_id=s.organization_id
            join organizations o on o.id=m.organization_id
            where s.token_hash=? and s.revoked_at is null and s.expires_at>? and u.active=1
              and (m.active=1 or u.system_admin=1) and (o.active=1 or u.system_admin=1)""",(token_hash,now)).fetchone()
            if r:c.execute("update sessions set last_seen_at=? where id=?",(now,r["session_id"]))
        return dict(r) if r else None
    def update_user_password(self,user_id,password_hash):
        with self.conn() as c:c.execute("update users set password_hash=? where id=?",(password_hash,user_id))

    def list_sessions(self,user_id):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select id,created_at,last_seen_at,user_agent,ip,expires_at,revoked_at
            from sessions where user_id=? order by created_at desc""",(user_id,))]

    def revoke_other_sessions(self,user_id,current_session_id):
        with self.conn() as c:c.execute("update sessions set revoked_at=? where user_id=? and id<>? and revoked_at is null",(self.now(),user_id,current_session_id))

    def revoke_session(self,session_id):
        with self.conn() as c:c.execute("update sessions set revoked_at=? where id=?",(self.now(),session_id))
    def list_memberships_for_user(self,user_id):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select m.organization_id,m.role,o.name organization_name
            from memberships m join organizations o on o.id=m.organization_id
            where m.user_id=? and m.active=1 and o.active=1 order by m.created_at""",(user_id,))]

    def list_members(self,org_id):
        with self.conn() as c:return [dict(r) for r in c.execute("""select u.id,u.email,u.name,m.active,u.active account_active,m.role,m.created_at,u.last_login_at,u.email_verified,u.mfa_enabled
          from memberships m join users u on u.id=m.user_id where m.organization_id=? order by m.created_at""",(org_id,))]
    def member_activity(self,org_id,user_id,limit=100):
        with self.conn() as c:
            member=c.execute("select 1 from memberships where organization_id=? and user_id=?",(org_id,user_id)).fetchone()
            if not member:return None
            rows=[dict(r) for r in c.execute("""select a.*,actor.name actor_name,actor.email actor_email
              from audit_logs a left join users actor on actor.id=a.user_id
              where a.organization_id=? and ((a.resource_type='user' and a.resource_id=?) or a.user_id=?)
              order by a.created_at desc limit ?""",(org_id,user_id,user_id,limit))]
        for r in rows:
            try:r['details']=json.loads(r.pop('details_json') or '{}')
            except Exception:r['details']={}
        return rows

    def add_member(self,org_id,email,name,password_hash,role):
        user=self.get_user_by_email(email);now=self.now()
        with self.conn() as c:
            if not user:
                uid=self._id();c.execute("""insert into users(id,email,name,password_hash,active,email_verified,failed_logins,locked_until,last_login_at,created_at,mfa_enabled,mfa_secret)
                values(?,?,?,?,1,0,0,null,null,?,0,null)""",(uid,email.lower(),name,password_hash,now))
            else:uid=user["id"]
            c.execute("""insert into memberships(id,organization_id,user_id,role,created_at,active) values(?,?,?,?,?,1)
              on conflict(organization_id,user_id) do update set role=excluded.role,active=1""",(self._id(),org_id,uid,role,now))
        return {"user_id":uid,"email":email.lower(),"role":role}
    def update_member_role(self,org_id,user_id,role):
        with self.conn() as c:c.execute("update memberships set role=? where organization_id=? and user_id=?",(role,org_id,user_id))
    def set_email_verified(self,user_id,verified=True):
        with self.conn() as c:c.execute("update users set email_verified=? where id=?",(int(verified),user_id))

    def create_auth_token(self,user_id,purpose,token_hash,ttl_minutes,meta=None):
        now=self.now();exp=(datetime.now(timezone.utc)+timedelta(minutes=ttl_minutes)).isoformat()
        row={'id':self._id(),'user_id':user_id,'purpose':purpose,'token_hash':token_hash,'expires_at':exp,'used_at':None,'meta_json':json.dumps(meta or {}),'created_at':now}
        with self.conn() as c:
            c.execute("delete from auth_tokens where user_id=? and purpose=? and used_at is null",(user_id,purpose))
            c.execute("insert into auth_tokens values(?,?,?,?,?,?,?,?)",tuple(row.values()))
        return {'id':row['id'],'expires_at':exp}

    def consume_auth_token(self,purpose,token_hash):
        now=self.now()
        with self.conn() as c:
            c.execute("begin immediate")
            r=c.execute("select * from auth_tokens where purpose=? and token_hash=? and used_at is null and expires_at>?",(purpose,token_hash,now)).fetchone()
            if not r:c.commit();return None
            c.execute("update auth_tokens set used_at=? where id=?",(now,r['id']));c.commit()
        d=dict(r);d['meta']=json.loads(d.pop('meta_json') or '{}');return d

    def set_mfa(self,user_id,enabled,secret=None):
        with self.conn() as c:c.execute("update users set mfa_enabled=?,mfa_secret=? where id=?",(int(enabled),secret if enabled else None,user_id))

    def replace_mfa_recovery_codes(self,user_id,code_hashes):
        now=self.now()
        with self.conn() as c:
            c.execute("delete from mfa_recovery_codes where user_id=?",(user_id,))
            for h in code_hashes:c.execute("insert into mfa_recovery_codes(id,user_id,code_hash,used_at,created_at) values(?,?,?,null,?)",(self._id(),user_id,h,now))
        return len(code_hashes)

    def consume_mfa_recovery_code(self,user_id,code_hash):
        with self.conn() as c:
            c.execute("begin immediate")
            row=c.execute("select id from mfa_recovery_codes where user_id=? and code_hash=? and used_at is null",(user_id,code_hash)).fetchone()
            if not row:c.commit();return False
            c.execute("update mfa_recovery_codes set used_at=? where id=?",(self.now(),row['id']));c.commit();return True

    def unused_mfa_recovery_count(self,user_id):
        with self.conn() as c:return c.execute("select count(*) from mfa_recovery_codes where user_id=? and used_at is null",(user_id,)).fetchone()[0]

    def clear_mfa_recovery_codes(self,user_id):
        with self.conn() as c:c.execute("delete from mfa_recovery_codes where user_id=?",(user_id,))

    def revoke_user_session(self,user_id,session_id):
        with self.conn() as c:
            cur=c.execute("update sessions set revoked_at=? where id=? and user_id=? and revoked_at is null",(self.now(),session_id,user_id))
            return cur.rowcount>0

    def switch_session_workspace(self,session_id,user_id,organization_id):
        with self.conn() as c:
            ok=c.execute("""select 1 from memberships m join organizations o on o.id=m.organization_id
              where m.user_id=? and m.organization_id=? and m.active=1 and o.active=1""",(user_id,organization_id)).fetchone()
            if not ok:return False
            c.execute("update sessions set organization_id=?,last_seen_at=? where id=? and user_id=?",(organization_id,self.now(),session_id,user_id))
        return True

    def create_invitation(self,org_id,email,role,token_hash,invited_by,ttl_hours):
        now=self.now();exp=(datetime.now(timezone.utc)+timedelta(hours=ttl_hours)).isoformat()
        row={'id':self._id(),'organization_id':org_id,'email':email.lower(),'role':role,'token_hash':token_hash,'status':'PENDING','invited_by':invited_by,'expires_at':exp,'accepted_at':None,'created_at':now}
        with self.conn() as c:
            c.execute("update invitations set status='REVOKED' where organization_id=? and lower(email)=lower(?) and status='PENDING'",(org_id,email))
            c.execute("insert into invitations values(?,?,?,?,?,?,?,?,?,?)",tuple(row.values()))
        return row

    def consume_invitation(self,token_hash):
        now=self.now()
        with self.conn() as c:
            c.execute("begin immediate")
            r=c.execute("select * from invitations where token_hash=? and status='PENDING' and expires_at>?",(token_hash,now)).fetchone()
            if not r:c.commit();return None
            c.execute("update invitations set status='ACCEPTED',accepted_at=? where id=?",(now,r['id']));c.commit()
        return dict(r)

    def list_invitations(self,org_id):
        with self.conn() as c:return [dict(r) for r in c.execute("select id,email,role,status,expires_at,created_at from invitations where organization_id=? order by created_at desc",(org_id,))]

    def get_invitation(self,invite_id,org_id):
        with self.conn() as c:r=c.execute("select id,organization_id,email,role,status,expires_at,created_at from invitations where id=? and organization_id=?",(invite_id,org_id)).fetchone()
        return dict(r) if r else None

    def revoke_invitation(self,invite_id,org_id):
        with self.conn() as c:
            cur=c.execute("update invitations set status='REVOKED' where id=? and organization_id=? and status='PENDING'",(invite_id,org_id))
            return cur.rowcount>0

    def deactivate_member(self,org_id,user_id,active):
        with self.conn() as c:
            owner=c.execute("select role from memberships where organization_id=? and user_id=?",(org_id,user_id)).fetchone()
            if not owner:return False
            if owner['role']=='owner' and not active:return False
            c.execute("update memberships set active=? where organization_id=? and user_id=?",(int(active),org_id,user_id))
            if not active:c.execute("update sessions set revoked_at=? where organization_id=? and user_id=? and revoked_at is null",(self.now(),org_id,user_id))
        return True

    def remove_member(self,org_id,user_id):
        with self.conn() as c:
            row=c.execute("select role from memberships where organization_id=? and user_id=?",(org_id,user_id)).fetchone()
            if not row or row['role']=='owner':return False
            c.execute("delete from memberships where organization_id=? and user_id=?",(org_id,user_id))
            c.execute("update sessions set revoked_at=? where organization_id=? and user_id=? and revoked_at is null",(self.now(),org_id,user_id))
        return True

    def get_notification_preferences(self,user_id,org_id):
        defaults={'in_app_scan_completed':True,'in_app_scan_failed':True,'in_app_schedule_failure':True,'in_app_finding_overdue':True,
                  'email_scan_completed':True,'email_scan_failed':False,'email_schedule_failure':True,'email_finding_overdue':True}
        with self.conn() as c:r=c.execute("select preferences_json from notification_preferences where user_id=? and organization_id=?",(user_id,org_id)).fetchone()
        if not r:return defaults
        try:stored=json.loads(r['preferences_json'] or '{}')
        except Exception:stored={}
        for key in defaults:
            if key in stored:defaults[key]=bool(stored[key])
        return defaults

    def set_notification_preferences(self,user_id,org_id,updates):
        prefs=self.get_notification_preferences(user_id,org_id)
        for key in prefs:
            if key in updates:prefs[key]=bool(updates[key])
        with self.conn() as c:c.execute("""insert into notification_preferences(user_id,organization_id,preferences_json,updated_at)
          values(?,?,?,?) on conflict(user_id,organization_id) do update set preferences_json=excluded.preferences_json,updated_at=excluded.updated_at""",
          (user_id,org_id,json.dumps(prefs),self.now()))
        return prefs

    def notification_enabled(self,user_id,org_id,kind,channel='in_app'):
        if not user_id:return True
        prefs=self.get_notification_preferences(user_id,org_id)
        key=f"{channel}_{kind}"
        return prefs.get(key,True)

    def add_notification(self,org_id,user_id,kind,title,body,meta=None):
        effective_org=org_id
        if user_id and not effective_org:
            with self.conn() as c:
                m=c.execute("select organization_id from memberships where user_id=? and active=1 order by created_at limit 1",(user_id,)).fetchone()
                effective_org=m['organization_id'] if m else None
        if user_id and effective_org and not self.notification_enabled(user_id,effective_org,kind,'in_app'):return None
        row={'id':self._id(),'organization_id':org_id,'user_id':user_id,'type':kind,'title':title,'body':body,'read_at':None,'meta_json':json.dumps(meta or {}),'created_at':self.now()}
        with self.conn() as c:c.execute("insert into notifications values(?,?,?,?,?,?,?,?,?)",tuple(row.values()))
        return row['id']

    def list_notifications(self,org_id,user_id,limit=50):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from notifications where (organization_id=? or organization_id is null) and (user_id=? or user_id is null) order by created_at desc limit ?",(org_id,user_id,limit))]
        for r in rows:r['meta']=json.loads(r.pop('meta_json') or '{}')
        return rows

    def mark_notification_read(self,id,user_id):
        with self.conn() as c:c.execute("update notifications set read_at=? where id=? and (user_id=? or user_id is null)",(self.now(),id,user_id))

    def mark_all_notifications_read(self,org_id,user_id):
        with self.conn() as c:
            cur=c.execute("""update notifications set read_at=? where read_at is null
              and (organization_id=? or organization_id is null) and (user_id=? or user_id is null)""",(self.now(),org_id,user_id))
            return cur.rowcount

    def notification_counts(self,org_id,user_id):
        with self.conn() as c:
            total=c.execute("""select count(*) from notifications where (organization_id=? or organization_id is null)
              and (user_id=? or user_id is null)""",(org_id,user_id)).fetchone()[0]
            unread=c.execute("""select count(*) from notifications where read_at is null and (organization_id=? or organization_id is null)
              and (user_id=? or user_id is null)""",(org_id,user_id)).fetchone()[0]
        return {'total':total,'unread':unread}

    def record_backup(self,org_id,user_id,filename,size_bytes):
        with self.conn() as c:c.execute("insert into backup_history values(?,?,?,?,?,?)",(self._id(),org_id,user_id,filename,size_bytes,self.now()))

    def list_backups(self,org_id):
        with self.conn() as c:return [dict(r) for r in c.execute("select * from backup_history where organization_id=? order by created_at desc",(org_id,))]

    def delete_account(self,user_id):
        with self.conn() as c:
            memberships=[dict(r) for r in c.execute("select organization_id,role from memberships where user_id=?",(user_id,))]
            owned=[m['organization_id'] for m in memberships if m['role']=='owner']
            for org_id in owned:
                count=c.execute("select count(*) from memberships where organization_id=?",(org_id,)).fetchone()[0]
                if count>1:raise ValueError("Transfer or remove other workspace members before deleting an owner account")
        for org_id in owned:
            for p in self.list_projects(org_id):self.delete_project(p['id'],org_id)
            with self.conn() as c:
                c.execute("delete from audit_logs where organization_id=?",(org_id,))
                c.execute("delete from invitations where organization_id=?",(org_id,))
                c.execute("delete from notifications where organization_id=?",(org_id,))
                c.execute("delete from backup_history where organization_id=?",(org_id,))
                c.execute("delete from memberships where organization_id=?",(org_id,))
                c.execute("delete from organizations where id=?",(org_id,))
        with self.conn() as c:
            c.execute("delete from sessions where user_id=?",(user_id,))
            c.execute("delete from memberships where user_id=?",(user_id,))
            c.execute("delete from notifications where user_id=?",(user_id,))
            c.execute("delete from auth_tokens where user_id=?",(user_id,))
            c.execute("delete from mfa_recovery_codes where user_id=?",(user_id,))
            c.execute("delete from api_keys where user_id=?",(user_id,))
            c.execute("delete from users where id=?",(user_id,))

    def export_workspace(self,org_id):
        data={'organization':None,'members':self.list_members(org_id),'projects':self.list_projects(org_id),'targets':self.list_targets(org_id=org_id),'scans':self.list_scans(10000,org_id),'schedules':self.list_schedules(org_id),'audit':self.list_audit(org_id,10000)}
        with self.conn() as c:
            o=c.execute("select * from organizations where id=?",(org_id,)).fetchone()
            data['organization']=dict(o) if o else None
        return data

    # projects / targets
    def create_project(self,name,description='',organization_id=None,created_by=None,tags=None):
        x={'id':self._id(),'name':name,'description':description,'organization_id':organization_id,'created_by':created_by,'created_at':self.now(),'status':'active','tags_json':json.dumps(tags or [])}
        with self.conn() as c:c.execute("""insert into projects(id,name,description,organization_id,created_by,created_at,status,tags_json)
          values(?,?,?,?,?,?,?,?)""",(x['id'],x['name'],x['description'],x['organization_id'],x['created_by'],x['created_at'],x['status'],x['tags_json']))
        x['tags']=json.loads(x.pop('tags_json'));return x
    def _project_row(self,row):
        if not row:return None
        d=dict(row)
        try:d['tags']=json.loads(d.pop('tags_json') or '[]')
        except Exception:d['tags']=[]
        return d
    def list_projects(self,org_id=None):
        q="select * from projects";args=[]
        if org_id:q+=" where organization_id=?";args=[org_id]
        q+=" order by case status when 'active' then 0 else 1 end,created_at desc"
        with self.conn() as c:rows=c.execute(q,args).fetchall()
        return [self._project_row(r) for r in rows]
    def get_project(self,id,org_id=None):
        q="select * from projects where id=?";args=[id]
        if org_id:q+=" and organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        return self._project_row(r)
    def update_project(self,id,org_id,updates):
        allowed={'name','description','status','tags_json'};sets=[];vals=[]
        for k,v in updates.items():
            if k in allowed:sets.append(k+"=?");vals.append(v)
        if not sets:return self.get_project(id,org_id)
        with self.conn() as c:
            row=c.execute("select id from projects where id=? and organization_id=?",(id,org_id)).fetchone()
            if not row:return None
            vals.append(id);c.execute("update projects set "+",".join(sets)+" where id=?",vals)
            if updates.get('status')=='archived':
                c.execute("""update schedules set enabled=0 where target_id in (select id from targets where project_id=?)""",(id,))
        return self.get_project(id,org_id)
    def delete_project(self,id,org_id):
        with self.conn() as c:
            p=c.execute("select id from projects where id=? and organization_id=?",(id,org_id)).fetchone()
            if not p:return False
            tids=[r[0] for r in c.execute("select id from targets where project_id=?",(id,))]
            for tid in tids:
                sids=[r[0] for r in c.execute("select id from scans where target_id=?",(tid,))]
                state_ids=[r[0] for r in c.execute("select id from finding_states where target_id=?",(tid,))]
                for state_id in state_ids:
                    c.execute("delete from finding_comments where finding_state_id=?",(state_id,))
                    c.execute("delete from remediation_verifications where finding_state_id=?",(state_id,))
                c.execute("delete from finding_states where target_id=?",(tid,))
                for sid in sids:
                    c.execute("delete from assets where scan_id=?",(sid,))
                    c.execute("delete from remediation_verifications where scan_id=?",(sid,))
                    c.execute("delete from findings where scan_id=?",(sid,));c.execute("delete from scan_events where scan_id=?",(sid,));c.execute("delete from zap_imports where scan_id=?",(sid,));c.execute("delete from scans where id=?",(sid,))
                c.execute("delete from schedules where target_id=?",(tid,))
                c.execute("delete from target_verifications where target_id=?",(tid,));c.execute("delete from targets where id=?",(tid,))
            c.execute("delete from scan_policies where project_id=?",(id,))
            c.execute("delete from projects where id=?",(id,))
        return True
    def create_target(self,project_id,url,name,authorized=False,verified=False,created_by=None,criticality='medium',environment='production',tags=None):
        criticality=criticality if criticality in {'low','medium','high','critical'} else 'medium'
        environment=environment if environment in {'development','test','staging','production'} else 'production'
        x={'id':self._id(),'project_id':project_id,'url':url,'name':name,'authorized':int(authorized),'verified':int(verified),'created_by':created_by,'created_at':self.now(),'criticality':criticality,'environment':environment,'tags_json':json.dumps(tags or [])}
        with self.conn() as c:c.execute("""insert into targets(id,project_id,url,name,authorized,verified,created_by,created_at,criticality,environment,tags_json)
          values(?,?,?,?,?,?,?,?,?,?,?)""",(x['id'],x['project_id'],x['url'],x['name'],x['authorized'],x['verified'],x['created_by'],x['created_at'],x['criticality'],x['environment'],x['tags_json']))
        x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified']);x['tags']=json.loads(x.pop('tags_json'));return x
    def list_targets(self,project_id=None,org_id=None):
        q="select t.* from targets t join projects p on p.id=t.project_id where 1=1";args=[]
        if project_id:q+=" and t.project_id=?";args.append(project_id)
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        q+=" order by t.created_at desc"
        with self.conn() as c:out=[dict(r) for r in c.execute(q,args)]
        for x in out:
            x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified'])
            try:x['tags']=json.loads(x.pop('tags_json') or '[]')
            except Exception:x['tags']=[]
        return out
    def target_organization(self,target_id):
        with self.conn() as c:r=c.execute("""select p.organization_id from targets t join projects p on p.id=t.project_id where t.id=?""",(target_id,)).fetchone()
        return r['organization_id'] if r else None

    def get_target(self,id,org_id=None):
        q="select t.* from targets t join projects p on p.id=t.project_id where t.id=?";args=[id]
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        if not r:return None
        x=dict(r);x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified'])
        try:x['tags']=json.loads(x.pop('tags_json') or '[]')
        except Exception:x['tags']=[]
        return x
    def update_target(self,target_id,org_id,updates):
        allowed={'name','criticality','environment','tags_json'}
        sets=[];vals=[]
        for k,v in updates.items():
            if k in allowed:sets.append(k+"=?");vals.append(v)
        if not sets:return False
        with self.conn() as c:
            row=c.execute("""select t.id from targets t join projects p on p.id=t.project_id where t.id=? and p.organization_id=?""",(target_id,org_id)).fetchone()
            if not row:return False
            vals.append(target_id);c.execute("update targets set "+",".join(sets)+" where id=?",vals)
        return True

    def delete_target(self,target_id,org_id):
        with self.conn() as c:
            row=c.execute("""select t.id from targets t join projects p on p.id=t.project_id
            where t.id=? and p.organization_id=?""",(target_id,org_id)).fetchone()
            if not row:return False
            scan_ids=[r[0] for r in c.execute("select id from scans where target_id=?",(target_id,))]
            state_ids=[r[0] for r in c.execute("select id from finding_states where target_id=?",(target_id,))]
            for state_id in state_ids:
                c.execute("delete from finding_comments where finding_state_id=?",(state_id,))
                c.execute("delete from remediation_verifications where finding_state_id=?",(state_id,))
            c.execute("delete from finding_states where target_id=?",(target_id,))
            for sid in scan_ids:
                c.execute("delete from assets where scan_id=?",(sid,))
                c.execute("delete from remediation_verifications where scan_id=?",(sid,))
                c.execute("delete from findings where scan_id=?",(sid,))
                c.execute("delete from scan_events where scan_id=?",(sid,))
                c.execute("delete from zap_imports where scan_id=?",(sid,))
                c.execute("delete from scans where id=?",(sid,))
            c.execute("delete from schedules where target_id=?",(target_id,))
            c.execute("delete from target_verifications where target_id=?",(target_id,))
            c.execute("delete from targets where id=?",(target_id,))
        return True

    def set_target_verified(self,target_id,verified=True):
        with self.conn() as c:c.execute("update targets set verified=? where id=?",(int(verified),target_id))
    # asset governance and reusable scan profiles
    def update_target_metadata(self,target_id,org_id,updates):
        allowed={'name','environment','criticality','owner_user_id','notes'}
        sets=[];vals=[]
        for k,v in updates.items():
            if k in allowed:sets.append(k+"=?");vals.append(v)
        if 'tags' in updates:
            sets.append("tags_json=?");vals.append(json.dumps(sorted(set(str(x)[:64] for x in updates.get('tags',[]) if str(x).strip()))[:30]))
        if not sets:return self.get_target(target_id,org_id)
        with self.conn() as c:
            row=c.execute("""select t.id from targets t join projects p on p.id=t.project_id
              where t.id=? and p.organization_id=?""",(target_id,org_id)).fetchone()
            if not row:return None
            vals.append(target_id);c.execute("update targets set "+",".join(sets)+" where id=?",vals)
        return self.get_target(target_id,org_id)

    def create_scan_profile(self,project_id,name,description,scan_mode,policy,is_default,user_id):
        now=self.now();pid=self._id()
        with self.conn() as c:
            if is_default:c.execute("update scan_profiles set is_default=0 where project_id=?",(project_id,))
            c.execute("""insert into scan_profiles(id,project_id,name,description,scan_mode,policy_json,version,is_default,active,created_by,updated_by,created_at,updated_at)
              values(?,?,?,?,?,?,1,?,1,?,?,?,?,?)""",(pid,project_id,name,description,scan_mode,json.dumps(policy),int(is_default),user_id,user_id,now,now))
        return self.get_scan_profile(pid)

    def get_scan_profile(self,profile_id):
        with self.conn() as c:r=c.execute("select * from scan_profiles where id=?",(profile_id,)).fetchone()
        if not r:return None
        d=dict(r);d['policy']=json.loads(d.pop('policy_json') or '{}');d['is_default']=bool(d['is_default']);d['active']=bool(d['active']);return d

    def list_scan_profiles(self,project_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from scan_profiles where project_id=? order by is_default desc,updated_at desc",(project_id,))]
        for d in rows:
            d['policy']=json.loads(d.pop('policy_json') or '{}');d['is_default']=bool(d['is_default']);d['active']=bool(d['active'])
        return rows

    def update_scan_profile(self,profile_id,project_id,updates,user_id):
        current=self.get_scan_profile(profile_id)
        if not current or current['project_id']!=project_id:return None
        name=updates.get('name',current['name']);description=updates.get('description',current['description'])
        scan_mode=updates.get('scan_mode',current['scan_mode']);policy=updates.get('policy',current['policy'])
        is_default=bool(updates.get('is_default',current['is_default']));active=bool(updates.get('active',current['active']))
        with self.conn() as c:
            if is_default:c.execute("update scan_profiles set is_default=0 where project_id=? and id<>?",(project_id,profile_id))
            c.execute("""update scan_profiles set name=?,description=?,scan_mode=?,policy_json=?,version=version+1,is_default=?,active=?,updated_by=?,updated_at=?
              where id=? and project_id=?""",(name,description,scan_mode,json.dumps(policy),int(is_default),int(active),user_id,self.now(),profile_id,project_id))
        return self.get_scan_profile(profile_id)

    def clone_scan_profile(self,profile_id,project_id,user_id):
        current=self.get_scan_profile(profile_id)
        if not current or current['project_id']!=project_id:return None
        return self.create_scan_profile(project_id,current['name']+" Copy",current['description'],current['scan_mode'],current['policy'],False,user_id)

    def delete_scan_profile(self,profile_id,project_id):
        with self.conn() as c:
            r=c.execute("select is_default from scan_profiles where id=? and project_id=?",(profile_id,project_id)).fetchone()
            if not r:return False
            c.execute("delete from scan_profiles where id=?",(profile_id,))
        return True

    def ensure_default_scan_profile(self,project_id,user_id):
        rows=self.list_scan_profiles(project_id)
        if rows:return next((x for x in rows if x['is_default']),rows[0])
        return self.create_scan_profile(project_id,"Standard Baseline","Reusable default project assessment profile","standard",self.get_project_policy(project_id),True,user_id)

    def get_sla_policy(self,org_id):
        defaults={'CRITICAL':24,'HIGH':72,'MEDIUM':168,'LOW':720}
        with self.conn() as c:rows=c.execute("select severity,due_hours from sla_policies where organization_id=?",(org_id,))
        for r in rows:defaults[r['severity']]=r['due_hours']
        return defaults

    def set_sla_policy(self,org_id,rules,user_id):
        now=self.now()
        with self.conn() as c:
            for severity,hours in rules.items():
                if severity not in {'CRITICAL','HIGH','MEDIUM','LOW'}:continue
                c.execute("""insert into sla_policies(organization_id,severity,due_hours,updated_by,updated_at) values(?,?,?,?,?)
                  on conflict(organization_id,severity) do update set due_hours=excluded.due_hours,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                  (org_id,severity,max(1,min(int(hours),8760)),user_id,now))
        return self.get_sla_policy(org_id)

    # verification
    def create_verification(self,target_id,method,token,instructions,created_by):
        x={'id':self._id(),'target_id':target_id,'method':method,'token':token,'instructions':instructions,'status':'PENDING','evidence':None,'created_by':created_by,'created_at':self.now(),'verified_at':None}
        with self.conn() as c:c.execute("insert into target_verifications values(?,?,?,?,?,?,?,?,?,?)",tuple(x.values()))
        return x
    def get_verification(self,id):
        with self.conn() as c:r=c.execute("select * from target_verifications where id=?",(id,)).fetchone()
        return dict(r) if r else None
    def complete_verification(self,id,ok,evidence):
        now=self.now() if ok else None
        with self.conn() as c:c.execute("update target_verifications set status=?,evidence=?,verified_at=? where id=?",("VERIFIED" if ok else "FAILED",evidence,now,id))
    # deep scan policies
    def get_project_policy(self,project_id):
        defaults={'max_pages':20,'max_depth':2,'request_delay_ms':100,'include_paths':[],'exclude_paths':[],'disabled_checks':[]}
        with self.conn() as c:r=c.execute("select policy_json from scan_policies where project_id=?",(project_id,)).fetchone()
        if not r:return defaults
        try:stored=json.loads(r['policy_json'])
        except Exception:stored={}
        defaults.update(stored);return defaults

    def set_project_policy(self,project_id,policy,user_id):
        now=self.now()
        with self.conn() as c:c.execute("""insert into scan_policies(project_id,policy_json,updated_by,updated_at) values(?,?,?,?)
          on conflict(project_id) do update set policy_json=excluded.policy_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
          (project_id,json.dumps(policy),user_id,now))
        return self.get_project_policy(project_id)

    def scan_policy(self,scan_id):
        with self.conn() as c:r=c.execute("select policy_json from scans where id=?",(scan_id,)).fetchone()
        if not r:return {}
        try:return json.loads(r['policy_json'] or '{}')
        except Exception:return {}

    def organization_scan_usage(self,org_id):
        day=(datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
        with self.conn() as c:
            used=c.execute("""select count(*) from scans s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
              where p.organization_id=? and s.created_at>=?""",(org_id,day)).fetchone()[0]
            active=c.execute("""select count(*) from scans s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
              where p.organization_id=? and s.status in ('QUEUED','SCANNING')""",(org_id,)).fetchone()[0]
        return {'last_24h':used,'active':active}

    # scans / findings
    def create_scan(self,target_id,target_url,profile,created_by=None,policy=None,scan_profile_id=None):
        x={'id':self._id(),'target_id':target_id,'target_url':target_url,'profile':profile,'status':'QUEUED','progress':0,'stage':'QUEUED','score':None,'pages_scanned':None,'duration_ms':None,'created_by':created_by,'created_at':self.now(),'completed_at':None,'error':None,'cancel_requested':0,'policy_json':json.dumps(policy or {}),'scan_profile_id':scan_profile_id}
        with self.conn() as c:c.execute("""insert into scans(id,target_id,target_url,profile,status,progress,stage,score,pages_scanned,duration_ms,created_by,created_at,completed_at,error,cancel_requested,policy_json,scan_profile_id)
          values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(x['id'],x['target_id'],x['target_url'],x['profile'],x['status'],x['progress'],x['stage'],x['score'],x['pages_scanned'],x['duration_ms'],x['created_by'],x['created_at'],x['completed_at'],x['error'],x['cancel_requested'],x['policy_json'],x['scan_profile_id']))
        self.add_scan_event(x['id'],'STATE','QUEUED',0,'Scan queued')
        x['policy']=policy or {};x.pop('policy_json',None)
        return x
    def update_scan(self,id,**kw):
        if kw:
            with self.conn() as c:c.execute("update scans set "+','.join(f'{k}=?' for k in kw)+" where id=?",(*kw.values(),id))
    def add_findings(self,scan_id,findings):
        with self.conn() as c:
            c.execute("delete from findings where scan_id=?",(scan_id,))
            for f in findings:
                d=f.to_dict()
                c.execute("""insert into findings(id,scan_id,fingerprint,check_id,title,category,status,severity,confidence,url,evidence,description,impact,remediation,standards_json,metadata_json)
                  values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(self._id(),scan_id,d['fingerprint'],d['check_id'],d['title'],d['category'],d['status'],d['severity'],d['confidence'],d['url'],d['evidence'],d['description'],d['impact'],d['remediation'],json.dumps(d['standards']),json.dumps(d['metadata'])))
    def add_assets(self,scan_id,target_id,assets):
        with self.conn() as c:
            c.execute("delete from assets where scan_id=?",(scan_id,))
            for asset in assets:
                d=asset.to_dict() if hasattr(asset,'to_dict') else dict(asset)
                c.execute("""insert into assets(id,scan_id,target_id,url,kind,status_code,content_type,title,depth,size_bytes,source_url,metadata_json,created_at)
                  values(?,?,?,?,?,?,?,?,?,?,?,?,?)""",(self._id(),scan_id,target_id,d['url'],d['kind'],d.get('status_code'),d.get('content_type',''),d.get('title',''),int(d.get('depth',0)),int(d.get('size_bytes',0)),d.get('source_url'),json.dumps(d.get('metadata',{})),self.now()))

    def assets(self,scan_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from assets where scan_id=? order by depth,url",(scan_id,))]
        for r in rows:
            try:r['metadata']=json.loads(r.pop('metadata_json') or '{}')
            except Exception:r['metadata']={}
        return rows

    def get_workspace_security_policy(self,org_id):
        default={'sla_days':{'CRITICAL':7,'HIGH':14,'MEDIUM':30,'LOW':60,'INFO':90},
                 'require_owner_for_risk_acceptance':False,'auto_due_dates':True}
        with self.conn() as c:r=c.execute("select policy_json from workspace_security_policies where organization_id=?",(org_id,)).fetchone()
        if not r:return default
        try:stored=json.loads(r['policy_json'] or '{}')
        except Exception:stored={}
        if isinstance(stored.get('sla_days'),dict):default['sla_days'].update(stored['sla_days'])
        for key in ['require_owner_for_risk_acceptance','auto_due_dates']:
            if key in stored:default[key]=bool(stored[key])
        return default

    def set_workspace_security_policy(self,org_id,policy,user_id):
        current=self.get_workspace_security_policy(org_id)
        if isinstance(policy.get('sla_days'),dict):
            for severity,days in policy['sla_days'].items():
                sev=str(severity).upper()
                if sev in {'CRITICAL','HIGH','MEDIUM','LOW','INFO'}:current['sla_days'][sev]=max(1,min(int(days),3650))
        for key in ['require_owner_for_risk_acceptance','auto_due_dates']:
            if key in policy:current[key]=bool(policy[key])
        now=self.now()
        with self.conn() as c:c.execute("""insert into workspace_security_policies(organization_id,policy_json,updated_by,updated_at)
          values(?,?,?,?) on conflict(organization_id) do update set policy_json=excluded.policy_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
          (org_id,json.dumps(current),user_id,now))
        return current

    def add_finding_activity(self,state_id,user_id,event,details=None):
        row={'id':self._id(),'finding_state_id':state_id,'user_id':user_id,'event':event,'details_json':json.dumps(details or {}),'created_at':self.now()}
        with self.conn() as c:c.execute("insert into finding_activity values(?,?,?,?,?,?)",tuple(row.values()))
        return row['id']

    def finding_activity(self,state_id,org_id):
        if not self.get_finding_state(state_id,org_id):return []
        with self.conn() as c:rows=[dict(r) for r in c.execute("""select fa.*,u.name user_name,u.email user_email
          from finding_activity fa left join users u on u.id=fa.user_id where fa.finding_state_id=? order by fa.created_at desc limit 300""",(state_id,))]
        for r in rows:
            try:r['details']=json.loads(r.pop('details_json') or '{}')
            except Exception:r['details']={}
        return rows

    def list_issue_saved_views(self,org_id,user_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute("""select * from issue_saved_views
          where organization_id=? and (user_id=? or is_shared=1) order by is_shared desc,updated_at desc""",(org_id,user_id))]
        for r in rows:
            try:r['filters']=json.loads(r.pop('filters_json') or '{}')
            except Exception:r['filters']={}
            r['is_shared']=bool(r['is_shared'])
        return rows

    def create_issue_saved_view(self,org_id,user_id,name,filters,is_shared=False):
        row={'id':self._id(),'organization_id':org_id,'user_id':user_id,'name':name,'filters_json':json.dumps(filters or {}),
             'is_shared':int(bool(is_shared)),'created_at':self.now(),'updated_at':self.now()}
        with self.conn() as c:c.execute("insert into issue_saved_views values(?,?,?,?,?,?,?,?)",tuple(row.values()))
        return {'id':row['id'],'name':name,'filters':filters or {},'is_shared':bool(is_shared),'created_at':row['created_at'],'updated_at':row['updated_at']}

    def update_issue_saved_view(self,view_id,org_id,user_id,updates,can_admin=False):
        with self.conn() as c:
            row=c.execute("select * from issue_saved_views where id=? and organization_id=?",(view_id,org_id)).fetchone()
            if not row:return None
            if row['user_id']!=user_id and not can_admin:return None
            name=(updates.get('name') or row['name']).strip()[:80]
            try:filters=updates['filters'] if isinstance(updates.get('filters'),dict) else json.loads(row['filters_json'] or '{}')
            except Exception:filters={}
            shared=int(bool(updates['is_shared'])) if 'is_shared' in updates else row['is_shared']
            c.execute("update issue_saved_views set name=?,filters_json=?,is_shared=?,updated_at=? where id=?",(name,json.dumps(filters),shared,self.now(),view_id))
        return next((x for x in self.list_issue_saved_views(org_id,user_id) if x['id']==view_id),None)

    def delete_issue_saved_view(self,view_id,org_id,user_id,can_admin=False):
        with self.conn() as c:
            row=c.execute("select user_id from issue_saved_views where id=? and organization_id=?",(view_id,org_id)).fetchone()
            if not row or (row['user_id']!=user_id and not can_admin):return False
            return c.execute("delete from issue_saved_views where id=?",(view_id,)).rowcount>0

    def sync_finding_states(self,scan_id):
        scan=self.get_scan(scan_id)
        if not scan:return
        active=[f for f in self.findings(scan_id,with_lifecycle=False) if f['status'] in {'FAIL','WARNING','ERROR'}]
        with self.conn() as c:
            scope=c.execute("""select p.organization_id from targets t join projects p on p.id=t.project_id where t.id=?""",(scan['target_id'],)).fetchone()
        org_id=scope['organization_id'] if scope else None
        security_policy=self.get_workspace_security_policy(org_id) if org_id else {'sla_days':{},'auto_due_dates':False}
        now=self.now();fingerprints={f['fingerprint'] for f in active}
        activity=[]
        with self.conn() as c:
            for f in active:
                row=c.execute("select id,state from finding_states where target_id=? and fingerprint=?",(scan['target_id'],f['fingerprint'])).fetchone()
                if row:
                    new_state='OPEN' if row['state']=='REMEDIATED' else row['state']
                    c.execute("""update finding_states set state=?,check_id=?,title=?,base_severity=?,last_seen_at=?,occurrences=occurrences+1,last_scan_id=?,updated_at=?
                      where id=?""",(new_state,f['check_id'],f['title'],f['severity'],now,scan_id,now,row['id']))
                    if row['state']=='REMEDIATED':activity.append((row['id'],None,'REOPENED',{'scan_id':scan_id}))
                else:
                    state_id=self._id();due_at=None
                    if security_policy.get('auto_due_dates'):
                        days=int((security_policy.get('sla_days') or {}).get(str(f['severity']).upper(),30))
                        due_at=(datetime.now(timezone.utc)+timedelta(days=days)).date().isoformat()
                    c.execute("""insert into finding_states(id,target_id,fingerprint,check_id,title,state,severity_override,assignee_user_id,due_at,risk_reason,first_seen_at,last_seen_at,occurrences,last_scan_id,updated_by,updated_at,base_severity,risk_expires_at,risk_accepted_by)
                      values(?,?,?,?,?,'OPEN',null,null,?,null,?,?,1,?,null,?,?,null,null)""",(state_id,scan['target_id'],f['fingerprint'],f['check_id'],f['title'],due_at,now,now,scan_id,now,f['severity']))
                    activity.append((state_id,None,'CREATED',{'scan_id':scan_id,'sla_due_at':due_at}))
            rows=[dict(r) for r in c.execute("select id,fingerprint,state from finding_states where target_id=?",(scan['target_id'],))]
            for row in rows:
                if row['fingerprint'] not in fingerprints and row['state'] in {'OPEN','ACKNOWLEDGED','IN_PROGRESS'}:
                    c.execute("update finding_states set state='REMEDIATED',updated_at=? where id=?",(now,row['id']))
                    activity.append((row['id'],None,'AUTO_REMEDIATED',{'scan_id':scan_id}))
        for state_id,user_id,event,details in activity:self.add_finding_activity(state_id,user_id,event,details)

    def list_finding_states(self,org_id,state=None,target_id=None,limit=500):
        q="""select fs.*,t.name target_name,t.url target_url,t.criticality target_criticality,t.environment target_environment,
          p.name project_name,u.name assignee_name,u.email assignee_email
          from finding_states fs join targets t on t.id=fs.target_id join projects p on p.id=t.project_id
          left join users u on u.id=fs.assignee_user_id where p.organization_id=?""";args=[org_id]
        if state:q+=" and fs.state=?";args.append(state)
        if target_id:q+=" and fs.target_id=?";args.append(target_id)
        q+=" order by fs.last_seen_at desc limit ?";args.append(limit)
        with self.conn() as c:rows=[dict(r) for r in c.execute(q,args)]
        sev={'INFO':0,'LOW':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4};crit={'low':0,'medium':1,'high':2,'critical':3}
        now=datetime.now(timezone.utc)
        for r in rows:
            effective=(r.get('severity_override') or r.get('base_severity') or 'INFO').upper()
            score=sev.get(effective,0)*20+crit.get((r.get('target_criticality') or 'medium').lower(),1)*8+min(int(r.get('occurrences') or 1),10)
            if r.get('state')=='IN_PROGRESS':score-=3
            if r.get('state') in {'ACCEPTED_RISK','FALSE_POSITIVE','REMEDIATED'}:score-=30
            due=r.get('due_at')
            if due and r.get('state') not in {'FALSE_POSITIVE','REMEDIATED'}:
                try:
                    parsed=datetime.fromisoformat(due if 'T' in due else due+'T23:59:59+00:00')
                    if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
                    if parsed<now:score+=15
                except Exception:pass
            expired=False
            if r.get('state')=='ACCEPTED_RISK' and r.get('risk_expires_at'):
                try:
                    exp=datetime.fromisoformat(r['risk_expires_at'] if 'T' in r['risk_expires_at'] else r['risk_expires_at']+'T23:59:59+00:00')
                    if exp.tzinfo is None:exp=exp.replace(tzinfo=timezone.utc)
                    expired=exp<now
                    if expired:score+=25
                except Exception:pass
            r['effective_severity']=effective;r['risk_score']=max(0,score);r['risk_acceptance_expired']=expired
        rows.sort(key=lambda r:(r['state'] in {'REMEDIATED','FALSE_POSITIVE'},-r['risk_score'],-int(r.get('occurrences') or 0)))
        return rows

    def get_finding_state(self,state_id,org_id=None):
        q="""select fs.*,t.name target_name,t.url target_url,t.criticality target_criticality,t.environment target_environment,p.name project_name,p.organization_id
          from finding_states fs join targets t on t.id=fs.target_id join projects p on p.id=t.project_id where fs.id=?""";args=[state_id]
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        return dict(r) if r else None

    def update_finding_state(self,state_id,org_id,updates,user_id):
        allowed={'state','severity_override','assignee_user_id','due_at','risk_reason','risk_expires_at','risk_accepted_by'}
        sets=[];vals=[]
        for k,v in updates.items():
            if k in allowed:sets.append(k+"=?");vals.append(v)
        if not sets:return self.get_finding_state(state_id,org_id)
        before=self.get_finding_state(state_id,org_id)
        with self.conn() as c:
            exists=c.execute("""select fs.id from finding_states fs join targets t on t.id=fs.target_id join projects p on p.id=t.project_id
              where fs.id=? and p.organization_id=?""",(state_id,org_id)).fetchone()
            if not exists:return None
            vals.extend([user_id,self.now(),state_id]);c.execute("update finding_states set "+",".join(sets)+",updated_by=?,updated_at=? where id=?",vals)
        after=self.get_finding_state(state_id,org_id)
        changed={k:{'before':before.get(k) if before else None,'after':after.get(k) if after else None} for k in allowed if k in updates and (before or {}).get(k)!=(after or {}).get(k)}
        if changed:self.add_finding_activity(state_id,user_id,'TRIAGE_UPDATED',changed)
        return after

    def bulk_update_finding_states(self,state_ids,org_id,updates,user_id):
        unique=list(dict.fromkeys([str(x) for x in state_ids if x]))[:250]
        changed=[];missing=[]
        for state_id in unique:
            row=self.update_finding_state(state_id,org_id,updates,user_id)
            if row:changed.append(row)
            else:missing.append(state_id)
        return {'updated':changed,'missing':missing,'count':len(changed)}

    def add_finding_comment(self,state_id,org_id,user_id,body):
        if not self.get_finding_state(state_id,org_id):return None
        row={'id':self._id(),'finding_state_id':state_id,'user_id':user_id,'body':body,'created_at':self.now()}
        with self.conn() as c:c.execute("insert into finding_comments values(?,?,?,?,?)",tuple(row.values()))
        self.add_finding_activity(state_id,user_id,'COMMENT_ADDED',{'comment_id':row['id']})
        return row

    def finding_comments(self,state_id,org_id):
        if not self.get_finding_state(state_id,org_id):return []
        with self.conn() as c:return [dict(r) for r in c.execute("""select fc.*,u.name user_name,u.email user_email from finding_comments fc
          join users u on u.id=fc.user_id where fc.finding_state_id=? order by fc.created_at""",(state_id,))]

    def create_remediation_verification(self,state_id,scan_id,user_id):
        row={'id':self._id(),'finding_state_id':state_id,'scan_id':scan_id,'requested_by':user_id,'status':'QUEUED','created_at':self.now(),'completed_at':None}
        with self.conn() as c:c.execute("insert into remediation_verifications values(?,?,?,?,?,?,?)",tuple(row.values()))
        return row

    def finalize_remediation_verifications(self,scan_id):
        scan=self.get_scan(scan_id)
        if not scan:return
        present={f['fingerprint'] for f in self.findings(scan_id,with_lifecycle=False) if f['status'] in {'FAIL','WARNING','ERROR'}}
        with self.conn() as c:
            rows=[dict(r) for r in c.execute("""select rv.id,rv.finding_state_id,fs.fingerprint from remediation_verifications rv
              join finding_states fs on fs.id=rv.finding_state_id where rv.scan_id=? and rv.status='QUEUED'""",(scan_id,))]
            for r in rows:
                fixed=r['fingerprint'] not in present;status='VERIFIED_FIXED' if fixed else 'STILL_PRESENT'
                c.execute("update remediation_verifications set status=?,completed_at=? where id=?",(status,self.now(),r['id']))
                if fixed:c.execute("update finding_states set state='REMEDIATED',updated_at=? where id=?",(self.now(),r['finding_state_id']))

    def remediation_history(self,state_id,org_id):
        if not self.get_finding_state(state_id,org_id):return []
        with self.conn() as c:return [dict(r) for r in c.execute("select * from remediation_verifications where finding_state_id=? order by created_at desc",(state_id,))]

    def get_scan(self,id,org_id=None):
        q="select s.* from scans s join targets t on t.id=s.target_id join projects p on p.id=t.project_id where s.id=?";args=[id]
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        return dict(r) if r else None
    def list_scans(self,limit=100,org_id=None):
        q="select s.* from scans s join targets t on t.id=s.target_id join projects p on p.id=t.project_id";args=[]
        if org_id:q+=" where p.organization_id=?";args.append(org_id)
        q+=" order by s.created_at desc limit ?";args.append(limit)
        with self.conn() as c:return [dict(r) for r in c.execute(q,args)]
    def findings(self,scan_id,with_lifecycle=True):
        if with_lifecycle:
            q="""select f.*,fs.id lifecycle_id,fs.state lifecycle_state,fs.severity_override,fs.assignee_user_id,fs.due_at,fs.risk_reason,fs.first_seen_at,fs.last_seen_at,fs.occurrences
              from findings f join scans s on s.id=f.scan_id left join finding_states fs on fs.target_id=s.target_id and fs.fingerprint=f.fingerprint
              where f.scan_id=? order by case f.severity when 'CRITICAL' then 5 when 'HIGH' then 4 when 'MEDIUM' then 3 when 'LOW' then 2 else 1 end desc,f.title"""
        else:
            q="""select f.* from findings f where f.scan_id=? order by case f.severity when 'CRITICAL' then 5 when 'HIGH' then 4 when 'MEDIUM' then 3 when 'LOW' then 2 else 1 end desc,f.title"""
        with self.conn() as c:rows=[dict(r) for r in c.execute(q,(scan_id,))]
        for r in rows:
            r['standards']=json.loads(r.pop('standards_json'));r['metadata']=json.loads(r.pop('metadata_json'))
        return rows
    def latest_assets_for_org(self,org_id,limit=2000):
        with self.conn() as c:
            rows=[dict(r) for r in c.execute("""select a.*,t.name target_name,t.url target_url,p.name project_name,s.score scan_score,s.completed_at scan_completed_at
              from assets a join scans s on s.id=a.scan_id join targets t on t.id=a.target_id join projects p on p.id=t.project_id
              where p.organization_id=? and s.status='COMPLETED' and s.id=(
                select s2.id from scans s2 where s2.target_id=a.target_id and s2.status='COMPLETED'
                order by s2.created_at desc limit 1
              )
              order by p.name,t.name,a.depth,a.url limit ?""",(org_id,limit))]
        for r in rows:
            try:r['metadata']=json.loads(r.pop('metadata_json') or '{}')
            except Exception:r['metadata']={}
        return rows

    def asset_portfolio_summary(self,org_id):
        assets=self.latest_assets_for_org(org_id,10000)
        return {
          'total':len(assets),
          'html':sum(1 for a in assets if a.get('kind')=='html'),
          'json':sum(1 for a in assets if a.get('kind')=='json'),
          'redirected':sum(1 for a in assets if (a.get('metadata') or {}).get('redirects')),
          'truncated':sum(1 for a in assets if (a.get('metadata') or {}).get('truncated')),
          'targets':len({a.get('target_id') for a in assets}),
          'projects':len({a.get('project_name') for a in assets}),
        }

    def finding_portfolio_summary(self,org_id):
        rows=self.list_finding_states(org_id,limit=5000)
        counts={}
        for r in rows:counts[r['state']]=counts.get(r['state'],0)+1
        overdue=0;now=datetime.now(timezone.utc)
        for r in rows:
            due=r.get('due_at')
            if due and r.get('state') not in {'REMEDIATED','FALSE_POSITIVE'}:
                try:
                    parsed=datetime.fromisoformat(due if 'T' in due else due+'T23:59:59+00:00')
                    if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
                    if parsed<now:overdue+=1
                except Exception:pass
        return {'total':len(rows),'states':counts,'overdue':overdue,'assigned':sum(1 for r in rows if r.get('assignee_user_id'))}

    def asset_history(self,org_id,target_id,url,limit=100):
        with self.conn() as c:
            target=c.execute("""select t.*,p.name project_name,p.organization_id from targets t join projects p on p.id=t.project_id
              where t.id=? and p.organization_id=?""",(target_id,org_id)).fetchone()
            if not target:return None
            rows=[dict(r) for r in c.execute("""select a.*,s.created_at scan_created_at,s.completed_at,s.score,s.profile,s.status scan_status
              from assets a join scans s on s.id=a.scan_id where a.target_id=? and a.url=?
              order by s.created_at desc limit ?""",(target_id,url,limit))]
        for r in rows:
            try:r['metadata']=json.loads(r.pop('metadata_json') or '{}')
            except Exception:r['metadata']={}
        latest=rows[0] if rows else None
        return {'target':dict(target),'latest':latest,'history':rows,
                'summary':{'occurrences':len(rows),'first_seen':rows[-1]['scan_created_at'] if rows else None,
                           'last_seen':rows[0]['scan_created_at'] if rows else None,
                           'status_changes':sum(1 for i in range(1,len(rows)) if rows[i-1].get('status_code')!=rows[i].get('status_code')),
                           'content_type_changes':sum(1 for i in range(1,len(rows)) if rows[i-1].get('content_type')!=rows[i].get('content_type'))}}

    def asset_comparison(self,scan_id):
        current=self.get_scan(scan_id)
        if not current:return {}
        with self.conn() as c:
            prev=c.execute("select id from scans where target_id=? and status='COMPLETED' and id<>? and created_at<? order by created_at desc limit 1",(current['target_id'],scan_id,current['created_at'])).fetchone()
        cur={a['url']:a for a in self.assets(scan_id)};old={a['url']:a for a in self.assets(prev['id'])} if prev else {}
        added=sorted(set(cur)-set(old));removed=sorted(set(old)-set(cur));changed=[]
        for url in sorted(set(cur)&set(old)):
            diffs={}
            for key in ['status_code','content_type','title']:
                if cur[url].get(key)!=old[url].get(key):diffs[key]={'before':old[url].get(key),'after':cur[url].get(key)}
            before_size=int(old[url].get('size_bytes') or 0);after_size=int(cur[url].get('size_bytes') or 0)
            if abs(after_size-before_size)>=max(512,int(max(1,before_size)*0.10)):
                diffs['size_bytes']={'before':before_size,'after':after_size}
            if diffs:changed.append({'url':url,'changes':diffs})
        return {'previous_scan_id':prev['id'] if prev else None,'added':added,'removed':removed,'changed':changed,
                'summary':{'added':len(added),'removed':len(removed),'changed':len(changed),'current_assets':len(cur)}}

    def standards_summary(self,scan_id):
        summary={}
        for f in self.findings(scan_id,with_lifecycle=False):
            for standard in f.get('standards') or []:
                row=summary.setdefault(standard,{'checks':set(),'PASS':0,'WARNING':0,'FAIL':0,'ERROR':0,'INFO':0,'NOT_APPLICABLE':0})
                row['checks'].add(f['check_id']);row[f['status']]=row.get(f['status'],0)+1
        out=[]
        for standard,row in sorted(summary.items()):
            checks=len(row.pop('checks'));active=row.get('FAIL',0)+row.get('WARNING',0)+row.get('ERROR',0)
            out.append({'standard':standard,'mapped_checks':checks,'active_findings':active,**row})
        return out

    def finding_timeline(self,state_id,org_id):
        state=self.get_finding_state(state_id,org_id)
        if not state:return []
        with self.conn() as c:
            rows=[dict(r) for r in c.execute("""select s.id scan_id,s.created_at,s.completed_at,s.score,f.status,f.severity,f.confidence,f.evidence
              from scans s join findings f on f.scan_id=s.id where s.target_id=? and f.fingerprint=?
              order by s.created_at desc limit 100""",(state['target_id'],state['fingerprint']))]
        return rows

    def comparison(self,scan_id):
        current=self.get_scan(scan_id)
        if not current:return {}
        with self.conn() as c:prev=c.execute("select id from scans where target_id=? and status='COMPLETED' and id<>? and created_at<? order by created_at desc limit 1",(current['target_id'],scan_id,current['created_at'])).fetchone()
        cur={x['fingerprint'] for x in self.findings(scan_id) if x['status'] in {'FAIL','WARNING','ERROR'}};old={x['fingerprint'] for x in self.findings(prev['id']) if x['status'] in {'FAIL','WARNING','ERROR'}} if prev else set()
        return {'previous_scan_id':prev['id'] if prev else None,'new':len(cur-old),'fixed':len(old-cur),'unchanged':len(cur&old)}
    # events / queue / schedules
    def add_scan_event(self,scan_id,event_type,stage,progress,message,data=None):
        with self.conn() as c:c.execute("insert into scan_events(scan_id,event_type,stage,progress,message,data_json,created_at) values(?,?,?,?,?,?,?)",(scan_id,event_type,stage,progress,message,json.dumps(data or {}),self.now()))
    def scan_events(self,scan_id,after=0):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from scan_events where scan_id=? and id>? order by id",(scan_id,after))]
        for r in rows:r['data']=json.loads(r.pop('data_json') or '{}')
        return rows
    def enqueue_job(self,kind,payload,run_after=None,max_attempts=3):
        x={'id':self._id(),'kind':kind,'payload_json':json.dumps(payload),'status':'QUEUED','attempts':0,'max_attempts':max_attempts,'run_after':run_after or self.now(),'locked_by':None,'locked_at':None,'last_error':None,'created_at':self.now(),'completed_at':None}
        with self.conn() as c:c.execute("insert into jobs values(?,?,?,?,?,?,?,?,?,?,?,?)",tuple(x.values()))
        return {'id':x['id'],'kind':kind,'status':'QUEUED','payload':payload}
    def claim_job(self,worker_id):
        now=self.now()
        with self.conn() as c:
            c.execute("begin immediate")
            r=c.execute("select * from jobs where status='QUEUED' and run_after<=? order by created_at limit 1",(now,)).fetchone()
            if not r:c.commit();return None
            c.execute("update jobs set status='RUNNING',attempts=attempts+1,locked_by=?,locked_at=? where id=? and status='QUEUED'",(worker_id,now,r['id']))
            c.commit();row=c.execute("select * from jobs where id=?",(r['id'],)).fetchone()
        d=dict(row);d['payload']=json.loads(d.pop('payload_json'));return d
    def finish_job(self,id):
        with self.conn() as c:c.execute("update jobs set status='COMPLETED',completed_at=?,locked_by=null where id=?",(self.now(),id))
    def fail_job(self,id,error,retry=True):
        with self.conn() as c:
            r=c.execute("select attempts,max_attempts from jobs where id=?",(id,)).fetchone()
            status='QUEUED' if retry and r and r['attempts']<r['max_attempts'] else 'FAILED'
            attempts=int(r['attempts']) if r else 1
            delay_seconds=min(900,15*(2**max(0,attempts-1)))
            run_after=(datetime.now(timezone.utc)+timedelta(seconds=delay_seconds)).isoformat()
            c.execute("update jobs set status=?,run_after=?,last_error=?,locked_by=null,locked_at=null,completed_at=? where id=?",(status,run_after,error[:1000],None if status=='QUEUED' else self.now(),id))
    def queue_stats(self):
        with self.conn() as c:return {r['status']:r['n'] for r in c.execute("select status,count(*) n from jobs group by status")}
    def create_schedule(self,target_id,profile,interval_minutes,created_by,name=None,notify_on_failure=True):
        x={'id':self._id(),'target_id':target_id,'profile':profile,'interval_minutes':interval_minutes,'enabled':1,'next_run_at':(datetime.now(timezone.utc)+timedelta(minutes=interval_minutes)).isoformat(),'created_by':created_by,'created_at':self.now(),
           'name':(name or '').strip()[:160] or None,'last_run_at':None,'last_scan_id':None,'run_count':0,'failure_count':0,'notify_on_failure':int(bool(notify_on_failure))}
        with self.conn() as c:c.execute("""insert into schedules(id,target_id,profile,interval_minutes,enabled,next_run_at,created_by,created_at,name,last_run_at,last_scan_id,run_count,failure_count,notify_on_failure)
          values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(x['id'],x['target_id'],x['profile'],x['interval_minutes'],x['enabled'],x['next_run_at'],x['created_by'],x['created_at'],x['name'],x['last_run_at'],x['last_scan_id'],x['run_count'],x['failure_count'],x['notify_on_failure']))
        return x
    def list_schedules(self,org_id):
        with self.conn() as c:return [dict(r) for r in c.execute("""select s.* from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id where p.organization_id=? order by s.created_at desc""",(org_id,))]
    def get_schedule(self,schedule_id,org_id=None):
        q="""select s.*,t.url target_url,t.name target_name,t.verified target_verified,t.project_id,
          p.name project_name,p.status project_status,p.organization_id
          from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id where s.id=?""";args=[schedule_id]
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        return dict(r) if r else None

    def update_schedule(self,schedule_id,org_id,updates):
        allowed={'enabled','profile','interval_minutes','name','notify_on_failure'}
        sets=[];vals=[]
        with self.conn() as c:
            row=c.execute("""select s.id from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
              where s.id=? and p.organization_id=?""",(schedule_id,org_id)).fetchone()
            if not row:return None
            for k,v in updates.items():
                if k not in allowed:continue
                if k in {'enabled','notify_on_failure'}:v=int(bool(v))
                sets.append(k+"=?");vals.append(v)
            if 'interval_minutes' in updates:
                sets.append("next_run_at=?");vals.append((datetime.now(timezone.utc)+timedelta(minutes=int(updates['interval_minutes']))).isoformat())
            if sets:
                vals.append(schedule_id);c.execute("update schedules set "+",".join(sets)+" where id=?",vals)
            out=c.execute("select * from schedules where id=?",(schedule_id,)).fetchone()
        return dict(out) if out else None

    def set_schedule_enabled(self,schedule_id,org_id,enabled):
        with self.conn() as c:
            row=c.execute("""select s.id from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
            where s.id=? and p.organization_id=?""",(schedule_id,org_id)).fetchone()
            if not row:return False
            c.execute("update schedules set enabled=? where id=?",(int(enabled),schedule_id))
        return True

    def delete_schedule(self,schedule_id,org_id):
        with self.conn() as c:
            row=c.execute("""select s.id from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
            where s.id=? and p.organization_id=?""",(schedule_id,org_id)).fetchone()
            if not row:return False
            c.execute("delete from schedules where id=?",(schedule_id,))
        return True

    def create_schedule_run(self,schedule_id,scan_id):
        row={'id':self._id(),'schedule_id':schedule_id,'scan_id':scan_id,'status':'QUEUED','created_at':self.now(),'completed_at':None}
        with self.conn() as c:c.execute("insert into schedule_runs values(?,?,?,?,?,?)",tuple(row.values()))
        return row

    def schedule_notification_context(self,scan_id):
        with self.conn() as c:r=c.execute("""select sr.schedule_id,s.created_by,s.notify_on_failure,s.name,t.name target_name,p.organization_id
          from schedule_runs sr join schedules s on s.id=sr.schedule_id join targets t on t.id=s.target_id
          join projects p on p.id=t.project_id where sr.scan_id=? order by sr.created_at desc limit 1""",(scan_id,)).fetchone()
        return dict(r) if r else None

    def finalize_schedule_run(self,scan_id,status):
        notify=None
        with self.conn() as c:
            run=c.execute("""select sr.schedule_id,s.created_by,s.notify_on_failure,s.name,t.name target_name,p.organization_id
              from schedule_runs sr join schedules s on s.id=sr.schedule_id join targets t on t.id=s.target_id
              join projects p on p.id=t.project_id where sr.scan_id=? order by sr.created_at desc limit 1""",(scan_id,)).fetchone()
            if not run:return False
            c.execute("update schedule_runs set status=?,completed_at=? where scan_id=?",(status,self.now(),scan_id))
            if status=='FAILED':
                c.execute("update schedules set failure_count=failure_count+1 where id=?",(run['schedule_id'],))
                if run['notify_on_failure']:
                    notify=dict(run)
            if status=='COMPLETED':
                c.execute("update schedules set failure_count=case when failure_count<0 then 0 else failure_count end where id=?",(run['schedule_id'],))
        if notify:
            self.add_notification(notify['organization_id'],notify['created_by'],'schedule_failure',
              'Recurring assessment failed',
              f"{notify.get('name') or notify.get('target_name') or 'Scheduled assessment'} failed. Review the scan and worker error before the next run.",
              {'schedule_id':notify['schedule_id'],'scan_id':scan_id})
        return True

    def schedule_history(self,schedule_id,org_id,limit=50):
        with self.conn() as c:
            owned=c.execute("""select s.id from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
              where s.id=? and p.organization_id=?""",(schedule_id,org_id)).fetchone()
            if not owned:return []
            return [dict(r) for r in c.execute("""select sr.*,sc.score,sc.pages_scanned,sc.duration_ms,sc.error
              from schedule_runs sr left join scans sc on sc.id=sr.scan_id where sr.schedule_id=? order by sr.created_at desc limit ?""",(schedule_id,limit))]

    def run_schedule_now(self,schedule_id,org_id,user_id):
        s=self.get_schedule(schedule_id,org_id)
        if not s:return None
        if s.get('project_status')=='archived':raise ValueError("Archived projects cannot run recurring assessments")
        if s.get('profile')=='lab' and not s.get('target_verified'):raise ValueError("Lab profile requires verified ownership")
        policy=self.get_project_policy(s['project_id'])
        scan=self.create_scan(s['target_id'],s['target_url'],s['profile'],user_id,policy)
        self.enqueue_job('scan',{'scan_id':scan['id'],'target_id':s['target_id'],'schedule_id':schedule_id})
        self.create_schedule_run(schedule_id,scan['id'])
        with self.conn() as c:c.execute("update schedules set last_run_at=?,last_scan_id=?,run_count=run_count+1 where id=?",(self.now(),scan['id'],schedule_id))
        return scan

    def enqueue_due_schedules(self):
        now=self.now()
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from schedules where enabled=1 and next_run_at<=?",(now,))]
        for s in rows:
            t=self.get_target(s['target_id'])
            if not t:continue
            named=self.get_scan_profile(s.get('scan_profile_id')) if s.get('scan_profile_id') else None
            policy=named['policy'] if named and named.get('active') else self.get_project_policy(t['project_id'])
            mode=named['scan_mode'] if named and named.get('active') else s['profile']
            scan=self.create_scan(t['id'],t['url'],mode,s['created_by'],policy,named['id'] if named else None)
            self.enqueue_job('scan',{'scan_id':scan['id'],'target_id':t['id'],'schedule_id':s['id']})
            self.create_schedule_run(s['id'],scan['id'])
            nxt=(datetime.now(timezone.utc)+timedelta(minutes=s['interval_minutes'])).isoformat()
            with self.conn() as c:c.execute("update schedules set next_run_at=?,last_run_at=?,last_scan_id=?,run_count=run_count+1 where id=?",(nxt,self.now(),scan['id'],s['id']))
        return len(rows)
    # ZAP / audit
    def save_zap_import(self,scan_id,filename,items,comparison,created_by):
        x={'id':self._id(),'scan_id':scan_id,'filename':filename,'items_json':json.dumps(items),'comparison_json':json.dumps(comparison),'created_by':created_by,'created_at':self.now()}
        with self.conn() as c:c.execute("insert into zap_imports values(?,?,?,?,?,?,?)",tuple(x.values()))
        return {'id':x['id'],'scan_id':scan_id,'filename':filename,'comparison':comparison,'created_at':x['created_at']}
    def latest_zap_import(self,scan_id):
        with self.conn() as c:r=c.execute("select * from zap_imports where scan_id=? order by created_at desc limit 1",(scan_id,)).fetchone()
        if not r:return None
        d=dict(r);d['items']=json.loads(d.pop('items_json'));d['comparison']=json.loads(d.pop('comparison_json'));return d
    def audit(self,org_id,user_id,event,resource_type=None,resource_id=None,details=None,ip=None):
        with self.conn() as c:c.execute("""insert into audit_logs(id,organization_id,user_id,event,resource_type,resource_id,details_json,ip,created_at)
        values(?,?,?,?,?,?,?,?,?)""",(self._id(),org_id,user_id,event,resource_type,resource_id,json.dumps(details or {}),ip,self.now()))
    def list_audit(self,org_id,limit=200):
        with self.conn() as c:rows=[dict(r) for r in c.execute("""select a.*,u.email user_email,u.name user_name
          from audit_logs a left join users u on u.id=a.user_id where a.organization_id=? order by a.created_at desc limit ?""",(org_id,limit))]
        for r in rows:r['details']=json.loads(r.pop('details_json') or '{}')
        return rows


    # API keys
    def create_api_key(self,user_id,org_id,name,token_hash,prefix,scopes,expires_at=None):
        row={'id':self._id(),'user_id':user_id,'organization_id':org_id,'name':name,'token_hash':token_hash,'prefix':prefix,'scopes_json':json.dumps(scopes),'expires_at':expires_at,'last_used_at':None,'revoked_at':None,'created_at':self.now()}
        with self.conn() as c:c.execute("insert into api_keys values(?,?,?,?,?,?,?,?,?,?,?)",tuple(row.values()))
        return {'id':row['id'],'name':name,'prefix':prefix,'scopes':scopes,'expires_at':expires_at,'created_at':row['created_at']}

    def api_key_identity(self,token_hash):
        now=self.now()
        with self.conn() as c:
            r=c.execute("""select k.id api_key_id,k.scopes_json,k.expires_at,u.id user_id,u.email,u.name,u.email_verified,u.mfa_enabled,u.system_admin,
              m.organization_id,m.role,o.name organization_name,o.active organization_active
              from api_keys k join users u on u.id=k.user_id join memberships m on m.user_id=u.id and m.organization_id=k.organization_id
              join organizations o on o.id=m.organization_id
              where k.token_hash=? and k.revoked_at is null and (k.expires_at is null or k.expires_at>?) and u.active=1
                and m.active=1 and o.active=1""",(token_hash,now)).fetchone()
            if r:c.execute("update api_keys set last_used_at=? where id=?",(now,r['api_key_id']))
        if not r:return None
        d=dict(r);d['api_scopes']=json.loads(d.pop('scopes_json') or '[]');d['auth_method']='api_key';d['csrf_token']=None;d['session_id']=None
        return d

    def list_api_keys(self,user_id,org_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute("""select id,name,prefix,scopes_json,expires_at,last_used_at,revoked_at,created_at
          from api_keys where user_id=? and organization_id=? order by created_at desc""",(user_id,org_id))]
        for r in rows:r['scopes']=json.loads(r.pop('scopes_json') or '[]')
        return rows

    def revoke_api_key(self,key_id,user_id,org_id):
        with self.conn() as c:
            cur=c.execute("update api_keys set revoked_at=? where id=? and user_id=? and organization_id=? and revoked_at is null",(self.now(),key_id,user_id,org_id))
            return cur.rowcount>0

    def purge_retention(self,days):
        cutoff=(datetime.now(timezone.utc)-timedelta(days=max(1,int(days)))).isoformat()
        with self.conn() as c:
            scan_ids=[r[0] for r in c.execute("select id from scans where completed_at is not null and completed_at<?",(cutoff,))]
            for sid in scan_ids:
                c.execute("delete from assets where scan_id=?",(sid,));c.execute("delete from remediation_verifications where scan_id=?",(sid,));c.execute("delete from findings where scan_id=?",(sid,));c.execute("delete from scan_events where scan_id=?",(sid,));c.execute("delete from zap_imports where scan_id=?",(sid,))
                c.execute("delete from scans where id=?",(sid,))
            return len(scan_ids)

    # SLA escalation automation
    def process_overdue_finding_escalations(self):
        today=datetime.now(timezone.utc).date().isoformat();escalation_key='overdue:'+today
        with self.conn() as c:
            rows=[dict(r) for r in c.execute("""select fs.id finding_state_id,fs.title,fs.state,fs.due_at,fs.assignee_user_id,
              fs.base_severity,fs.severity_override,t.id target_id,t.name target_name,t.url target_url,p.organization_id
              from finding_states fs join targets t on t.id=fs.target_id join projects p on p.id=t.project_id
              where fs.state in ('OPEN','ACKNOWLEDGED','IN_PROGRESS') and fs.due_at is not null and substr(fs.due_at,1,10)<?
              order by fs.due_at""",(today,))]
        emitted=[]
        for row in rows:
            recipients=set()
            if row.get('assignee_user_id'):recipients.add(row['assignee_user_id'])
            with self.conn() as c:
                for x in c.execute("""select user_id from memberships where organization_id=? and active=1 and role in ('owner','admin')""",(row['organization_id'],)):
                    recipients.add(x['user_id'])
            for uid in recipients:
                with self.conn() as c:
                    try:
                        c.execute("insert into finding_escalations(id,finding_state_id,organization_id,user_id,escalation_key,created_at) values(?,?,?,?,?,?)",
                          (self._id(),row['finding_state_id'],row['organization_id'],uid,escalation_key,self.now()))
                    except sqlite3.IntegrityError:
                        continue
                severity=row.get('severity_override') or row.get('base_severity') or 'INFO'
                body=f"{severity} issue overdue since {str(row.get('due_at'))[:10]} on {row.get('target_name') or row.get('target_url')}: {row.get('title')}"
                self.add_notification(row['organization_id'],uid,'finding_overdue','Security issue overdue',body,
                  {'finding_state_id':row['finding_state_id'],'target_id':row['target_id'],'due_at':row['due_at'],'severity':severity})
                emitted.append({**row,'user_id':uid,'severity':severity,'body':body,'escalation_key':escalation_key})
        return emitted

    def list_finding_escalations(self,org_id,limit=200):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select e.*,fs.title,fs.due_at,u.name user_name,u.email user_email,t.name target_name
              from finding_escalations e join finding_states fs on fs.id=e.finding_state_id
              join users u on u.id=e.user_id join targets t on t.id=fs.target_id
              where e.organization_id=? order by e.created_at desc limit ?""",(org_id,limit))]

    # report export evidence ledger
    def record_report_export(self,org_id,scan_id,fmt,user_id,sha256,size_bytes):
        row={'id':self._id(),'organization_id':org_id,'scan_id':scan_id,'format':fmt.upper(),'user_id':user_id,
             'sha256':sha256,'size_bytes':int(size_bytes),'created_at':self.now()}
        with self.conn() as c:c.execute("insert into report_exports values(?,?,?,?,?,?,?,?)",tuple(row.values()))
        return row

    def list_report_exports(self,org_id,limit=200):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select e.*,u.name user_name,u.email user_email,s.target_url,s.score,s.profile
              from report_exports e join users u on u.id=e.user_id join scans s on s.id=e.scan_id
              where e.organization_id=? order by e.created_at desc limit ?""",(org_id,limit))]

    # enterprise access certification
    def create_access_review(self,org_id,name,created_by):
        now=self.now();review_id=self._id()
        with self.conn() as c:
            c.execute("insert into access_reviews(id,organization_id,name,status,created_by,created_at,completed_at) values(?,?,?,'OPEN',?,?,null)",(review_id,org_id,name,created_by,now))
            members=[dict(r) for r in c.execute("""select m.user_id,m.role from memberships m join users u on u.id=m.user_id
              where m.organization_id=? and m.active=1 and u.active=1 order by m.created_at""",(org_id,))]
            for m in members:
                c.execute("insert into access_review_items(id,review_id,user_id,role_snapshot,decision,note,reviewed_by,reviewed_at) values(?,?,?,?, 'PENDING',null,null,null)",
                  (self._id(),review_id,m['user_id'],m['role']))
        return self.get_access_review(review_id,org_id)

    def list_access_reviews(self,org_id,limit=100):
        with self.conn() as c:
            rows=[dict(r) for r in c.execute("""select r.*,
              count(i.id) item_count,
              sum(case when i.decision='PENDING' then 1 else 0 end) pending_count,
              sum(case when i.decision='APPROVE' then 1 else 0 end) approved_count,
              sum(case when i.decision='REVOKE' then 1 else 0 end) revoke_count
              from access_reviews r left join access_review_items i on i.review_id=r.id
              where r.organization_id=? group by r.id order by r.created_at desc limit ?""",(org_id,limit))]
        return rows

    def get_access_review(self,review_id,org_id):
        with self.conn() as c:
            r=c.execute("select * from access_reviews where id=? and organization_id=?",(review_id,org_id)).fetchone()
            if not r:return None
            items=[dict(x) for x in c.execute("""select i.*,u.name,u.email,u.active user_active,m.active membership_active,m.role current_role,u.email_verified,u.mfa_enabled,u.last_login_at
              from access_review_items i join users u on u.id=i.user_id
              left join memberships m on m.user_id=i.user_id and m.organization_id=?
              where i.review_id=? order by case i.role_snapshot when 'owner' then 1 when 'admin' then 2 when 'analyst' then 3 else 4 end,u.name""",(org_id,review_id))]
        out=dict(r);out['items']=items
        out['summary']={'total':len(items),'pending':sum(1 for x in items if x['decision']=='PENDING'),'approved':sum(1 for x in items if x['decision']=='APPROVE'),'revoke':sum(1 for x in items if x['decision']=='REVOKE')}
        return out

    def decide_access_review_item(self,review_id,item_id,org_id,decision,note,reviewed_by):
        if decision not in {'APPROVE','REVOKE'}:return None
        with self.conn() as c:
            review=c.execute("select status from access_reviews where id=? and organization_id=?",(review_id,org_id)).fetchone()
            if not review or review['status']!='OPEN':return None
            item=c.execute("select * from access_review_items where id=? and review_id=?",(item_id,review_id)).fetchone()
            if not item:return None
            if item['role_snapshot']=='owner' and decision=='REVOKE':raise ValueError("Workspace Owner access cannot be revoked by access review")
            c.execute("update access_review_items set decision=?,note=?,reviewed_by=?,reviewed_at=? where id=?",(decision,(note or '')[:1000],reviewed_by,self.now(),item_id))
        return self.get_access_review(review_id,org_id)

    def complete_access_review(self,review_id,org_id,completed_by):
        now=self.now()
        with self.conn() as c:
            review=c.execute("select status from access_reviews where id=? and organization_id=?",(review_id,org_id)).fetchone()
            if not review or review['status']!='OPEN':return None
            pending=c.execute("select count(*) from access_review_items where review_id=? and decision='PENDING'",(review_id,)).fetchone()[0]
            if pending:raise ValueError("All review items must have a decision before completion")
            revokes=[dict(r) for r in c.execute("select user_id,role_snapshot from access_review_items where review_id=? and decision='REVOKE'",(review_id,))]
            for item in revokes:
                if item['role_snapshot']=='owner':continue
                c.execute("update memberships set active=0 where organization_id=? and user_id=?",(org_id,item['user_id']))
                c.execute("update sessions set revoked_at=? where organization_id=? and user_id=? and revoked_at is null",(now,org_id,item['user_id']))
            c.execute("update access_reviews set status='COMPLETED',completed_at=? where id=?",(now,review_id))
        return self.get_access_review(review_id,org_id)

    # integrations / outbound webhooks
    def create_webhook_endpoint(self,org_id,name,url,secret_ciphertext,events,created_by):
        now=self.now();row={'id':self._id(),'organization_id':org_id,'name':name,'url':url,'secret_ciphertext':secret_ciphertext,
            'events_json':json.dumps(sorted(set(events))),'active':1,'created_by':created_by,'created_at':now,'updated_at':now}
        with self.conn() as c:c.execute("""insert into webhook_endpoints(id,organization_id,name,url,secret_ciphertext,events_json,active,created_by,created_at,updated_at)
          values(?,?,?,?,?,?,?,?,?,?)""",(row['id'],org_id,name,url,secret_ciphertext,row['events_json'],1,created_by,now,now))
        return self.get_webhook_endpoint(row['id'],org_id)

    def get_webhook_endpoint(self,endpoint_id,org_id=None):
        q="select * from webhook_endpoints where id=?";args=[endpoint_id]
        if org_id:q+=" and organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        if not r:return None
        d=dict(r);d['events']=json.loads(d.pop('events_json') or '[]');d['active']=bool(d['active']);return d

    def list_webhook_endpoints(self,org_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from webhook_endpoints where organization_id=? order by created_at desc",(org_id,))]
        out=[]
        for d in rows:
            d['events']=json.loads(d.pop('events_json') or '[]');d['active']=bool(d['active']);d.pop('secret_ciphertext',None);out.append(d)
        return out

    def update_webhook_endpoint(self,endpoint_id,org_id,updates):
        allowed={'name','url','active'}
        sets=[];vals=[]
        for k,v in updates.items():
            if k in allowed:
                sets.append(k+"=?");vals.append(int(bool(v)) if k=='active' else v)
        if 'events' in updates:
            sets.append("events_json=?");vals.append(json.dumps(sorted(set(updates['events']))))
        if 'secret_ciphertext' in updates:
            sets.append("secret_ciphertext=?");vals.append(updates['secret_ciphertext'])
        if not sets:return self.get_webhook_endpoint(endpoint_id,org_id)
        sets.append("updated_at=?");vals.append(self.now());vals.extend([endpoint_id,org_id])
        with self.conn() as c:
            cur=c.execute("update webhook_endpoints set "+",".join(sets)+" where id=? and organization_id=?",vals)
            if cur.rowcount<1:return None
        return self.get_webhook_endpoint(endpoint_id,org_id)

    def delete_webhook_endpoint(self,endpoint_id,org_id):
        with self.conn() as c:
            row=c.execute("select id from webhook_endpoints where id=? and organization_id=?",(endpoint_id,org_id)).fetchone()
            if not row:return False
            c.execute("delete from webhook_deliveries where endpoint_id=?",(endpoint_id,))
            c.execute("delete from webhook_endpoints where id=?",(endpoint_id,))
        return True

    def create_webhook_delivery(self,endpoint_id,event,payload):
        row={'id':self._id(),'endpoint_id':endpoint_id,'event':event,'payload_json':json.dumps(payload,separators=(',',':')),
             'status':'QUEUED','response_code':None,'response_body':None,'attempts':0,'last_error':None,'created_at':self.now(),'completed_at':None}
        with self.conn() as c:c.execute("""insert into webhook_deliveries(id,endpoint_id,event,payload_json,status,response_code,response_body,attempts,last_error,created_at,completed_at)
          values(?,?,?,?,?,?,?,?,?,?,?)""",tuple(row.values()))
        return {'id':row['id'],'endpoint_id':endpoint_id,'event':event,'status':'QUEUED','created_at':row['created_at']}

    def emit_webhook_event(self,org_id,event,payload):
        queued=[]
        with self.conn() as c:rows=[dict(r) for r in c.execute("select id,events_json from webhook_endpoints where organization_id=? and active=1",(org_id,))]
        for r in rows:
            try:events=json.loads(r['events_json'] or '[]')
            except Exception:events=[]
            if event not in events and '*' not in events:continue
            delivery=self.create_webhook_delivery(r['id'],event,{'event':event,'created_at':self.now(),'data':payload})
            self.enqueue_job('webhook',{'delivery_id':delivery['id']},max_attempts=5);queued.append(delivery['id'])
        return queued

    def get_webhook_delivery(self,delivery_id):
        with self.conn() as c:r=c.execute("""select d.*,e.organization_id,e.url,e.secret_ciphertext,e.active endpoint_active,e.name endpoint_name
          from webhook_deliveries d join webhook_endpoints e on e.id=d.endpoint_id where d.id=?""",(delivery_id,)).fetchone()
        if not r:return None
        d=dict(r)
        try:d['payload']=json.loads(d.pop('payload_json'))
        except Exception:d['payload']={}
        return d

    def list_webhook_deliveries(self,org_id,endpoint_id=None,limit=200):
        q="""select d.id,d.endpoint_id,d.event,d.status,d.response_code,d.attempts,d.last_error,d.created_at,d.completed_at,e.name endpoint_name,e.url
          from webhook_deliveries d join webhook_endpoints e on e.id=d.endpoint_id where e.organization_id=?""";args=[org_id]
        if endpoint_id:q+=" and d.endpoint_id=?";args.append(endpoint_id)
        q+=" order by d.created_at desc limit ?";args.append(limit)
        with self.conn() as c:return [dict(r) for r in c.execute(q,args)]

    def mark_webhook_delivery_running(self,delivery_id):
        with self.conn() as c:c.execute("update webhook_deliveries set status='RUNNING',attempts=attempts+1,last_error=null where id=?",(delivery_id,))

    def mark_webhook_delivery_success(self,delivery_id,status_code,response_body):
        with self.conn() as c:c.execute("""update webhook_deliveries set status='DELIVERED',response_code=?,response_body=?,last_error=null,completed_at=? where id=?""",
          (status_code,(response_body or '')[:1000],self.now(),delivery_id))

    def mark_webhook_delivery_failure(self,delivery_id,error,status_code=None,response_body=None):
        with self.conn() as c:c.execute("""update webhook_deliveries set status='FAILED',response_code=?,response_body=?,last_error=? where id=?""",
          (status_code,(response_body or '')[:1000],str(error)[:1000],delivery_id))

    def retry_webhook_delivery(self,delivery_id,org_id):
        with self.conn() as c:
            row=c.execute("""select d.id from webhook_deliveries d join webhook_endpoints e on e.id=d.endpoint_id
              where d.id=? and e.organization_id=?""",(delivery_id,org_id)).fetchone()
            if not row:return False
            c.execute("update webhook_deliveries set status='QUEUED',response_code=null,response_body=null,last_error=null,completed_at=null where id=?",(delivery_id,))
        self.enqueue_job('webhook',{'delivery_id':delivery_id},max_attempts=5);return True

    # system administration
    def set_system_admin(self,user_id,enabled=True):
        with self.conn() as c:c.execute("update users set system_admin=? where id=?",(int(enabled),user_id))

    def sync_system_admin_emails(self,emails):
        cleaned=[e.strip().lower() for e in emails if e and e.strip()]
        if not cleaned:return 0
        placeholders=",".join("?" for _ in cleaned)
        with self.conn() as c:
            cur=c.execute(f"update users set system_admin=1 where lower(email) in ({placeholders})",cleaned)
            return cur.rowcount

    def system_admin_count(self):
        with self.conn() as c:return c.execute("select count(*) from users where system_admin=1 and active=1").fetchone()[0]

    def admin_overview(self):
        with self.conn() as c:
            counts={
                'users':c.execute("select count(*) from users").fetchone()[0],
                'active_users':c.execute("select count(*) from users where active=1").fetchone()[0],
                'organizations':c.execute("select count(*) from organizations").fetchone()[0],
                'active_organizations':c.execute("select count(*) from organizations where active=1").fetchone()[0],
                'projects':c.execute("select count(*) from projects").fetchone()[0],
                'targets':c.execute("select count(*) from targets").fetchone()[0],
                'verified_targets':c.execute("select count(*) from targets where verified=1").fetchone()[0],
                'scans':c.execute("select count(*) from scans").fetchone()[0],
                'findings':c.execute("select count(*) from findings").fetchone()[0],
                'sessions':c.execute("select count(*) from sessions where revoked_at is null and expires_at>?",(self.now(),)).fetchone()[0],
                'failed_logins_24h':c.execute("select count(*) from auth_attempts where success=0 and created_at>=?",((datetime.now(timezone.utc)-timedelta(hours=24)).isoformat(),)).fetchone()[0],
            }
            severities={r['severity']:r['n'] for r in c.execute("select severity,count(*) n from findings where status in ('FAIL','WARNING','ERROR') group by severity")}
            scan_statuses={r['status']:r['n'] for r in c.execute("select status,count(*) n from scans group by status")}
        return {'counts':counts,'severities':severities,'scan_statuses':scan_statuses,'queue':self.queue_stats()}

    def admin_list_users(self,limit=500):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select u.id,u.email,u.name,u.active,u.email_verified,u.mfa_enabled,u.system_admin,
              u.failed_logins,u.locked_until,u.last_login_at,u.created_at,count(m.id) workspace_count
              from users u left join memberships m on m.user_id=u.id
              group by u.id order by u.created_at desc limit ?""",(limit,))]

    def admin_set_user_active(self,user_id,active):
        with self.conn() as c:
            c.execute("update users set active=? where id=?",(int(active),user_id))
            if not active:c.execute("update sessions set revoked_at=? where user_id=? and revoked_at is null",(self.now(),user_id))
            return c.total_changes>0

    def admin_list_organizations(self,limit=500):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select o.id,o.name,o.active,o.created_at,
              count(distinct m.user_id) member_count,count(distinct p.id) project_count,
              count(distinct t.id) target_count,count(distinct s.id) scan_count
              from organizations o
              left join memberships m on m.organization_id=o.id
              left join projects p on p.organization_id=o.id
              left join targets t on t.project_id=p.id
              left join scans s on s.target_id=t.id
              group by o.id order by o.created_at desc limit ?""",(limit,))]

    def admin_set_organization_active(self,org_id,active):
        with self.conn() as c:
            cur=c.execute("update organizations set active=? where id=?",(int(active),org_id))
            if not active:c.execute("update sessions set revoked_at=? where organization_id=? and revoked_at is null",(self.now(),org_id))
            return cur.rowcount>0

    def admin_list_scans(self,limit=500):
        with self.conn() as c:
            return [dict(r) for r in c.execute("""select s.*,t.name target_name,p.name project_name,o.name organization_name,o.id organization_id
              from scans s join targets t on t.id=s.target_id join projects p on p.id=t.project_id
              join organizations o on o.id=p.organization_id order by s.created_at desc limit ?""",(limit,))]

    def request_scan_cancel(self,scan_id):
        with self.conn() as c:
            r=c.execute("select status from scans where id=?",(scan_id,)).fetchone()
            if not r or r['status'] not in ('QUEUED','SCANNING'):return False
            c.execute("update scans set cancel_requested=1 where id=?",(scan_id,))
            if r['status']=='QUEUED':
                c.execute("update scans set status='CANCELLED',stage='CANCELLED',progress=100,completed_at=? where id=?",(self.now(),scan_id))
                rows=[dict(x) for x in c.execute("select id,payload_json from jobs where status='QUEUED' and kind='scan'")]
                for job in rows:
                    try:
                        if json.loads(job['payload_json']).get('scan_id')==scan_id:
                            c.execute("update jobs set status='CANCELLED',completed_at=? where id=?",(self.now(),job['id']))
                    except Exception:pass
            return True

    def scan_cancel_requested(self,scan_id):
        with self.conn() as c:r=c.execute("select cancel_requested from scans where id=?",(scan_id,)).fetchone()
        return bool(r and r['cancel_requested'])

    def recover_stale_jobs(self,stale_minutes=10):
        cutoff=(datetime.now(timezone.utc)-timedelta(minutes=max(1,int(stale_minutes)))).isoformat();recovered=[];failed=[]
        with self.conn() as c:
            c.execute("begin immediate")
            rows=[dict(r) for r in c.execute("""select * from jobs where status='RUNNING' and locked_at is not null and locked_at<?""",(cutoff,))]
            for job in rows:
                next_status='QUEUED' if int(job['attempts'])<int(job['max_attempts']) else 'FAILED'
                c.execute("""update jobs set status=?,run_after=?,locked_by=null,locked_at=null,last_error=?,completed_at=?
                  where id=? and status='RUNNING'""",(next_status,self.now(),'Recovered after stale worker lease',None if next_status=='QUEUED' else self.now(),job['id']))
                try:payload=json.loads(job['payload_json'] or '{}')
                except Exception:payload={}
                scan_id=payload.get('scan_id')
                if scan_id:
                    if next_status=='QUEUED':
                        c.execute("update scans set status='QUEUED',stage='RECOVERED',progress=0,error=null where id=? and status='SCANNING'",(scan_id,))
                        c.execute("insert into scan_events(scan_id,event_type,stage,progress,message,data_json,created_at) values(?,?,?,?,?,?,?)",(scan_id,'STATE','RECOVERED',0,'Stale worker lease recovered; scan re-queued','{}',self.now()))
                    else:
                        c.execute("update scans set status='FAILED',stage='FAILED',progress=100,error=?,completed_at=? where id=? and status in ('SCANNING','QUEUED')",('Worker lease expired and retry limit was reached',self.now(),scan_id))
                (recovered if next_status=='QUEUED' else failed).append(job['id'])
            c.commit()
        return {'recovered':recovered,'failed':failed,'checked':len(rows)}

    def admin_list_jobs(self,limit=500):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from jobs order by created_at desc limit ?",(limit,))]
        for r in rows:
            try:r['payload']=json.loads(r.pop('payload_json'))
            except Exception:r['payload']={}
        return rows

    def admin_retry_job(self,job_id):
        with self.conn() as c:
            cur=c.execute("""update jobs set status='QUEUED',run_after=?,locked_by=null,locked_at=null,last_error=null,completed_at=null
            where id=? and status in ('FAILED','CANCELLED')""",(self.now(),job_id))
            return cur.rowcount>0

    def admin_cancel_job(self,job_id):
        with self.conn() as c:
            cur=c.execute("update jobs set status='CANCELLED',completed_at=? where id=? and status='QUEUED'",(self.now(),job_id))
            return cur.rowcount>0

    def admin_purge_jobs(self):
        with self.conn() as c:
            cur=c.execute("delete from jobs where status in ('COMPLETED','CANCELLED') and completed_at<?",((datetime.now(timezone.utc)-timedelta(days=7)).isoformat(),))
            return cur.rowcount

    def worker_heartbeat(self,worker_id,hostname,pid,status='IDLE',current_job_id=None,started_at=None):
        now=self.now();started=started_at or now
        with self.conn() as c:c.execute("""insert into worker_heartbeats(worker_id,hostname,pid,status,current_job_id,started_at,last_seen_at)
          values(?,?,?,?,?,?,?) on conflict(worker_id) do update set status=excluded.status,current_job_id=excluded.current_job_id,last_seen_at=excluded.last_seen_at""",
          (worker_id,hostname,pid,status,current_job_id,started,now))

    def admin_list_workers(self):
        cutoff=datetime.now(timezone.utc)-timedelta(seconds=30)
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from worker_heartbeats order by last_seen_at desc")]
        for r in rows:
            try:r['online']=datetime.fromisoformat(r['last_seen_at'])>=cutoff
            except Exception:r['online']=False
        return rows

    def get_system_settings(self):
        with self.conn() as c:rows=c.execute("select key,value_json,updated_by,updated_at from system_settings order by key")
        out={}
        for r in rows:
            try:value=json.loads(r['value_json'])
            except Exception:value=r['value_json']
            out[r['key']]={'value':value,'updated_by':r['updated_by'],'updated_at':r['updated_at']}
        return out

    def system_setting(self,key,default=None):
        with self.conn() as c:r=c.execute("select value_json from system_settings where key=?",(key,)).fetchone()
        if not r:return default
        try:return json.loads(r['value_json'])
        except Exception:return default

    def set_system_setting(self,key,value,user_id):
        allowed={'registration_enabled','maintenance_mode','maintenance_message','platform_name','admin_banner','scan_quota_per_day','max_concurrent_scans_per_org','scan_retention_days','require_verified_email_for_scans'}
        if key not in allowed:raise ValueError("Unsupported system setting")
        with self.conn() as c:c.execute("""insert into system_settings(key,value_json,updated_by,updated_at) values(?,?,?,?)
          on conflict(key) do update set value_json=excluded.value_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
          (key,json.dumps(value),user_id,self.now()))

    def admin_security_events(self,limit=300):
        with self.conn() as c:
            attempts=[dict(r) for r in c.execute("select * from auth_attempts order by created_at desc limit ?",(limit,))]
            locked=[dict(r) for r in c.execute("""select id,email,name,failed_logins,locked_until,last_login_at from users
              where locked_until is not null order by locked_until desc limit 100""")]
        return {'login_attempts':attempts,'locked_users':locked}

    def admin_list_audit(self,limit=1000):
        with self.conn() as c:rows=[dict(r) for r in c.execute("""select a.*,u.email user_email,o.name organization_name
          from audit_logs a left join users u on u.id=a.user_id left join organizations o on o.id=a.organization_id
          order by a.created_at desc limit ?""",(limit,))]
        for r in rows:
            try:r['details']=json.loads(r.pop('details_json') or '{}')
            except Exception:r['details']={}
        return rows

    def admin_list_backups(self,limit=500):
        with self.conn() as c:return [dict(r) for r in c.execute("""select b.*,u.email user_email,o.name organization_name
          from backup_history b left join users u on u.id=b.user_id left join organizations o on o.id=b.organization_id
          order by b.created_at desc limit ?""",(limit,))]
