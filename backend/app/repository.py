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
            create table if not exists zap_imports(
              id text primary key,scan_id text not null,filename text,items_json text not null,comparison_json text not null,
              created_by text,created_at text not null);
            create table if not exists audit_logs(
              id text primary key,organization_id text,user_id text,event text,resource_type text,resource_id text,
              details_json text,ip text,created_at text not null);
            create table if not exists auth_attempts(
              id integer primary key autoincrement,email text,ip text,success integer not null,created_at text not null);
            """)
            self._ensure_column(c,"projects","organization_id","text")
            self._ensure_column(c,"projects","created_by","text")
            self._ensure_column(c,"targets","created_by","text")
            self._ensure_column(c,"scans","created_by","text")
            c.execute("create index if not exists idx_projects_org on projects(organization_id)")
            c.execute("create index if not exists idx_jobs_queue on jobs(status,run_after)")
            c.execute("create index if not exists idx_events_scan on scan_events(scan_id,id)")
            c.execute("create index if not exists idx_audit_org on audit_logs(organization_id,created_at)")
            c.execute("create index if not exists idx_auth_attempts on auth_attempts(email,created_at)")
    # auth / org
    def user_count(self):
        with self.conn() as c:return c.execute("select count(*) from users").fetchone()[0]
    def create_signup(self,email,name,password_hash,org_name):
        uid,oid,mid=self._id(),self._id(),self._id(); now=self.now()
        with self.conn() as c:
            c.execute("insert into users values(?,?,?,?,1,1,0,null,null,?)",(uid,email.lower(),name,password_hash,now))
            c.execute("insert into organizations values(?,?,?)",(oid,org_name,now))
            c.execute("insert into memberships values(?,?,?,?,?)",(mid,oid,uid,"owner",now))
        return {"user_id":uid,"organization_id":oid}
    def create_bootstrap_owner(self,email,name,password_hash):
        return self.create_signup(email,name,password_hash,"Default Workspace")
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
            r=c.execute("""select s.id session_id,s.csrf_token,s.expires_at,u.id user_id,u.email,u.name,m.organization_id,m.role,o.name organization_name
            from sessions s join users u on u.id=s.user_id join memberships m on m.user_id=u.id and m.organization_id=s.organization_id
            join organizations o on o.id=m.organization_id
            where s.token_hash=? and s.revoked_at is null and s.expires_at>? and u.active=1""",(token_hash,now)).fetchone()
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
            where m.user_id=? order by m.created_at""",(user_id,))]

    def list_members(self,org_id):
        with self.conn() as c:return [dict(r) for r in c.execute("""select u.id,u.email,u.name,u.active,m.role,m.created_at from memberships m join users u on u.id=m.user_id where m.organization_id=? order by m.created_at""",(org_id,))]
    def add_member(self,org_id,email,name,password_hash,role):
        user=self.get_user_by_email(email);now=self.now()
        with self.conn() as c:
            if not user:
                uid=self._id();c.execute("insert into users values(?,?,?,?,1,1,0,null,null,?)",(uid,email.lower(),name,password_hash,now))
            else:uid=user["id"]
            c.execute("insert or replace into memberships(id,organization_id,user_id,role,created_at) values(?,?,?,?,?)",(self._id(),org_id,uid,role,now))
        return {"user_id":uid,"email":email.lower(),"role":role}
    def update_member_role(self,org_id,user_id,role):
        with self.conn() as c:c.execute("update memberships set role=? where organization_id=? and user_id=?",(role,org_id,user_id))
    # projects / targets
    def create_project(self,name,description='',organization_id=None,created_by=None):
        x={'id':self._id(),'name':name,'description':description,'organization_id':organization_id,'created_by':created_by,'created_at':self.now()}
        with self.conn() as c:c.execute("insert into projects(id,name,description,organization_id,created_by,created_at) values(?,?,?,?,?,?)",tuple(x.values()))
        return x
    def list_projects(self,org_id=None):
        q="select * from projects";args=[]
        if org_id:q+=" where organization_id=?";args=[org_id]
        q+=" order by created_at desc"
        with self.conn() as c:return [dict(r) for r in c.execute(q,args)]
    def get_project(self,id,org_id=None):
        q="select * from projects where id=?";args=[id]
        if org_id:q+=" and organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        return dict(r) if r else None
    def delete_project(self,id,org_id):
        with self.conn() as c:
            p=c.execute("select id from projects where id=? and organization_id=?",(id,org_id)).fetchone()
            if not p:return False
            tids=[r[0] for r in c.execute("select id from targets where project_id=?",(id,))]
            for tid in tids:
                sids=[r[0] for r in c.execute("select id from scans where target_id=?",(tid,))]
                for sid in sids:
                    c.execute("delete from findings where scan_id=?",(sid,));c.execute("delete from scan_events where scan_id=?",(sid,));c.execute("delete from scans where id=?",(sid,))
                c.execute("delete from target_verifications where target_id=?",(tid,));c.execute("delete from targets where id=?",(tid,))
            c.execute("delete from projects where id=?",(id,))
        return True
    def create_target(self,project_id,url,name,authorized=False,verified=False,created_by=None):
        x={'id':self._id(),'project_id':project_id,'url':url,'name':name,'authorized':int(authorized),'verified':int(verified),'created_by':created_by,'created_at':self.now()}
        with self.conn() as c:c.execute("insert into targets(id,project_id,url,name,authorized,verified,created_by,created_at) values(?,?,?,?,?,?,?,?)",tuple(x.values()))
        x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified']);return x
    def list_targets(self,project_id=None,org_id=None):
        q="select t.* from targets t join projects p on p.id=t.project_id where 1=1";args=[]
        if project_id:q+=" and t.project_id=?";args.append(project_id)
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        q+=" order by t.created_at desc"
        with self.conn() as c:out=[dict(r) for r in c.execute(q,args)]
        for x in out:x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified'])
        return out
    def get_target(self,id,org_id=None):
        q="select t.* from targets t join projects p on p.id=t.project_id where t.id=?";args=[id]
        if org_id:q+=" and p.organization_id=?";args.append(org_id)
        with self.conn() as c:r=c.execute(q,args).fetchone()
        if not r:return None
        x=dict(r);x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified']);return x
    def delete_target(self,target_id,org_id):
        with self.conn() as c:
            row=c.execute("""select t.id from targets t join projects p on p.id=t.project_id
            where t.id=? and p.organization_id=?""",(target_id,org_id)).fetchone()
            if not row:return False
            scan_ids=[r[0] for r in c.execute("select id from scans where target_id=?",(target_id,))]
            for sid in scan_ids:
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
    # scans / findings
    def create_scan(self,target_id,target_url,profile,created_by=None):
        x={'id':self._id(),'target_id':target_id,'target_url':target_url,'profile':profile,'status':'QUEUED','progress':0,'stage':'QUEUED','score':None,'pages_scanned':None,'duration_ms':None,'created_by':created_by,'created_at':self.now(),'completed_at':None,'error':None}
        with self.conn() as c:c.execute("insert into scans(id,target_id,target_url,profile,status,progress,stage,score,pages_scanned,duration_ms,created_by,created_at,completed_at,error) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",tuple(x.values()))
        self.add_scan_event(x['id'],'STATE','QUEUED',0,'Scan queued')
        return x
    def update_scan(self,id,**kw):
        if kw:
            with self.conn() as c:c.execute("update scans set "+','.join(f'{k}=?' for k in kw)+" where id=?",(*kw.values(),id))
    def add_findings(self,scan_id,findings):
        with self.conn() as c:
            c.execute("delete from findings where scan_id=?",(scan_id,))
            for f in findings:
                d=f.to_dict()
                c.execute("insert into findings values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(self._id(),scan_id,d['fingerprint'],d['check_id'],d['title'],d['category'],d['status'],d['severity'],d['confidence'],d['url'],d['evidence'],d['description'],d['impact'],d['remediation'],json.dumps(d['standards']),json.dumps(d['metadata'])))
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
    def findings(self,scan_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute("""select * from findings where scan_id=? order by case severity when 'CRITICAL' then 5 when 'HIGH' then 4 when 'MEDIUM' then 3 when 'LOW' then 2 else 1 end desc,title""",(scan_id,))]
        for r in rows:r['standards']=json.loads(r.pop('standards_json'));r['metadata']=json.loads(r.pop('metadata_json'))
        return rows
    def comparison(self,scan_id):
        current=self.get_scan(scan_id)
        if not current:return {}
        with self.conn() as c:prev=c.execute("select id from scans where target_id=? and status='COMPLETED' and id<>? and created_at<? order by created_at desc limit 1",(current['target_id'],scan_id,current['created_at'])).fetchone()
        cur={x['fingerprint'] for x in self.findings(scan_id)};old={x['fingerprint'] for x in self.findings(prev['id'])} if prev else set()
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
            run_after=(datetime.now(timezone.utc)+timedelta(seconds=15)).isoformat()
            c.execute("update jobs set status=?,run_after=?,last_error=?,locked_by=null,locked_at=null,completed_at=? where id=?",(status,run_after,error[:1000],None if status=='QUEUED' else self.now(),id))
    def queue_stats(self):
        with self.conn() as c:return {r['status']:r['n'] for r in c.execute("select status,count(*) n from jobs group by status")}
    def create_schedule(self,target_id,profile,interval_minutes,created_by):
        x={'id':self._id(),'target_id':target_id,'profile':profile,'interval_minutes':interval_minutes,'enabled':1,'next_run_at':(datetime.now(timezone.utc)+timedelta(minutes=interval_minutes)).isoformat(),'created_by':created_by,'created_at':self.now()}
        with self.conn() as c:c.execute("insert into schedules values(?,?,?,?,?,?,?,?)",tuple(x.values()))
        return x
    def list_schedules(self,org_id):
        with self.conn() as c:return [dict(r) for r in c.execute("""select s.* from schedules s join targets t on t.id=s.target_id join projects p on p.id=t.project_id where p.organization_id=? order by s.created_at desc""",(org_id,))]
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

    def enqueue_due_schedules(self):
        now=self.now()
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from schedules where enabled=1 and next_run_at<=?",(now,))]
        for s in rows:
            t=self.get_target(s['target_id'])
            if not t:continue
            scan=self.create_scan(t['id'],t['url'],s['profile'],s['created_by'])
            self.enqueue_job('scan',{'scan_id':scan['id'],'target_id':t['id']})
            nxt=(datetime.now(timezone.utc)+timedelta(minutes=s['interval_minutes'])).isoformat()
            with self.conn() as c:c.execute("update schedules set next_run_at=? where id=?",(nxt,s['id']))
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
        with self.conn() as c:c.execute("insert into audit_logs values(?,?,?,?,?,?,?,?,?)",(self._id(),org_id,user_id,event,resource_type,resource_id,json.dumps(details or {}),ip,self.now()))
    def list_audit(self,org_id,limit=200):
        with self.conn() as c:rows=[dict(r) for r in c.execute("select * from audit_logs where organization_id=? order by created_at desc limit ?",(org_id,limit))]
        for r in rows:r['details']=json.loads(r.pop('details_json') or '{}')
        return rows
