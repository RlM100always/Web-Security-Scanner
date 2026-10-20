import json, sqlite3, uuid
from pathlib import Path
from datetime import datetime, timezone
class Repository:
    def __init__(self,path): self.path=path; Path(path).parent.mkdir(parents=True,exist_ok=True)
    def conn(self): c=sqlite3.connect(self.path,check_same_thread=False); c.row_factory=sqlite3.Row; return c
    def init_schema(self):
        with self.conn() as c:
            c.executescript('''
            create table if not exists projects(id text primary key,name text not null,description text default '',created_at text not null);
            create table if not exists targets(id text primary key,project_id text,url text not null,name text not null,authorized integer not null default 0,verified integer not null default 0,created_at text not null);
            create table if not exists scans(id text primary key,target_id text,target_url text,profile text,status text,progress integer default 0,stage text,score integer,pages_scanned integer,duration_ms integer,created_at text,completed_at text,error text);
            create table if not exists findings(id text primary key,scan_id text,fingerprint text,check_id text,title text,category text,status text,severity text,confidence text,url text,evidence text,description text,impact text,remediation text,standards_json text,metadata_json text);
            create table if not exists audit_logs(id text primary key,event text,details_json text,created_at text);
            ''')
    def now(self): return datetime.now(timezone.utc).isoformat()
    def create_project(self,name,description=''):
        x={'id':uuid.uuid4().hex,'name':name,'description':description,'created_at':self.now()}
        with self.conn() as c:c.execute('insert into projects values(?,?,?,?)',tuple(x.values()))
        return x
    def list_projects(self):
        with self.conn() as c:return [dict(r) for r in c.execute('select * from projects order by created_at desc')]
    def create_target(self,project_id,url,name,authorized=False,verified=False):
        x={'id':uuid.uuid4().hex,'project_id':project_id,'url':url,'name':name,'authorized':int(authorized),'verified':int(verified),'created_at':self.now()}
        with self.conn() as c:c.execute('insert into targets values(?,?,?,?,?,?,?)',tuple(x.values()))
        x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified']);return x
    def list_targets(self,project_id=None):
        q='select * from targets'; args=[]
        if project_id:q+=' where project_id=?';args=[project_id]
        q+=' order by created_at desc'
        with self.conn() as c:
            out=[dict(r) for r in c.execute(q,args)]
        for x in out:x['authorized']=bool(x['authorized']);x['verified']=bool(x['verified'])
        return out
    def get_target(self,id):
        with self.conn() as c:r=c.execute('select * from targets where id=?',(id,)).fetchone()
        return dict(r) if r else None
    def create_scan(self,target_id,target_url,profile):
        x={'id':uuid.uuid4().hex,'target_id':target_id,'target_url':target_url,'profile':profile,'status':'CREATED','progress':0,'stage':'CREATED','score':None,'pages_scanned':None,'duration_ms':None,'created_at':self.now(),'completed_at':None,'error':None}
        with self.conn() as c:c.execute('insert into scans values(?,?,?,?,?,?,?,?,?,?,?,?,?)',tuple(x.values()))
        return x
    def update_scan(self,id,**kw):
        if not kw:return
        with self.conn() as c:c.execute('update scans set '+','.join(f'{k}=?' for k in kw)+' where id=?',(*kw.values(),id))
    def add_findings(self,scan_id,findings):
        with self.conn() as c:
            for f in findings:
                d=f.to_dict(); c.execute('insert into findings values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,scan_id,d['fingerprint'],d['check_id'],d['title'],d['category'],d['status'],d['severity'],d['confidence'],d['url'],d['evidence'],d['description'],d['impact'],d['remediation'],json.dumps(d['standards']),json.dumps(d['metadata'])))
    def get_scan(self,id):
        with self.conn() as c:r=c.execute('select * from scans where id=?',(id,)).fetchone()
        return dict(r) if r else None
    def list_scans(self,limit=50):
        with self.conn() as c:return [dict(r) for r in c.execute('select * from scans order by created_at desc limit ?',(limit,))]
    def findings(self,scan_id):
        with self.conn() as c:rows=[dict(r) for r in c.execute('select * from findings where scan_id=? order by case severity when "CRITICAL" then 5 when "HIGH" then 4 when "MEDIUM" then 3 when "LOW" then 2 else 1 end desc,title',(scan_id,))]
        for r in rows:r['standards']=json.loads(r.pop('standards_json'));r['metadata']=json.loads(r.pop('metadata_json'))
        return rows
    def comparison(self,scan_id):
        current=self.get_scan(scan_id)
        if not current:return {}
        with self.conn() as c: prev=c.execute('select id from scans where target_id=? and status="COMPLETED" and id<>? and created_at<? order by created_at desc limit 1',(current['target_id'],scan_id,current['created_at'])).fetchone()
        cur={x['fingerprint'] for x in self.findings(scan_id)}
        old={x['fingerprint'] for x in self.findings(prev['id'])} if prev else set()
        return {'previous_scan_id':prev['id'] if prev else None,'new':len(cur-old),'fixed':len(old-cur),'unchanged':len(cur&old)}
