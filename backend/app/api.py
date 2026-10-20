import json
import secrets
import time
from datetime import datetime, timezone
from flask import Blueprint,current_app,request,jsonify,Response,stream_with_context
from .security.targets import validate_target,TargetValidationError
from .reports import as_json,as_html,as_pdf
from .auth import current_identity,require_auth,require_role,ROLES
from .crypto import hash_password,verify_password,token_hash
from .verification import make_verification,check_file,check_dns
from .zap import parse_zap_json,compare_with_scanner

def create_blueprint():
    bp=Blueprint('api',__name__)
    def repo():return current_app.extensions['repo']
    def ip_addr():
        if current_app.config.get("TRUST_PROXY_HEADERS"):
            return (request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.remote_addr or "")
        return request.remote_addr or ""
    def audit(event,resource_type=None,resource_id=None,details=None):
        ident=current_identity()
        if ident:repo().audit(ident['organization_id'],ident['user_id'],event,resource_type,resource_id,details or {},ip_addr())
    def cookie_response(payload,status,raw_token=None,max_age=None):
        response=jsonify(payload);response.status_code=status
        if raw_token:
            response.set_cookie("wss_session",raw_token,max_age=max_age,httponly=True,
                secure=current_app.config["SESSION_COOKIE_SECURE"],samesite=current_app.config["SESSION_COOKIE_SAMESITE"],path="/")
        return response

    # Authentication
    @bp.post('/auth/signup')
    def signup():
        d=request.get_json(force=True) or {}
        email=(d.get('email') or '').strip().lower();name=(d.get('name') or '').strip();password=d.get('password') or ''
        org=(d.get('organization_name') or f"{name}'s workspace").strip()
        if '@' not in email or len(email)>254:return {'error':'A valid email address is required'},400
        if len(name)<2:return {'error':'Your name is required'},400
        if len(password)<12:return {'error':'Use a password with at least 12 characters'},400
        if repo().get_user_by_email(email):return {'error':'An account already exists for this email'},409
        try:created=repo().create_signup(email,name,hash_password(password),org)
        except Exception:return {'error':'Unable to create account'},400
        raw=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32)
        sess=repo().create_session(created['user_id'],created['organization_id'],token_hash(raw),csrf,current_app.config['SESSION_TTL_HOURS'],request.headers.get('User-Agent','')[:300],ip_addr())
        repo().audit(created['organization_id'],created['user_id'],'ACCOUNT_SIGNUP','user',created['user_id'],{'email':email},ip_addr())
        ident=repo().session_identity(token_hash(raw))
        return cookie_response({'user':ident,'csrf_token':csrf},201,raw,current_app.config['SESSION_TTL_HOURS']*3600)

    @bp.post('/auth/login')
    def login():
        d=request.get_json(force=True) or {};email=(d.get('email') or '').strip().lower();password=d.get('password') or ''
        if repo().recent_failed_attempts(email,ip_addr(),current_app.config['AUTH_WINDOW_MINUTES'])>=current_app.config['AUTH_MAX_ATTEMPTS']:
            return {'error':'Too many failed attempts. Try again later.'},429
        user=repo().get_user_by_email(email)
        locked=False
        if user and user.get('locked_until'):
            try:locked=datetime.fromisoformat(user['locked_until'])>datetime.now(timezone.utc)
            except Exception:locked=False
        ok=bool(user and not locked and user.get('active') and verify_password(password,user['password_hash']))
        repo().record_login_attempt(email,ip_addr(),ok)
        if not ok:
            if user:repo().set_login_failure(user['id'],repo().recent_failed_attempts(email,ip_addr())>=5)
            return {'error':'Invalid email or password'},401
        repo().set_login_success(user['id'])
        memberships=repo().list_memberships_for_user(user['id'])
        if not memberships:return {'error':'Account has no active workspace'},403
        org_id=(d.get('organization_id') if any(m['organization_id']==d.get('organization_id') for m in memberships) else memberships[0]['organization_id'])
        raw=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32)
        repo().create_session(user['id'],org_id,token_hash(raw),csrf,current_app.config['SESSION_TTL_HOURS'],request.headers.get('User-Agent','')[:300],ip_addr())
        ident=repo().session_identity(token_hash(raw));repo().audit(org_id,user['id'],'LOGIN','user',user['id'],{},ip_addr())
        return cookie_response({'user':ident,'csrf_token':csrf,'workspaces':memberships},200,raw,current_app.config['SESSION_TTL_HOURS']*3600)

    @bp.post('/auth/logout')
    @require_auth
    def logout():
        ident=current_identity();repo().revoke_session(ident['session_id']);audit('LOGOUT','user',ident['user_id'])
        response=jsonify({'ok':True});response.delete_cookie('wss_session',path='/');return response

    @bp.get('/auth/me')
    @require_auth
    def me():
        ident=current_identity()
        return {'user':ident,'csrf_token':ident['csrf_token'],'workspaces':repo().list_memberships_for_user(ident['user_id'])}

    # Dashboard
    @bp.get('/dashboard')
    @require_auth
    def dashboard():
        ident=current_identity();scans=repo().list_scans(30,ident['organization_id']);completed=[s for s in scans if s['status']=='COMPLETED'];latest=completed[0] if completed else None
        return {'projects':len(repo().list_projects(ident['organization_id'])),'targets':len(repo().list_targets(org_id=ident['organization_id'])),
                'latest_scan':latest,'recent_scans':scans[:8],'queue':repo().queue_stats(),
                'members':len(repo().list_members(ident['organization_id'])),'schedules':len(repo().list_schedules(ident['organization_id']))}

    # Team / RBAC
    @bp.get('/team')
    @require_role('viewer')
    def team_list():return jsonify(repo().list_members(current_identity()['organization_id']))

    @bp.post('/team')
    @require_role('admin')
    def team_add():
        d=request.get_json(force=True) or {};role=d.get('role','viewer')
        if role not in ROLES or role=='owner':return {'error':'Role must be admin, analyst or viewer'},400
        email=(d.get('email') or '').strip().lower();name=(d.get('name') or '').strip();password=d.get('temporary_password') or ''
        if '@' not in email or len(name)<2 or len(password)<12:return {'error':'Valid email, name and 12+ character temporary password are required'},400
        member=repo().add_member(current_identity()['organization_id'],email,name,hash_password(password),role)
        audit('TEAM_MEMBER_ADDED','user',member['user_id'],{'email':email,'role':role});return member,201

    @bp.patch('/team/<user_id>')
    @require_role('admin')
    def team_role(user_id):
        d=request.get_json(force=True) or {};role=d.get('role')
        if role not in {'admin','analyst','viewer'}:return {'error':'Invalid role'},400
        repo().update_member_role(current_identity()['organization_id'],user_id,role);audit('TEAM_ROLE_CHANGED','user',user_id,{'role':role})
        return {'ok':True,'role':role}

    # Projects
    @bp.route('/projects',methods=['GET','POST'])
    @require_auth
    def projects():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_projects(ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        d=request.get_json(force=True) or {};name=(d.get('name') or '').strip()
        if not name:return {'error':'Project name is required'},400
        p=repo().create_project(name,d.get('description',''),ident['organization_id'],ident['user_id']);audit('PROJECT_CREATED','project',p['id'],{'name':name});return p,201

    @bp.delete('/projects/<project_id>')
    @require_role('admin')
    def project_delete(project_id):
        ok=repo().delete_project(project_id,current_identity()['organization_id'])
        if not ok:return {'error':'Project not found'},404
        audit('PROJECT_DELETED','project',project_id);return {'ok':True}

    # Targets
    @bp.route('/targets',methods=['GET','POST'])
    @require_auth
    def targets():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_targets(request.args.get('project_id'),ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        d=request.get_json(force=True) or {}
        if not d.get('authorized'):return {'error':'You must confirm ownership or explicit authorization'},400
        project=repo().get_project(d.get('project_id'),ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        try:url=validate_target(d.get('url'),current_app.config['SCANNER_ALLOW_PRIVATE'])
        except TargetValidationError as e:return {'error':str(e)},400
        t=repo().create_target(project['id'],url,d.get('name') or url,True,False,ident['user_id']);audit('TARGET_CREATED','target',t['id'],{'url':url});return t,201

    @bp.post('/targets/<target_id>/verification')
    @require_role('analyst')
    def verification_create(target_id):
        ident=current_identity();t=repo().get_target(target_id,ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        method=(request.get_json(force=True) or {}).get('method','file')
        try:token,instructions=make_verification(t['url'],method)
        except ValueError as e:return {'error':str(e)},400
        v=repo().create_verification(target_id,method,token,instructions,ident['user_id']);audit('VERIFICATION_CREATED','target',target_id,{'method':method})
        return {'id':v['id'],'method':method,'instructions':instructions,'status':v['status']},201

    @bp.post('/verifications/<verification_id>/check')
    @require_role('analyst')
    def verification_check(verification_id):
        ident=current_identity();v=repo().get_verification(verification_id)
        if not v:return {'error':'Verification not found'},404
        t=repo().get_target(v['target_id'],ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        try:
            ok,evidence=check_file(t['url'],v['token'],current_app.config['SCANNER_ALLOW_PRIVATE']) if v['method']=='file' else check_dns(t['url'],v['token'])
        except Exception as e:ok=False;evidence=str(e)
        repo().complete_verification(v['id'],ok,evidence)
        if ok:repo().set_target_verified(t['id'],True)
        audit('VERIFICATION_CHECKED','target',t['id'],{'ok':ok,'method':v['method']})
        return {'verified':ok,'evidence':evidence}

    # Scans and worker queue
    @bp.route('/scans',methods=['GET','POST'])
    @require_auth
    def scans():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_scans(100,ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        d=request.get_json(force=True) or {};t=repo().get_target(d.get('target_id'),ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        if not t.get('authorized'):return {'error':'Target is not authorized'},403
        profile=d.get('profile','standard')
        if profile not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
        if profile=='lab' and not t.get('verified'):return {'error':'Lab profile requires verified ownership'},403
        s=repo().create_scan(t['id'],t['url'],profile,ident['user_id']);job=repo().enqueue_job('scan',{'scan_id':s['id'],'target_id':t['id']})
        audit('SCAN_QUEUED','scan',s['id'],{'profile':profile,'job_id':job['id']});s['job_id']=job['id'];return s,202

    @bp.get('/scans/<scan_id>')
    @require_auth
    def scan_get(scan_id):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        s['findings']=repo().findings(scan_id);s['comparison']=repo().comparison(scan_id);s['zap']=repo().latest_zap_import(scan_id);return s

    @bp.get('/scans/<scan_id>/events')
    @require_auth
    def scan_events(scan_id):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        start=int(request.headers.get('Last-Event-ID') or request.args.get('after') or 0)
        @stream_with_context
        def stream():
            cursor=start;idle=0
            while idle<120:
                events=repo().scan_events(scan_id,cursor)
                if events:
                    idle=0
                    for e in events:
                        cursor=e['id'];yield f"id: {cursor}\nevent: scan\ndata: {json.dumps(e)}\n\n"
                else:
                    idle+=1;yield ": keepalive\n\n"
                current=repo().get_scan(scan_id,ident['organization_id'])
                if current and current['status'] in {'COMPLETED','FAILED','CANCELLED'} and not repo().scan_events(scan_id,cursor):
                    yield f"event: terminal\ndata: {json.dumps({'status':current['status']})}\n\n";break
                time.sleep(1)
        return Response(stream(),mimetype='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

    # Schedules
    @bp.route('/schedules',methods=['GET','POST'])
    @require_auth
    def schedules():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_schedules(ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        d=request.get_json(force=True) or {};t=repo().get_target(d.get('target_id'),ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        interval=int(d.get('interval_minutes') or 1440)
        if interval<60:return {'error':'Minimum recurring interval is 60 minutes'},400
        profile=d.get('profile','standard')
        if profile not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
        if profile=='lab' and not t.get('verified'):return {'error':'Lab profile requires verified ownership'},403
        s=repo().create_schedule(t['id'],profile,interval,ident['user_id']);audit('SCHEDULE_CREATED','schedule',s['id'],{'interval_minutes':interval});return s,201

    # ZAP import / comparison
    @bp.post('/scans/<scan_id>/zap')
    @require_role('analyst')
    def zap_import(scan_id):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        filename='upload.json'
        if request.files.get('file'):
            f=request.files['file'];filename=f.filename or filename;raw=f.read(current_app.config['MAX_ZAP_UPLOAD_BYTES']+1)
            if len(raw)>current_app.config['MAX_ZAP_UPLOAD_BYTES']:return {'error':'ZAP file is too large'},413
            try:data=json.loads(raw.decode('utf-8'))
            except Exception:return {'error':'Invalid ZAP JSON'},400
        else:data=request.get_json(force=True)
        items=parse_zap_json(data);comparison=compare_with_scanner(repo().findings(scan_id),items)
        saved=repo().save_zap_import(scan_id,filename,items,comparison,ident['user_id']);audit('ZAP_IMPORTED','scan',scan_id,comparison['summary']);return saved,201

    # Reports / audit
    @bp.get('/scans/<scan_id>/report.<fmt>')
    @require_auth
    def report(scan_id,fmt):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        f=repo().findings(scan_id);comp=repo().comparison(scan_id)
        if fmt=='json':return Response(as_json(s,f,comp),mimetype='application/json')
        if fmt=='html':return Response(as_html(s,f,comp),mimetype='text/html')
        if fmt=='pdf':return Response(as_pdf(s,f,comp),mimetype='application/pdf',headers={'Content-Disposition':f'attachment; filename=scan-{scan_id}.pdf'})
        return {'error':'Unsupported format'},404

    @bp.get('/audit')
    @require_role('admin')
    def audit_list():return jsonify(repo().list_audit(current_identity()['organization_id']))

    return bp
