import json
import hashlib
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from flask import Blueprint,current_app,request,jsonify,Response,stream_with_context,send_file
from .security.targets import validate_target,TargetValidationError
from .reports import as_json,as_html,as_pdf
from .auth import current_identity,require_auth,require_role,require_scope,ROLES
from .crypto import hash_password,verify_password,token_hash,encrypt_secret,decrypt_secret
from .verification import make_verification,check_file,check_dns
from .preflight import run_target_preflight
from .zap import parse_zap_json,compare_with_scanner
from .mailer import send_email
from .backup import create_sqlite_backup,restore_sqlite_backup
from .metrics import snapshot,prometheus
import os
import tempfile
import pyotp

WEBHOOK_EVENTS={
  'scan.completed','scan.failed','finding.updated','finding.remediation_requested',
  'risk.accepted','schedule.created','schedule.updated','webhook.test'
}

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

    def send_token_email(user,purpose,token,subject,path):
        link=current_app.config["PUBLIC_APP_URL"].rstrip("/")+"/"+path+"?token="+token
        result=send_email(current_app.config,user["email"],subject,subject+"\n\n"+link)
        if not result.get("delivered"):
            repo().add_notification(None,user["id"],"auth",subject,link,{"development_link":link})
        return result,link

    def make_recovery_codes(count=10):
        raw=[secrets.token_hex(4).upper() for _ in range(count)]
        repo().replace_mfa_recovery_codes(current_identity()['user_id'],[token_hash(x.lower()) for x in raw])
        return [x[:4]+'-'+x[4:] for x in raw]

    def recovery_hash(value):
        return token_hash(str(value or '').replace('-','').replace(' ','').lower())

    # Authentication
    @bp.post('/auth/signup')
    def signup():
        if not repo().system_setting("registration_enabled",True):
            return {'error':'Public registration is currently disabled'},403
        d=request.get_json(force=True) or {}
        email=(d.get('email') or '').strip().lower();name=(d.get('name') or '').strip();password=d.get('password') or ''
        org=(d.get('organization_name') or f"{name}'s workspace").strip()
        if '@' not in email or len(email)>254:return {'error':'A valid email address is required'},400
        if len(name)<2:return {'error':'Your name is required'},400
        if len(password)<12:return {'error':'Use a password with at least 12 characters'},400
        if repo().get_user_by_email(email):return {'error':'An account already exists for this email'},409
        try:created=repo().create_signup(email,name,hash_password(password),org)
        except Exception:return {'error':'Unable to create account'},400
        if email in current_app.config.get('SYSTEM_ADMIN_EMAILS',[]):
            repo().set_system_admin(created['user_id'],True)
        raw=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32)
        sess=repo().create_session(created['user_id'],created['organization_id'],token_hash(raw),csrf,current_app.config['SESSION_TTL_HOURS'],request.headers.get('User-Agent','')[:300],ip_addr())
        repo().audit(created['organization_id'],created['user_id'],'ACCOUNT_SIGNUP','user',created['user_id'],{'email':email},ip_addr())
        ident=repo().session_identity(token_hash(raw))
        verify_raw=secrets.token_urlsafe(40)
        repo().create_auth_token(created['user_id'],'email_verify',token_hash(verify_raw),current_app.config['EMAIL_VERIFY_TTL_MINUTES'])
        userrow=repo().get_user_by_id(created['user_id'])
        delivery,dev_link=send_token_email(userrow,'email_verify',verify_raw,'Verify your SentinelScope email','verify-email')
        payload={'user':ident,'csrf_token':csrf,'verification_sent':True}
        if delivery.get('mode')=='outbox':payload['development_verification_link']=dev_link
        return cookie_response(payload,201,raw,current_app.config['SESSION_TTL_HOURS']*3600)

    @bp.post('/auth/login')
    def login():
        d=request.get_json(force=True) or {};email=(d.get('email') or '').strip().lower();password=d.get('password') or ''
        window=current_app.config['AUTH_WINDOW_MINUTES'];remote_ip=ip_addr()
        email_failures=repo().recent_failed_email_attempts(email,window)
        ip_failures=repo().recent_failed_ip_attempts(remote_ip,window)
        if email_failures>=current_app.config['AUTH_MAX_ATTEMPTS'] or ip_failures>=current_app.config.get('AUTH_MAX_IP_ATTEMPTS',50):
            return {'error':'Too many failed attempts. Try again later.'},429
        user=repo().get_user_by_email(email)
        locked=False
        if user and user.get('locked_until'):
            try:locked=datetime.fromisoformat(user['locked_until'])>datetime.now(timezone.utc)
            except Exception:locked=False
        ok=bool(user and not locked and user.get('active') and verify_password(password,user['password_hash']))
        repo().record_login_attempt(email,ip_addr(),ok)
        if not ok:
            if user:repo().set_login_failure(user['id'],repo().recent_failed_email_attempts(email)>=5)
            return {'error':'Invalid email or password'},401
        if user.get('mfa_enabled'):
            code=str(d.get('mfa_code') or '').replace(' ','')
            if not code:return {'error':'MFA code required','mfa_required':True},401
            try:mfa_secret=decrypt_secret(user.get('mfa_secret'),current_app.config.get('APP_ENCRYPTION_KEY'))
            except Exception:return {'error':'MFA secret could not be decrypted; check application encryption key configuration'},500
            totp_ok=pyotp.TOTP(mfa_secret).verify(code.replace('-',''),valid_window=1) if code.replace('-','').isdigit() else False
            recovery_ok=False if totp_ok else repo().consume_mfa_recovery_code(user['id'],recovery_hash(code))
            if not totp_ok and not recovery_ok:return {'error':'Invalid MFA or recovery code','mfa_required':True},401
        repo().set_login_success(user['id'])
        memberships=repo().list_memberships_for_user(user['id'])
        if not memberships:return {'error':'Account has no active workspace'},403
        org_id=(d.get('organization_id') if any(m['organization_id']==d.get('organization_id') for m in memberships) else memberships[0]['organization_id'])
        raw=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32)
        repo().create_session(user['id'],org_id,token_hash(raw),csrf,current_app.config['SESSION_TTL_HOURS'],request.headers.get('User-Agent','')[:300],ip_addr())
        ident=repo().session_identity(token_hash(raw));repo().audit(org_id,user['id'],'LOGIN','user',user['id'],{},ip_addr())
        return cookie_response({'user':ident,'csrf_token':csrf,'workspaces':memberships},200,raw,current_app.config['SESSION_TTL_HOURS']*3600)

    @bp.post('/auth/email-verification/request')
    @require_auth
    def email_verification_request():
        ident=current_identity();user=repo().get_user_by_id(ident['user_id'])
        if user.get('email_verified'):return {'ok':True,'already_verified':True}
        raw=secrets.token_urlsafe(40)
        repo().create_auth_token(user['id'],'email_verify',token_hash(raw),current_app.config['EMAIL_VERIFY_TTL_MINUTES'])
        delivery,link=send_token_email(user,'email_verify',raw,'Verify your SentinelScope email','verify-email')
        out={'ok':True,'sent':delivery.get('delivered',False)}
        if delivery.get('mode')=='outbox':out['development_verification_link']=link
        return out

    @bp.post('/auth/email-verification/confirm')
    def email_verification_confirm():
        d=request.get_json(force=True) or {};raw=d.get('token') or ''
        row=repo().consume_auth_token('email_verify',token_hash(raw))
        if not row:return {'error':'Verification link is invalid or expired'},400
        repo().set_email_verified(row['user_id'],True)
        return {'ok':True}

    @bp.post('/auth/forgot-password')
    def forgot_password():
        d=request.get_json(force=True) or {};email=(d.get('email') or '').strip().lower()
        user=repo().get_user_by_email(email)
        if user and user.get('active'):
            raw=secrets.token_urlsafe(40)
            repo().create_auth_token(user['id'],'password_reset',token_hash(raw),current_app.config['PASSWORD_RESET_TTL_MINUTES'])
            send_token_email(user,'password_reset',raw,'Reset your SentinelScope password','reset-password')
        return {'ok':True,'message':'If the account exists, reset instructions have been sent.'}

    @bp.post('/auth/reset-password')
    def reset_password():
        d=request.get_json(force=True) or {};raw=d.get('token') or '';new=d.get('new_password') or ''
        if len(new)<12:return {'error':'New password must be at least 12 characters'},400
        row=repo().consume_auth_token('password_reset',token_hash(raw))
        if not row:return {'error':'Reset link is invalid or expired'},400
        repo().update_user_password(row['user_id'],hash_password(new))
        repo().revoke_other_sessions(row['user_id'],'')
        return {'ok':True}

    @bp.post('/auth/mfa/setup')
    @require_auth
    def mfa_setup():
        ident=current_identity();secret=pyotp.random_base32()
        repo().create_auth_token(ident['user_id'],'mfa_setup',token_hash(secret),10,{'secret':secret})
        uri=pyotp.TOTP(secret).provisioning_uri(name=ident['email'],issuer_name=current_app.config['MFA_ISSUER'])
        return {'secret':secret,'otpauth_uri':uri}

    @bp.post('/auth/mfa/confirm')
    @require_auth
    def mfa_confirm():
        ident=current_identity();d=request.get_json(force=True) or {}
        secret=d.get('secret') or '';code=str(d.get('code') or '').replace(' ','')
        if not secret or not pyotp.TOTP(secret).verify(code,valid_window=1):
            return {'error':'Invalid authenticator code'},400
        try:
            stored_secret=encrypt_secret(secret,current_app.config.get('APP_ENCRYPTION_KEY'))
        except Exception as e:
            return {'error':'Invalid APP_ENCRYPTION_KEY: '+str(e)},500
        repo().set_mfa(ident['user_id'],True,stored_secret)
        codes=make_recovery_codes()
        audit('MFA_ENABLED','user',ident['user_id'],{'recovery_codes':len(codes),'encrypted':stored_secret.startswith('fernet$')})
        return {'ok':True,'recovery_codes':codes}

    @bp.post('/auth/mfa/disable')
    @require_auth
    def mfa_disable():
        ident=current_identity();d=request.get_json(force=True) or {};user=repo().get_user_by_id(ident['user_id'])
        if not verify_password(d.get('password') or '',user['password_hash']):return {'error':'Password is incorrect'},400
        repo().set_mfa(ident['user_id'],False,None);repo().clear_mfa_recovery_codes(ident['user_id']);audit('MFA_DISABLED','user',ident['user_id']);return {'ok':True}

    @bp.post('/auth/mfa/recovery-codes/regenerate')
    @require_auth
    def mfa_recovery_regenerate():
        ident=current_identity();d=request.get_json(force=True) or {};user=repo().get_user_by_id(ident['user_id'])
        if not user or not user.get('mfa_enabled'):return {'error':'MFA is not enabled'},400
        if not verify_password(d.get('password') or '',user['password_hash']):return {'error':'Password is incorrect'},400
        code=str(d.get('code') or '').replace(' ','')
        try:mfa_secret=decrypt_secret(user.get('mfa_secret'),current_app.config.get('APP_ENCRYPTION_KEY'))
        except Exception:return {'error':'MFA secret could not be decrypted; check application encryption key configuration'},500
        if not pyotp.TOTP(mfa_secret).verify(code,valid_window=1):return {'error':'Valid authenticator code required'},400
        codes=make_recovery_codes();audit('MFA_RECOVERY_CODES_REGENERATED','user',ident['user_id'],{'count':len(codes)})
        return {'ok':True,'recovery_codes':codes}

    @bp.post('/auth/workspace')
    @require_auth
    def switch_workspace():
        ident=current_identity();org=(request.get_json(force=True) or {}).get('organization_id')
        if not repo().switch_session_workspace(ident['session_id'],ident['user_id'],org):return {'error':'Workspace not available'},404
        return {'ok':True}

    @bp.get('/auth/invitations/info')
    def invitation_info():
        raw=request.args.get('token') or ''
        info=repo().invitation_info(token_hash(raw)) if raw else None
        if not info:return {'error':'Invitation is invalid or expired'},404
        return info

    @bp.post('/auth/invitations/accept')
    def invitation_accept():
        d=request.get_json(force=True) or {};raw=d.get('token') or '';name=(d.get('name') or '').strip();password=d.get('password') or ''
        info=repo().invitation_info(token_hash(raw)) if raw else None
        if not info:return {'error':'Invitation is invalid or expired'},400
        password_digest=None
        if not info.get('existing_account'):
            if len(name)<2 or len(password)<12:return {'error':'Name and a 12+ character password are required for a new account'},400
            password_digest=hash_password(password)
        try:accepted=repo().accept_invitation(token_hash(raw),name,password_digest)
        except ValueError as e:return {'error':str(e)},409
        if not accepted:return {'error':'Invitation is invalid, expired, or already accepted'},409
        return {'ok':True,**accepted}

    @bp.post('/auth/logout')
    @require_auth
    def logout():
        ident=current_identity();repo().revoke_session(ident['session_id']);audit('LOGOUT','user',ident['user_id'])
        response=jsonify({'ok':True});response.delete_cookie('wss_session',path='/');return response

    @bp.post('/auth/password')
    @require_auth
    def change_password():
        ident=current_identity();d=request.get_json(force=True) or {}
        current=d.get('current_password') or '';new=d.get('new_password') or ''
        user=repo().get_user_by_email(ident['email'])
        if not user or not verify_password(current,user['password_hash']):return {'error':'Current password is incorrect'},400
        if len(new)<12:return {'error':'New password must be at least 12 characters'},400
        repo().update_user_password(ident['user_id'],hash_password(new))
        repo().revoke_other_sessions(ident['user_id'],ident['session_id'])
        audit('PASSWORD_CHANGED','user',ident['user_id']);return {'ok':True}

    @bp.get('/auth/sessions')
    @require_auth
    def auth_sessions():
        ident=current_identity();rows=repo().list_sessions(ident['user_id'])
        for r in rows:r['current']=r['id']==ident['session_id']
        return jsonify(rows)

    @bp.delete('/auth/sessions/<session_id>')
    @require_auth
    def auth_session_revoke(session_id):
        ident=current_identity()
        if session_id==ident.get('session_id'):return {'error':'Use sign out to end the current session'},400
        if not repo().revoke_user_session(ident['user_id'],session_id):return {'error':'Session not found or already revoked'},404
        audit('SESSION_REVOKED','session',session_id);return {'ok':True}

    @bp.delete('/auth/account')
    @require_auth
    def delete_account():
        ident=current_identity();d=request.get_json(force=True) or {};user=repo().get_user_by_id(ident['user_id'])
        if not verify_password(d.get('password') or '',user['password_hash']):return {'error':'Password is incorrect'},400
        try:repo().delete_account(ident['user_id'])
        except ValueError as e:return {'error':str(e)},400
        response=jsonify({'ok':True});response.delete_cookie('wss_session',path='/');return response

    @bp.get('/auth/me')
    @require_auth
    def me():
        ident=current_identity()
        return {'user':ident,'csrf_token':ident['csrf_token'],'workspaces':repo().list_memberships_for_user(ident['user_id']),
                'security':{'recovery_codes_remaining':repo().unused_mfa_recovery_count(ident['user_id']) if ident.get('mfa_enabled') else 0}}

    # Workspace onboarding / readiness
    @bp.get('/onboarding')
    @require_auth
    def onboarding_get():
        ident=current_identity()
        return repo().onboarding_state(ident['user_id'],ident['organization_id'])

    @bp.post('/onboarding/dismiss')
    @require_auth
    def onboarding_dismiss():
        ident=current_identity();d=request.get_json(force=True) or {}
        dismissed=bool(d.get('dismissed',True))
        state=repo().set_onboarding_dismissed(ident['user_id'],ident['organization_id'],dismissed)
        audit('ONBOARDING_'+('DISMISSED' if dismissed else 'RESTORED'),'workspace',ident['organization_id'])
        return state

    # Dashboard
    @bp.get('/dashboard')
    @require_auth
    def dashboard():
        ident=current_identity();scans=repo().list_scans(30,ident['organization_id']);completed=[s for s in scans if s['status']=='COMPLETED'];latest=completed[0] if completed else None
        lifecycle=repo().list_finding_states(ident['organization_id'],limit=500);usage=repo().organization_scan_usage(ident['organization_id'])
        return {'projects':len(repo().list_projects(ident['organization_id'])),'targets':len(repo().list_targets(org_id=ident['organization_id'])),
                'latest_scan':latest,'recent_scans':scans[:8],'queue':repo().queue_stats(),
                'members':len(repo().list_members(ident['organization_id'])),'schedules':len(repo().list_schedules(ident['organization_id'])),
                'finding_states':{k:sum(1 for f in lifecycle if f['state']==k) for k in ['OPEN','ACKNOWLEDGED','IN_PROGRESS','ACCEPTED_RISK','FALSE_POSITIVE','REMEDIATED']},
                'issue_portfolio':repo().finding_portfolio_summary(ident['organization_id']),
                'asset_portfolio':repo().asset_portfolio_summary(ident['organization_id']),
                'scan_usage':usage,'scan_quota_per_day':repo().system_setting('scan_quota_per_day',100)}

    # Team / RBAC
    @bp.get('/team')
    @require_role('viewer')
    def team_list():return jsonify(repo().list_members(current_identity()['organization_id']))

    @bp.get('/team/<user_id>/activity')
    @require_role('admin')
    def team_member_activity(user_id):
        ident=current_identity();rows=repo().member_activity(ident['organization_id'],user_id,min(int(request.args.get('limit',100)),500))
        if rows is None:return {'error':'Team member not found'},404
        return jsonify(rows)

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
        try:updated=repo().update_member_role(current_identity()['organization_id'],user_id,role)
        except ValueError as e:return {'error':str(e)},409
        if not updated:return {'error':'Workspace member not found'},404
        audit('TEAM_ROLE_CHANGED','user',user_id,{'role':role})
        return {'ok':True,'role':role}

    @bp.post('/team/invitations')
    @require_role('admin')
    def create_team_invitation():
        ident=current_identity();d=request.get_json(force=True) or {};email=(d.get('email') or '').strip().lower();role=d.get('role','viewer')
        if '@' not in email or role not in {'admin','analyst','viewer'}:return {'error':'Valid email and role required'},400
        raw=secrets.token_urlsafe(40)
        try:inv=repo().create_invitation(ident['organization_id'],email,role,token_hash(raw),ident['user_id'],current_app.config['INVITE_TTL_HOURS'])
        except ValueError as e:return {'error':str(e)},409
        dummy={'id':'invite','email':email}
        result,link=send_token_email(dummy,'invite',raw,'You are invited to SentinelScope','accept-invite')
        audit('INVITATION_CREATED','invitation',inv['id'],{'email':email,'role':role})
        out={'id':inv['id'],'email':email,'role':role,'sent':result.get('delivered',False)}
        if result.get('mode')=='outbox':out['development_invite_link']=link
        return out,201

    @bp.get('/team/invitations')
    @require_role('admin')
    def team_invitations():
        return jsonify(repo().list_invitations(current_identity()['organization_id']))

    @bp.delete('/team/invitations/<invite_id>')
    @require_role('admin')
    def team_invitation_revoke(invite_id):
        ident=current_identity()
        if not repo().revoke_invitation(invite_id,ident['organization_id']):return {'error':'Pending invitation not found'},404
        audit('INVITATION_REVOKED','invitation',invite_id);return {'ok':True}

    @bp.post('/team/invitations/<invite_id>/resend')
    @require_role('admin')
    def team_invitation_resend(invite_id):
        ident=current_identity();existing=repo().get_invitation(invite_id,ident['organization_id'])
        if not existing or existing['status']!='PENDING':return {'error':'Pending invitation not found'},404
        raw=secrets.token_urlsafe(40)
        inv=repo().create_invitation(ident['organization_id'],existing['email'],existing['role'],token_hash(raw),ident['user_id'],current_app.config['INVITE_TTL_HOURS'])
        dummy={'id':'invite','email':existing['email']}
        result,link=send_token_email(dummy,'invite',raw,'You are invited to SentinelScope','accept-invite')
        audit('INVITATION_RESENT','invitation',inv['id'],{'email':existing['email'],'role':existing['role']})
        out={'id':inv['id'],'email':existing['email'],'role':existing['role'],'sent':result.get('delivered',False)}
        if result.get('mode')=='outbox':out['development_invite_link']=link
        return out,201

    @bp.patch('/team/<user_id>/active')
    @require_role('admin')
    def team_active(user_id):
        ident=current_identity();active=bool((request.get_json(force=True) or {}).get('active'))
        if not repo().deactivate_member(ident['organization_id'],user_id,active):return {'error':'Member cannot be changed'},400
        audit('TEAM_MEMBER_ACTIVE_CHANGED','user',user_id,{'active':active});return {'ok':True,'active':active}

    @bp.delete('/team/<user_id>')
    @require_role('admin')
    def team_remove(user_id):
        ident=current_identity()
        if not repo().remove_member(ident['organization_id'],user_id):return {'error':'Member cannot be removed'},400
        audit('TEAM_MEMBER_REMOVED','user',user_id);return {'ok':True}

    # Projects
    @bp.route('/projects',methods=['GET','POST'])
    @require_auth
    def projects():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_projects(ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        d=request.get_json(force=True) or {};name=(d.get('name') or '').strip()
        if not name:return {'error':'Project name is required'},400
        tags=[str(x).strip()[:48] for x in d.get('tags',[]) if str(x).strip()][:20] if isinstance(d.get('tags'),list) else []
        p=repo().create_project(name,d.get('description',''),ident['organization_id'],ident['user_id'],tags)
        repo().ensure_default_scan_profile(p['id'],ident['user_id'])
        audit('PROJECT_CREATED','project',p['id'],{'name':name,'tags':tags});return p,201

    @bp.patch('/projects/<project_id>')
    @require_role('analyst')
    def project_update(project_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        d=request.get_json(force=True) or {};updates={}
        if 'name' in d:
            name=(d.get('name') or '').strip()
            if not name:return {'error':'Project name is required'},400
            updates['name']=name[:160]
        if 'description' in d:updates['description']=str(d.get('description') or '')[:4000]
        if 'status' in d:
            if d['status'] not in {'active','archived'}:return {'error':'Invalid project status'},400
            updates['status']=d['status']
        if 'tags' in d:
            if not isinstance(d['tags'],list):return {'error':'tags must be an array'},400
            updates['tags_json']=json.dumps([str(x).strip()[:48] for x in d['tags'] if str(x).strip()][:20])
        saved=repo().update_project(project_id,ident['organization_id'],updates)
        audit('PROJECT_UPDATED','project',project_id,updates);return saved

    @bp.delete('/projects/<project_id>')
    @require_role('admin')
    def project_delete(project_id):
        try:ok=repo().delete_project(project_id,current_identity()['organization_id'])
        except ValueError as e:return {'error':str(e)},409
        if not ok:return {'error':'Project not found'},404
        audit('PROJECT_DELETED','project',project_id);return {'ok':True}

    @bp.route('/projects/<project_id>/policy',methods=['GET','PUT'])
    @require_auth
    def project_policy(project_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        if request.method=='GET':return repo().get_project_policy(project_id)
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        if ident.get('auth_method')=='api_key' and 'write' not in set(ident.get('api_scopes') or []) and 'admin' not in set(ident.get('api_scopes') or []):
            return {'error':'API key write scope required'},403
        d=request.get_json(force=True) or {}
        try:
            policy={
              'max_pages':max(1,min(int(d.get('max_pages',20)),200)),
              'max_depth':max(0,min(int(d.get('max_depth',2)),5)),
              'request_delay_ms':max(0,min(int(d.get('request_delay_ms',100)),5000)),
              'include_paths':[str(x)[:200] for x in d.get('include_paths',[])][:30],
              'exclude_paths':[str(x)[:200] for x in d.get('exclude_paths',[])][:30],
              'disabled_checks':[str(x)[:120] for x in d.get('disabled_checks',[])][:100],
            }
            for pattern in policy['include_paths']+policy['exclude_paths']:re.compile(pattern)
        except Exception as e:return {'error':'Invalid scan policy: '+str(e)},400
        saved=repo().set_project_policy(project_id,policy,ident['user_id'])
        audit('PROJECT_SCAN_POLICY_UPDATED','project',project_id,saved);return saved

    @bp.route('/projects/<project_id>/scan-profiles',methods=['GET','POST'])
    @require_auth
    def project_scan_profiles(project_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        if request.method=='GET':
            profiles=repo().list_scan_profiles(project_id)
            if not profiles and ROLES.get(ident['role'],0)>=ROLES['analyst']:
                profiles=[repo().ensure_default_scan_profile(project_id,ident['user_id'])]
            return jsonify(profiles)
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        if project.get('status')=='archived':return {'error':'Archived projects cannot create scan profiles'},409
        d=request.get_json(force=True) or {};name=(d.get('name') or '').strip()[:160]
        if not name:return {'error':'Profile name is required'},400
        mode=d.get('scan_mode','standard')
        if mode not in {'quick','standard','lab'}:return {'error':'Invalid scan mode'},400
        policy=d.get('policy') if isinstance(d.get('policy'),dict) else repo().get_project_policy(project_id)
        try:
            policy={
              'max_pages':max(1,min(int(policy.get('max_pages',20)),200)),
              'max_depth':max(0,min(int(policy.get('max_depth',2)),5)),
              'request_delay_ms':max(0,min(int(policy.get('request_delay_ms',100)),5000)),
              'include_paths':[str(x)[:200] for x in policy.get('include_paths',[])][:30],
              'exclude_paths':[str(x)[:200] for x in policy.get('exclude_paths',[])][:30],
              'disabled_checks':[str(x)[:120] for x in policy.get('disabled_checks',[])][:100],
            }
            for pattern in policy['include_paths']+policy['exclude_paths']:re.compile(pattern)
        except Exception as e:return {'error':'Invalid scan profile policy: '+str(e)},400
        row=repo().create_scan_profile(project_id,name,str(d.get('description') or '')[:1000],mode,policy,bool(d.get('is_default')),ident['user_id'])
        audit('SCAN_PROFILE_CREATED','scan_profile',row['id'],{'project_id':project_id,'name':name,'version':row['version']})
        return row,201

    @bp.patch('/projects/<project_id>/scan-profiles/<profile_id>')
    @require_role('analyst')
    def project_scan_profile_update(project_id,profile_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        if project.get('status')=='archived':return {'error':'Archived projects cannot modify scan profiles'},409
        current=repo().get_scan_profile(profile_id)
        if not current or current['project_id']!=project_id:return {'error':'Scan profile not found'},404
        d=request.get_json(force=True) or {};updates={}
        if d.get('active') is False:
            usage=repo().scan_profile_usage(profile_id,project_id)
            if usage['enabled_schedules']>0:return {'error':'Rebind or pause enabled schedules before deactivating this profile','usage':usage},409
        for key in ['name','description','scan_mode','is_default','active']:
            if key in d:updates[key]=d[key]
        if 'scan_mode' in updates and updates['scan_mode'] not in {'quick','standard','lab'}:return {'error':'Invalid scan mode'},400
        if 'policy' in d:
            p=d.get('policy') or {}
            try:
                updates['policy']={
                  'max_pages':max(1,min(int(p.get('max_pages',20)),200)),
                  'max_depth':max(0,min(int(p.get('max_depth',2)),5)),
                  'request_delay_ms':max(0,min(int(p.get('request_delay_ms',100)),5000)),
                  'include_paths':[str(x)[:200] for x in p.get('include_paths',[])][:30],
                  'exclude_paths':[str(x)[:200] for x in p.get('exclude_paths',[])][:30],
                  'disabled_checks':[str(x)[:120] for x in p.get('disabled_checks',[])][:100],
                }
                for pattern in updates['policy']['include_paths']+updates['policy']['exclude_paths']:re.compile(pattern)
            except Exception as e:return {'error':'Invalid scan profile policy: '+str(e)},400
        try:row=repo().update_scan_profile(profile_id,project_id,updates,ident['user_id'])
        except ValueError as e:return {'error':str(e)},409
        audit('SCAN_PROFILE_UPDATED','scan_profile',profile_id,{'project_id':project_id,'version':row['version'] if row else None})
        return row or ({'error':'Scan profile not found'},404)

    @bp.get('/projects/<project_id>/scan-profiles/<profile_id>/versions')
    @require_auth
    def project_scan_profile_versions(project_id,profile_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        current=repo().get_scan_profile(profile_id)
        if not current or current['project_id']!=project_id:return {'error':'Scan profile not found'},404
        return {'profile':current,'usage':repo().scan_profile_usage(profile_id,project_id),'versions':repo().scan_profile_versions(profile_id,project_id)}

    @bp.post('/projects/<project_id>/scan-profiles/<profile_id>/versions/<int:version>/restore')
    @require_role('analyst')
    def project_scan_profile_restore(project_id,profile_id,version):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        if project.get('status')=='archived':return {'error':'Archived projects cannot restore scan profiles'},409
        row=repo().restore_scan_profile_version(profile_id,project_id,version,ident['user_id'])
        if not row:return {'error':'Profile version not found'},404
        audit('SCAN_PROFILE_VERSION_RESTORED','scan_profile',profile_id,{'project_id':project_id,'restored_from_version':version,'new_version':row['version']})
        return row

    @bp.post('/projects/<project_id>/scan-profiles/<profile_id>/clone')
    @require_role('analyst')
    def project_scan_profile_clone(project_id,profile_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        row=repo().clone_scan_profile(profile_id,project_id,ident['user_id'])
        if not row:return {'error':'Scan profile not found'},404
        audit('SCAN_PROFILE_CLONED','scan_profile',row['id'],{'source_profile_id':profile_id,'project_id':project_id});return row,201

    @bp.delete('/projects/<project_id>/scan-profiles/<profile_id>')
    @require_role('analyst')
    def project_scan_profile_delete(project_id,profile_id):
        ident=current_identity();project=repo().get_project(project_id,ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        profiles=repo().list_scan_profiles(project_id)
        if len([x for x in profiles if x['active']])<=1:return {'error':'At least one active scan profile must remain'},409
        usage=repo().scan_profile_usage(profile_id,project_id)
        if usage['enabled_schedules']>0:return {'error':'Rebind or pause enabled schedules before archiving this profile','usage':usage},409
        try:ok=repo().delete_scan_profile(profile_id,project_id,ident['user_id'])
        except ValueError as e:return {'error':str(e),'usage':usage},409
        if not ok:return {'error':'Scan profile not found'},404
        audit('SCAN_PROFILE_ARCHIVED','scan_profile',profile_id,{'project_id':project_id,'usage':usage});return {'ok':True,'archived':True,'usage':usage}

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
        if project.get('status')=='archived':return {'error':'Archived projects cannot accept new targets'},409
        try:url=validate_target(d.get('url'),current_app.config['SCANNER_ALLOW_PRIVATE'])
        except TargetValidationError as e:return {'error':str(e)},400
        t=repo().create_target(project['id'],url,d.get('name') or url,True,False,ident['user_id'],d.get('criticality','medium'),d.get('environment','production'),d.get('tags') if isinstance(d.get('tags'),list) else [])
        owner=d.get('owner_user_id')
        if owner and owner not in {m['id'] for m in repo().list_members(ident['organization_id'])}:return {'error':'Target owner must be an active workspace member'},400
        t=repo().update_target_metadata(t['id'],ident['organization_id'],{'owner_user_id':owner or ident['user_id'],'notes':str(d.get('notes') or '')[:4000]})
        audit('TARGET_CREATED','target',t['id'],{'url':url,'criticality':t.get('criticality'),'environment':t.get('environment'),'owner_user_id':t.get('owner_user_id')});return t,201

    @bp.patch('/targets/<target_id>')
    @require_role('analyst')
    def target_update(target_id):
        ident=current_identity();t=repo().get_target(target_id,ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        d=request.get_json(force=True) or {};updates={}
        if 'name' in d:updates['name']=(d.get('name') or '').strip()[:160] or t['name']
        if 'criticality' in d:
            if d['criticality'] not in {'low','medium','high','critical'}:return {'error':'Invalid target criticality'},400
            updates['criticality']=d['criticality']
        if 'environment' in d:
            if d['environment'] not in {'development','test','staging','production'}:return {'error':'Invalid target environment'},400
            updates['environment']=d['environment']
        if 'tags' in d:
            if not isinstance(d['tags'],list):return {'error':'tags must be an array'},400
            updates['tags']=[str(x).strip()[:48] for x in d['tags'] if str(x).strip()][:20]
        if 'owner_user_id' in d:
            owner=d.get('owner_user_id')
            if owner and owner not in {m['id'] for m in repo().list_members(ident['organization_id'])}:return {'error':'Target owner must be an active workspace member'},400
            updates['owner_user_id']=owner or None
        if 'notes' in d:updates['notes']=str(d.get('notes') or '')[:4000]
        saved=repo().update_target_metadata(target_id,ident['organization_id'],updates) if updates else t
        audit('TARGET_METADATA_UPDATED','target',target_id,updates);return saved

    @bp.delete('/targets/<target_id>')
    @require_role('admin')
    def target_delete(target_id):
        ident=current_identity()
        try:ok=repo().delete_target(target_id,ident['organization_id'])
        except ValueError as e:return {'error':str(e)},409
        if not ok:return {'error':'Target not found'},404
        audit('TARGET_DELETED','target',target_id);return {'ok':True}

    @bp.route('/targets/<target_id>/preflight',methods=['GET','POST'])
    @require_role('analyst')
    def target_preflight(target_id):
        ident=current_identity();t=repo().get_target(target_id,ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        if request.method=='GET':
            limit=max(1,min(int(request.args.get('limit',10)),50))
            rows=repo().target_preflights(target_id,ident['organization_id'],limit)
            return {'latest':rows[0] if rows else None,'history':rows}
        d=request.get_json(silent=True) or {};profile=d.get('profile','standard')
        if profile not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
        result=run_target_preflight(t,profile,current_app.config['SCANNER_ALLOW_PRIVATE'],min(float(current_app.config.get('REQUEST_TIMEOUT',8)),8))
        saved=repo().save_target_preflight(target_id,ident['organization_id'],ident['user_id'],profile,result)
        audit('TARGET_PREFLIGHT_COMPLETED','target',target_id,{'profile':profile,'status':result.get('status'),'preflight_id':saved['id']})
        return saved,200

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
        if repo().system_setting('require_verified_email_for_scans',False) and not ident.get('email_verified'):
            return {'error':'Verify your email before creating assessments'},403
        d=request.get_json(force=True) or {};t=repo().get_target(d.get('target_id'),ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        project=repo().get_project(t['project_id'],ident['organization_id'])
        if project and project.get('status')=='archived':return {'error':'Archived projects cannot queue assessments'},409
        if not t.get('authorized'):return {'error':'Target is not authorized'},403
        named_profile=None
        if d.get('scan_profile_id'):
            named_profile=repo().get_scan_profile(d.get('scan_profile_id'))
            if not named_profile or named_profile['project_id']!=t['project_id'] or not named_profile.get('active'):return {'error':'Active scan profile not found for this project'},404
        profile=named_profile['scan_mode'] if named_profile else d.get('profile','standard')
        if profile not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
        if profile=='lab' and not t.get('verified'):return {'error':'Lab profile requires verified ownership'},403
        preflight=repo().latest_target_preflight(t['id'],ident['organization_id'],profile,15)
        if not preflight:
            pf_result=run_target_preflight(t,profile,current_app.config['SCANNER_ALLOW_PRIVATE'],min(float(current_app.config.get('REQUEST_TIMEOUT',8)),8))
            preflight=repo().save_target_preflight(t['id'],ident['organization_id'],ident['user_id'],profile,pf_result)
            audit('TARGET_PREFLIGHT_AUTO_COMPLETED','target',t['id'],{'profile':profile,'status':pf_result.get('status'),'preflight_id':preflight['id']})
        if preflight.get('status')=='BLOCKED':
            return {'error':'Target preflight blocked this assessment','preflight':preflight},409
        if ident.get('auth_method')=='api_key' and 'scan' not in set(ident.get('api_scopes') or []) and 'admin' not in set(ident.get('api_scopes') or []):
            return {'error':'API key scan scope required'},403
        usage=repo().organization_scan_usage(ident['organization_id'])
        quota=max(1,int(repo().system_setting('scan_quota_per_day',100)))
        concurrent=max(1,int(repo().system_setting('max_concurrent_scans_per_org',3)))
        if usage['last_24h']>=quota:return {'error':'Daily scan quota reached','quota':quota,'usage':usage},429
        if usage['active']>=concurrent:return {'error':'Concurrent scan limit reached','limit':concurrent,'usage':usage},429
        policy=dict(named_profile['policy']) if named_profile else repo().get_project_policy(t['project_id'])
        override=d.get('policy') if isinstance(d.get('policy'),dict) else {}
        try:
            if 'max_pages' in override:override['max_pages']=max(1,min(int(override['max_pages']),200))
            if 'max_depth' in override:override['max_depth']=max(0,min(int(override['max_depth']),5))
            if 'request_delay_ms' in override:override['request_delay_ms']=max(0,min(int(override['request_delay_ms']),5000))
            for key in ['include_paths','exclude_paths']:
                if key in override:
                    if not isinstance(override[key],list):return {'error':key+' must be an array'},400
                    override[key]=[str(x)[:200] for x in override[key]][:30]
                    for pattern in override[key]:re.compile(pattern)
            if 'disabled_checks' in override:
                if not isinstance(override['disabled_checks'],list):return {'error':'disabled_checks must be an array'},400
                override['disabled_checks']=[str(x)[:120] for x in override['disabled_checks']][:100]
        except (ValueError,TypeError,re.error) as e:return {'error':'Invalid per-scan policy: '+str(e)},400
        for key in ['max_pages','max_depth','request_delay_ms','include_paths','exclude_paths','disabled_checks']:
            if key in override:policy[key]=override[key]
        s=repo().create_scan(t['id'],t['url'],profile,ident['user_id'],policy,named_profile['id'] if named_profile else None);job=repo().enqueue_job('scan',{'scan_id':s['id'],'target_id':t['id']})
        audit('SCAN_QUEUED','scan',s['id'],{'profile':profile,'scan_profile_id':named_profile['id'] if named_profile else None,'scan_profile_version':named_profile['version'] if named_profile else None,'job_id':job['id'],'policy':policy,'preflight_id':preflight.get('id'),'preflight_status':preflight.get('status')});s['job_id']=job['id'];s['usage']=usage;s['preflight']=preflight;return s,202

    @bp.get('/scans/<scan_id>')
    @require_auth
    def scan_get(scan_id):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        s['findings']=repo().findings(scan_id);s['assets']=repo().assets(scan_id);s['asset_comparison']=repo().asset_comparison(scan_id);s['standards_summary']=repo().standards_summary(scan_id);s['policy']=repo().scan_policy(scan_id);s['comparison']=repo().comparison(scan_id);s['zap']=repo().latest_zap_import(scan_id);return s

    @bp.post('/scans/<scan_id>/cancel')
    @require_role('analyst')
    def scan_cancel_workspace(scan_id):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        if not repo().request_scan_cancel(scan_id):return {'error':'Only queued or running scans can be cancelled'},409
        audit('SCAN_CANCEL_REQUESTED','scan',scan_id);return {'ok':True}

    @bp.post('/scans/<scan_id>/rerun')
    @require_role('analyst')
    def scan_rerun(scan_id):
        ident=current_identity();old=repo().get_scan(scan_id,ident['organization_id'])
        if not old:return {'error':'Scan not found'},404
        target=repo().get_target(old['target_id'],ident['organization_id'])
        if not target:return {'error':'Target not found'},404
        if not target.get('authorized'):return {'error':'Target is not authorized'},403
        project=repo().get_project(target['project_id'],ident['organization_id'])
        if project and project.get('status')=='archived':return {'error':'Archived projects cannot queue assessments'},409
        if old['profile']=='lab' and not target.get('verified'):return {'error':'Lab profile requires verified ownership'},403
        if repo().system_setting('require_verified_email_for_scans',False) and not ident.get('email_verified'):
            return {'error':'Verify your email before creating assessments'},403
        preflight=repo().latest_target_preflight(target['id'],ident['organization_id'],old['profile'],15)
        if not preflight:
            pf_result=run_target_preflight(target,old['profile'],current_app.config['SCANNER_ALLOW_PRIVATE'],min(float(current_app.config.get('REQUEST_TIMEOUT',8)),8))
            preflight=repo().save_target_preflight(target['id'],ident['organization_id'],ident['user_id'],old['profile'],pf_result)
            audit('TARGET_PREFLIGHT_AUTO_COMPLETED','target',target['id'],{'profile':old['profile'],'status':pf_result.get('status'),'preflight_id':preflight['id']})
        if preflight.get('status')=='BLOCKED':
            return {'error':'Target preflight blocked this rerun','preflight':preflight},409
        usage=repo().organization_scan_usage(ident['organization_id'])
        quota=max(1,int(repo().system_setting('scan_quota_per_day',100)));concurrent=max(1,int(repo().system_setting('max_concurrent_scans_per_org',3)))
        if usage['last_24h']>=quota:return {'error':'Daily scan quota reached','quota':quota,'usage':usage},429
        if usage['active']>=concurrent:return {'error':'Concurrent scan limit reached','limit':concurrent,'usage':usage},429
        policy=repo().scan_policy(scan_id) or repo().get_project_policy(target['project_id'])
        profile_snapshot={'id':old.get('scan_profile_id'),'name':old.get('scan_profile_name'),'version':old.get('scan_profile_version'),'scan_mode':old['profile']} if old.get('scan_profile_id') else None
        new=repo().create_scan(target['id'],target['url'],old['profile'],ident['user_id'],policy,old.get('scan_profile_id'),profile_snapshot)
        job=repo().enqueue_job('scan',{'scan_id':new['id'],'target_id':target['id'],'rerun_of':scan_id})
        audit('SCAN_RERUN_QUEUED','scan',new['id'],{'rerun_of':scan_id,'job_id':job['id'],'preflight_id':preflight.get('id')})
        new['job_id']=job['id'];new['rerun_of']=scan_id;new['preflight']=preflight;return new,202

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

    @bp.get('/assets')
    @require_auth
    def asset_inventory():
        ident=current_identity()
        rows=repo().latest_assets_for_org(ident['organization_id'],min(int(request.args.get('limit',2000)),5000))
        q=(request.args.get('q') or '').strip().lower();kind=(request.args.get('kind') or '').strip().lower()
        if q:rows=[r for r in rows if q in (r.get('url') or '').lower() or q in (r.get('title') or '').lower() or q in (r.get('target_name') or '').lower() or q in (r.get('project_name') or '').lower()]
        if kind:rows=[r for r in rows if (r.get('kind') or '').lower()==kind]
        return {'summary':repo().asset_portfolio_summary(ident['organization_id']),'items':rows}

    @bp.get('/assets/history')
    @require_auth
    def asset_history():
        ident=current_identity();target_id=(request.args.get('target_id') or '').strip();url=(request.args.get('url') or '').strip()
        if not target_id or not url:return {'error':'target_id and url are required'},400
        row=repo().asset_history(ident['organization_id'],target_id,url,min(int(request.args.get('limit',100)),500))
        if row is None:return {'error':'Asset or target not found'},404
        return row

    @bp.get('/exposure-map')
    @require_auth
    def exposure_map():
        ident=current_identity();org_id=ident['organization_id']
        projects=repo().list_projects(org_id)
        targets=repo().list_targets(org_id=org_id)
        assets=repo().latest_assets_for_org(org_id,3000)
        issues=repo().list_finding_states(org_id,limit=5000)
        members=repo().list_members(org_id)
        active_issues=[x for x in issues if x.get('state') not in {'REMEDIATED','FALSE_POSITIVE'}]
        nodes=[];edges=[];seen=set()
        def add_node(node):
            if node['id'] not in seen:
                seen.add(node['id']);nodes.append(node)
        for p in projects:
            add_node({'id':'project:'+p['id'],'type':'project','label':p.get('name') or 'Project','status':p.get('status') or 'active'})
        for t in targets:
            tid='target:'+t['id'];add_node({'id':tid,'type':'target','label':t.get('name') or t.get('url'),'subtitle':t.get('url'),'criticality':t.get('criticality') or 'medium','environment':t.get('environment') or 'production','verified':bool(t.get('verified')),'owner_user_id':t.get('owner_user_id')})
            edges.append({'source':'project:'+t['project_id'],'target':tid,'type':'contains'})
        for a in assets:
            aid='asset:'+a['id'];add_node({'id':aid,'type':'asset','label':a.get('title') or a.get('url'),'subtitle':a.get('url'),'kind':a.get('kind'),'status_code':a.get('status_code'),'depth':a.get('depth')})
            edges.append({'source':'target:'+a['target_id'],'target':aid,'type':'discovered'})
        for x in active_issues:
            xid='issue:'+x['id'];risk=int(x.get('risk_score') or 0);severity=x.get('effective_severity') or x.get('base_severity') or 'INFO'
            add_node({'id':xid,'type':'issue','label':x.get('title') or x.get('check_id'),'severity':severity,'risk_score':risk,'state':x.get('state'),'overdue':bool(x.get('overdue')),'assignee_user_id':x.get('assignee_user_id')})
            edges.append({'source':'target:'+x['target_id'],'target':xid,'type':'has_issue'})
            if x.get('assignee_user_id'):
                uid='user:'+x['assignee_user_id'];member=next((m for m in members if m['id']==x['assignee_user_id']),None)
                add_node({'id':uid,'type':'owner','label':member.get('name') if member else 'Assigned member','subtitle':member.get('email') if member else None})
                edges.append({'source':xid,'target':uid,'type':'owned_by'})
        risk_by_target={}
        for x in active_issues:
            row=risk_by_target.setdefault(x['target_id'],{'target_id':x['target_id'],'risk_score':0,'issues':0,'critical':0,'high':0,'overdue':0})
            row['risk_score']=max(row['risk_score'],int(x.get('risk_score') or 0));row['issues']+=1
            sev=(x.get('effective_severity') or x.get('base_severity') or '').upper()
            if sev=='CRITICAL':row['critical']+=1
            if sev=='HIGH':row['high']+=1
            if x.get('overdue'):row['overdue']+=1
        top_targets=sorted(risk_by_target.values(),key=lambda x:(-x['risk_score'],-x['issues']))[:8]
        summary={'projects':len(projects),'targets':len(targets),'assets':len(assets),'active_issues':len(active_issues),'assigned_issues':sum(1 for x in active_issues if x.get('assignee_user_id')),'overdue_issues':sum(1 for x in active_issues if x.get('overdue')),'critical_high':sum(1 for x in active_issues if (x.get('effective_severity') or x.get('base_severity')) in {'CRITICAL','HIGH'})}
        return {'nodes':nodes,'edges':edges,'summary':summary,'top_targets':top_targets}

    @bp.get('/portfolio/issues')
    @require_auth
    def issue_portfolio():
        ident=current_identity();rows=repo().list_finding_states(ident['organization_id'],request.args.get('state'),request.args.get('target_id'),5000)
        q=(request.args.get('q') or '').strip().lower();assignee=request.args.get('assignee_user_id')
        if q:rows=[r for r in rows if q in (r.get('title') or '').lower() or q in (r.get('target_name') or '').lower() or q in (r.get('project_name') or '').lower() or q in (r.get('check_id') or '').lower()]
        if assignee:rows=[r for r in rows if r.get('assignee_user_id')==assignee]
        return {'summary':repo().finding_portfolio_summary(ident['organization_id']),'items':rows}

    # Finding lifecycle and remediation workflow
    @bp.route('/workspace/security-policy',methods=['GET','PUT'])
    @require_auth
    def workspace_security_policy():
        ident=current_identity()
        if request.method=='GET':return repo().get_workspace_security_policy(ident['organization_id'])
        if ROLES.get(ident['role'],0)<ROLES['admin']:return {'error':'Admin role required'},403
        d=request.get_json(force=True) or {}
        try:policy=repo().set_workspace_security_policy(ident['organization_id'],d,ident['user_id'])
        except (ValueError,TypeError) as e:return {'error':'Invalid security policy: '+str(e)},400
        audit('WORKSPACE_SECURITY_POLICY_UPDATED','organization',ident['organization_id'],policy);return policy

    @bp.route('/issue-views',methods=['GET','POST'])
    @require_auth
    def issue_views():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_issue_saved_views(ident['organization_id'],ident['user_id']))
        d=request.get_json(force=True) or {};name=(d.get('name') or '').strip()[:80];filters=d.get('filters') if isinstance(d.get('filters'),dict) else {}
        if not name:return {'error':'View name is required'},400
        shared=bool(d.get('is_shared'))
        if shared and ROLES.get(ident['role'],0)<ROLES['admin']:return {'error':'Admin role required to create shared views'},403
        row=repo().create_issue_saved_view(ident['organization_id'],ident['user_id'],name,filters,shared)
        audit('ISSUE_VIEW_CREATED','issue_view',row['id'],{'name':name,'shared':shared});return row,201

    @bp.route('/issue-views/<view_id>',methods=['PATCH','DELETE'])
    @require_auth
    def issue_view_update(view_id):
        ident=current_identity();can_admin=ROLES.get(ident['role'],0)>=ROLES['admin']
        if request.method=='DELETE':
            if not repo().delete_issue_saved_view(view_id,ident['organization_id'],ident['user_id'],can_admin):return {'error':'Saved view not found'},404
            audit('ISSUE_VIEW_DELETED','issue_view',view_id);return {'ok':True}
        d=request.get_json(force=True) or {}
        if d.get('is_shared') and not can_admin:return {'error':'Admin role required to share views'},403
        row=repo().update_issue_saved_view(view_id,ident['organization_id'],ident['user_id'],d,can_admin)
        if not row:return {'error':'Saved view not found'},404
        audit('ISSUE_VIEW_UPDATED','issue_view',view_id,d);return row

    @bp.post('/finding-states/bulk')
    @require_role('analyst')
    def finding_states_bulk():
        ident=current_identity();d=request.get_json(force=True) or {};ids=d.get('ids') if isinstance(d.get('ids'),list) else []
        if not ids:return {'error':'Select at least one issue'},400
        updates=d.get('updates') if isinstance(d.get('updates'),dict) else {}
        allowed={'state','severity_override','assignee_user_id','due_at','risk_reason','risk_expires_at'}
        updates={k:v for k,v in updates.items() if k in allowed}
        if not updates:return {'error':'No supported updates supplied'},400
        state=updates.get('state')
        if state and state not in {'OPEN','ACKNOWLEDGED','IN_PROGRESS','ACCEPTED_RISK','FALSE_POSITIVE','REMEDIATED'}:return {'error':'Invalid finding lifecycle state'},400
        if state in {'ACCEPTED_RISK','FALSE_POSITIVE'} and not (updates.get('risk_reason') or '').strip():return {'error':'A reason is required for risk acceptance or false-positive classification'},400
        policy=repo().get_workspace_security_policy(ident['organization_id'])
        if state=='ACCEPTED_RISK':
            if not updates.get('risk_expires_at'):return {'error':'Risk acceptance requires a review/expiry date'},400
            if policy.get('require_owner_for_risk_acceptance') and ident['role']!='owner':return {'error':'Workspace policy requires Owner approval for risk acceptance'},403
            updates['risk_accepted_by']=ident['user_id']
        if updates.get('assignee_user_id') and updates.get('assignee_user_id') not in {m['id'] for m in repo().list_members(ident['organization_id'])}:return {'error':'Assignee must be a workspace member'},400
        result=repo().bulk_update_finding_states(ids,ident['organization_id'],updates,ident['user_id'])
        audit('FINDING_BULK_UPDATED','finding_state',None,{'count':result['count'],'updates':updates})
        return result

    @bp.get('/finding-states')
    @require_auth
    def finding_states():
        ident=current_identity();return jsonify(repo().list_finding_states(ident['organization_id'],request.args.get('state'),request.args.get('target_id')))

    @bp.get('/finding-states/<state_id>')
    @require_auth
    def finding_state_get(state_id):
        ident=current_identity();row=repo().get_finding_state(state_id,ident['organization_id'])
        if not row:return {'error':'Finding state not found'},404
        row['comments']=repo().finding_comments(state_id,ident['organization_id']);row['verifications']=repo().remediation_history(state_id,ident['organization_id']);row['timeline']=repo().finding_timeline(state_id,ident['organization_id']);row['activity']=repo().finding_activity(state_id,ident['organization_id']);return row

    @bp.patch('/finding-states/<state_id>')
    @require_role('analyst')
    def finding_state_update(state_id):
        ident=current_identity();d=request.get_json(force=True) or {}
        state=d.get('state')
        if state and state not in {'OPEN','ACKNOWLEDGED','IN_PROGRESS','ACCEPTED_RISK','FALSE_POSITIVE','REMEDIATED'}:return {'error':'Invalid finding lifecycle state'},400
        if state in {'ACCEPTED_RISK','FALSE_POSITIVE'} and not (d.get('risk_reason') or '').strip():return {'error':'A reason is required for risk acceptance or false-positive classification'},400
        if state=='ACCEPTED_RISK' and not d.get('risk_expires_at'):return {'error':'Risk acceptance requires a review/expiry date'},400
        if state=='ACCEPTED_RISK':
            policy=repo().get_workspace_security_policy(ident['organization_id'])
            if policy.get('require_owner_for_risk_acceptance') and ident['role']!='owner':return {'error':'Workspace policy requires Owner approval for risk acceptance'},403
            d['risk_accepted_by']=ident['user_id']
        if d.get('assignee_user_id') and d.get('assignee_user_id') not in {m['id'] for m in repo().list_members(ident['organization_id'])}:return {'error':'Assignee must be a workspace member'},400
        row=repo().update_finding_state(state_id,ident['organization_id'],d,ident['user_id'])
        if not row:return {'error':'Finding state not found'},404
        audit('FINDING_STATE_UPDATED','finding_state',state_id,d)
        event='risk.accepted' if row.get('state')=='ACCEPTED_RISK' else 'finding.updated'
        repo().emit_webhook_event(ident['organization_id'],event,{'finding_state_id':state_id,'target_id':row.get('target_id'),'state':row.get('state'),'severity':row.get('effective_severity') or row.get('base_severity'),'title':row.get('title'),'updated_by':ident['user_id']})
        return row

    @bp.route('/finding-states/<state_id>/comments',methods=['GET','POST'])
    @require_auth
    def finding_state_comments(state_id):
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().finding_comments(state_id,ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        body=((request.get_json(force=True) or {}).get('body') or '').strip()
        if not body:return {'error':'Comment body is required'},400
        row=repo().add_finding_comment(state_id,ident['organization_id'],ident['user_id'],body[:4000])
        if not row:return {'error':'Finding state not found'},404
        audit('FINDING_COMMENT_ADDED','finding_state',state_id);return row,201

    @bp.post('/finding-states/<state_id>/verify')
    @require_role('analyst')
    def finding_verify(state_id):
        ident=current_identity();state=repo().get_finding_state(state_id,ident['organization_id'])
        if not state:return {'error':'Finding state not found'},404
        if repo().system_setting('require_verified_email_for_scans',False) and not ident.get('email_verified'):
            return {'error':'Verify your email before creating assessments'},403
        t=repo().get_target(state['target_id'],ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        if not t.get('authorized'):return {'error':'Target is not authorized'},403
        project=repo().get_project(t['project_id'],ident['organization_id'])
        if not project:return {'error':'Project not found'},404
        if project.get('status')=='archived':return {'error':'Archived projects cannot queue remediation verification'},409
        prior=repo().get_scan(state.get('last_scan_id'),ident['organization_id']) if state.get('last_scan_id') else None
        mode=prior.get('profile') if prior else 'standard'
        if mode=='lab' and not t.get('verified'):return {'error':'Lab profile requires verified ownership'},403
        preflight=repo().latest_target_preflight(t['id'],ident['organization_id'],mode,15)
        if not preflight:
            pf_result=run_target_preflight(t,mode,current_app.config['SCANNER_ALLOW_PRIVATE'],min(float(current_app.config.get('REQUEST_TIMEOUT',8)),8))
            preflight=repo().save_target_preflight(t['id'],ident['organization_id'],ident['user_id'],mode,pf_result)
            audit('TARGET_PREFLIGHT_AUTO_COMPLETED','target',t['id'],{'profile':mode,'status':pf_result.get('status'),'preflight_id':preflight['id']})
        if preflight.get('status')=='BLOCKED':
            return {'error':'Target preflight blocked remediation verification','preflight':preflight},409
        usage=repo().organization_scan_usage(ident['organization_id'])
        quota=max(1,int(repo().system_setting('scan_quota_per_day',100)))
        concurrent=max(1,int(repo().system_setting('max_concurrent_scans_per_org',3)))
        if usage['last_24h']>=quota:return {'error':'Daily scan quota reached','quota':quota,'usage':usage},429
        if usage['active']>=concurrent:return {'error':'Concurrent scan limit reached','limit':concurrent,'usage':usage},429
        policy=repo().scan_policy(prior['id']) if prior else repo().get_project_policy(t['project_id'])
        if not policy:policy=repo().get_project_policy(t['project_id'])
        snapshot={'id':prior.get('scan_profile_id'),'name':prior.get('scan_profile_name'),'version':prior.get('scan_profile_version'),'scan_mode':mode} if prior and prior.get('scan_profile_id') else None
        scan=repo().create_scan(t['id'],t['url'],mode,ident['user_id'],policy,prior.get('scan_profile_id') if prior else None,snapshot)
        job=repo().enqueue_job('scan',{'scan_id':scan['id'],'target_id':t['id'],'purpose':'remediation_verification','finding_state_id':state_id})
        verification=repo().create_remediation_verification(state_id,scan['id'],ident['user_id'])
        audit('REMEDIATION_VERIFICATION_QUEUED','finding_state',state_id,{'scan_id':scan['id'],'source_scan_id':prior.get('id') if prior else None,'profile':mode,'preflight_id':preflight.get('id')})
        repo().emit_webhook_event(ident['organization_id'],'finding.remediation_requested',{'finding_state_id':state_id,'scan_id':scan['id'],'target_id':state.get('target_id'),'requested_by':ident['user_id']})
        return {'verification':verification,'scan':scan,'job_id':job['id'],'preflight':preflight},202

    # Schedules
    @bp.route('/schedules',methods=['GET','POST'])
    @require_auth
    def schedules():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_schedules(ident['organization_id']))
        if ROLES.get(ident['role'],0)<ROLES['analyst']:return {'error':'Analyst role required'},403
        if repo().system_setting('require_verified_email_for_scans',False) and not ident.get('email_verified'):
            return {'error':'Verify your email before creating recurring assessments'},403
        d=request.get_json(force=True) or {};t=repo().get_target(d.get('target_id'),ident['organization_id'])
        if not t:return {'error':'Target not found'},404
        interval=int(d.get('interval_minutes') or 1440)
        if interval<60:return {'error':'Minimum recurring interval is 60 minutes'},400
        named_profile=None
        if d.get('scan_profile_id'):
            named_profile=repo().get_scan_profile(d.get('scan_profile_id'))
            if not named_profile or named_profile['project_id']!=t['project_id'] or not named_profile.get('active'):return {'error':'Active scan profile not found for this target project'},404
        profile=named_profile['scan_mode'] if named_profile else d.get('profile','standard')
        if profile not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
        if profile=='lab' and not t.get('verified'):return {'error':'Lab profile requires verified ownership'},403
        s=repo().create_schedule(t['id'],profile,interval,ident['user_id'],d.get('name'),d.get('notify_on_failure',True),named_profile['id'] if named_profile else None)
        audit('SCHEDULE_CREATED','schedule',s['id'],{'interval_minutes':interval,'name':s.get('name'),'scan_profile_id':named_profile['id'] if named_profile else None});return s,201

    @bp.patch('/schedules/<schedule_id>')
    @require_role('analyst')
    def schedule_update(schedule_id):
        ident=current_identity();d=request.get_json(force=True) or {};updates={}
        if 'enabled' in d:updates['enabled']=bool(d['enabled'])
        if 'name' in d:updates['name']=(d.get('name') or '').strip()[:160] or None
        if 'notify_on_failure' in d:updates['notify_on_failure']=bool(d['notify_on_failure'])
        if 'interval_minutes' in d:
            interval=int(d.get('interval_minutes') or 0)
            if interval<60 or interval>525600:return {'error':'Schedule interval must be between 60 minutes and one year'},400
            updates['interval_minutes']=interval
        if 'scan_profile_id' in d:
            existing=repo().get_schedule(schedule_id,ident['organization_id'])
            if not existing:return {'error':'Schedule not found'},404
            profile_id=d.get('scan_profile_id') or None
            if profile_id:
                named=repo().get_scan_profile(profile_id)
                if not named or named['project_id']!=existing['project_id'] or not named.get('active'):return {'error':'Active scan profile not found for this schedule'},404
                updates['scan_profile_id']=profile_id;updates['profile']=named['scan_mode']
            else:updates['scan_profile_id']=None
        if 'profile' in d:
            if d['profile'] not in {'quick','standard','lab'}:return {'error':'Invalid profile'},400
            if d['profile']=='lab':
                existing=repo().get_schedule(schedule_id,ident['organization_id'])
                if not existing:return {'error':'Schedule not found'},404
                if existing.get('project_status')=='archived':return {'error':'Archived projects cannot configure recurring assessments'},409
                if not existing.get('target_verified'):return {'error':'Lab profile requires verified ownership'},403
            updates['profile']=d['profile']
        existing=repo().get_schedule(schedule_id,ident['organization_id'])
        if existing and existing.get('project_status')=='archived':return {'error':'Archived projects cannot modify recurring assessments'},409
        saved=repo().update_schedule(schedule_id,ident['organization_id'],updates)
        if not saved:return {'error':'Schedule not found'},404
        audit('SCHEDULE_UPDATED','schedule',schedule_id,updates)
        repo().emit_webhook_event(ident['organization_id'],'schedule.updated',{'schedule_id':schedule_id,'changes':updates,'updated_by':ident['user_id']})
        return saved

    @bp.post('/schedules/<schedule_id>/run-now')
    @require_role('analyst')
    def schedule_run_now(schedule_id):
        ident=current_identity()
        if repo().system_setting('require_verified_email_for_scans',False) and not ident.get('email_verified'):
            return {'error':'Verify your email before running recurring assessments'},403
        schedule=repo().get_schedule(schedule_id,ident['organization_id'])
        if not schedule:return {'error':'Schedule not found'},404
        named_profile=repo().get_scan_profile(schedule.get('scan_profile_id')) if schedule.get('scan_profile_id') else None
        if schedule.get('scan_profile_id') and (not named_profile or not named_profile.get('active')):
            return {'error':'This schedule is bound to an inactive or missing scan profile; rebind it before running'},409
        mode=named_profile['scan_mode'] if named_profile else schedule.get('profile','standard')
        target=repo().get_target(schedule['target_id'],ident['organization_id'])
        if not target:return {'error':'Target not found'},404
        if not target.get('authorized'):return {'error':'Target is not authorized'},403
        preflight=repo().latest_target_preflight(target['id'],ident['organization_id'],mode,15)
        if not preflight:
            pf_result=run_target_preflight(target,mode,current_app.config['SCANNER_ALLOW_PRIVATE'],min(float(current_app.config.get('REQUEST_TIMEOUT',8)),8))
            preflight=repo().save_target_preflight(target['id'],ident['organization_id'],ident['user_id'],mode,pf_result)
            audit('TARGET_PREFLIGHT_AUTO_COMPLETED','target',target['id'],{'profile':mode,'status':pf_result.get('status'),'preflight_id':preflight['id']})
        if preflight.get('status')=='BLOCKED':
            return {'error':'Target preflight blocked this recurring assessment','preflight':preflight},409
        usage=repo().organization_scan_usage(ident['organization_id'])
        quota=max(1,int(repo().system_setting('scan_quota_per_day',100)))
        concurrent=max(1,int(repo().system_setting('max_concurrent_scans_per_org',3)))
        if usage['last_24h']>=quota:return {'error':'Daily scan quota reached','quota':quota,'usage':usage},429
        if usage['active']>=concurrent:return {'error':'Concurrent scan limit reached','limit':concurrent,'usage':usage},429
        try:scan=repo().run_schedule_now(schedule_id,ident['organization_id'],ident['user_id'])
        except ValueError as e:return {'error':str(e)},409
        audit('SCHEDULE_RUN_NOW','schedule',schedule_id,{'scan_id':scan['id'],'preflight_id':preflight.get('id')});scan['preflight']=preflight;return scan,202

    @bp.get('/schedules/<schedule_id>/history')
    @require_auth
    def schedule_history(schedule_id):
        ident=current_identity();return jsonify(repo().schedule_history(schedule_id,ident['organization_id']))

    @bp.delete('/schedules/<schedule_id>')
    @require_role('analyst')
    def schedule_delete(schedule_id):
        ident=current_identity()
        if not repo().delete_schedule(schedule_id,ident['organization_id']):return {'error':'Schedule not found'},404
        audit('SCHEDULE_DELETED','schedule',schedule_id);return {'ok':True}

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

    @bp.get('/portfolio/escalations')
    @require_auth
    def portfolio_escalations():
        ident=current_identity();return jsonify(repo().list_finding_escalations(ident['organization_id'],min(int(request.args.get('limit',200)),1000)))

    # Reports / audit
    @bp.get('/scans/<scan_id>/report.<fmt>')
    @require_auth
    def report(scan_id,fmt):
        ident=current_identity();s=repo().get_scan(scan_id,ident['organization_id'])
        if not s:return {'error':'Scan not found'},404
        f=repo().findings(scan_id);comp=repo().comparison(scan_id);target=repo().get_target(s['target_id'],ident['organization_id'])
        context={'assets':repo().assets(scan_id),'asset_comparison':repo().asset_comparison(scan_id),'standards_summary':repo().standards_summary(scan_id),
                 'policy':repo().scan_policy(scan_id),'target':target or {},'zap':repo().latest_zap_import(scan_id)}
        if fmt not in {'json','html','pdf'}:return {'error':'Unsupported format'},404
        if fmt=='json':body=as_json(s,f,comp,context);mimetype='application/json';disposition='attachment'
        elif fmt=='html':body=as_html(s,f,comp,context);mimetype='text/html';disposition='inline'
        else:body=as_pdf(s,f,comp,context);mimetype='application/pdf';disposition='attachment'
        raw=body if isinstance(body,(bytes,bytearray)) else str(body).encode('utf-8')
        digest=hashlib.sha256(raw).hexdigest()
        repo().record_report_export(ident['organization_id'],scan_id,fmt,ident['user_id'],digest,len(raw))
        audit('REPORT_EXPORTED','scan',scan_id,{'format':fmt,'sha256':digest,'size_bytes':len(raw)})
        return Response(body,mimetype=mimetype,headers={'Content-Disposition':f'{disposition}; filename=sentinelscope-{scan_id}.{fmt}','X-SentinelScope-SHA256':digest})

    @bp.get('/reports/history')
    @require_auth
    def report_history():
        ident=current_identity();return jsonify(repo().list_report_exports(ident['organization_id'],min(int(request.args.get('limit',200)),1000)))

    # Enterprise access reviews
    @bp.route('/access-reviews',methods=['GET','POST'])
    @require_role('admin')
    def access_reviews():
        ident=current_identity()
        if request.method=='GET':return jsonify(repo().list_access_reviews(ident['organization_id']))
        d=request.get_json(force=True) or {};name=(d.get('name') or '').strip()[:180] or ('Workspace access review '+datetime.now(timezone.utc).date().isoformat())
        row=repo().create_access_review(ident['organization_id'],name,ident['user_id'])
        audit('ACCESS_REVIEW_CREATED','access_review',row['id'],{'name':name,'members':row['summary']['total']})
        return row,201

    @bp.get('/access-reviews/<review_id>')
    @require_role('admin')
    def access_review_get(review_id):
        ident=current_identity();row=repo().get_access_review(review_id,ident['organization_id'])
        if not row:return {'error':'Access review not found'},404
        return row

    @bp.patch('/access-reviews/<review_id>/items/<item_id>')
    @require_role('admin')
    def access_review_decide(review_id,item_id):
        ident=current_identity();d=request.get_json(force=True) or {};decision=(d.get('decision') or '').upper()
        if decision not in {'APPROVE','REVOKE'}:return {'error':'Decision must be APPROVE or REVOKE'},400
        try:row=repo().decide_access_review_item(review_id,item_id,ident['organization_id'],decision,d.get('note'),ident['user_id'])
        except ValueError as e:return {'error':str(e)},400
        if not row:return {'error':'Open access review item not found'},404
        audit('ACCESS_REVIEW_ITEM_DECIDED','access_review',review_id,{'item_id':item_id,'decision':decision})
        return row

    @bp.post('/access-reviews/<review_id>/complete')
    @require_role('admin')
    def access_review_complete(review_id):
        ident=current_identity()
        try:row=repo().complete_access_review(review_id,ident['organization_id'],ident['user_id'])
        except ValueError as e:return {'error':str(e)},409
        if not row:return {'error':'Open access review not found'},404
        audit('ACCESS_REVIEW_COMPLETED','access_review',review_id,{'revoked_members':row['summary']['revoke']})
        repo().emit_webhook_event(ident['organization_id'],'access_review.completed',{'review_id':review_id,'revoked_members':row['summary']['revoke'],'completed_by':ident['user_id']})
        return row

    # Workspace integrations / signed webhooks
    @bp.get('/integrations/webhooks')
    @require_role('admin')
    def webhook_list():
        return jsonify(repo().list_webhook_endpoints(current_identity()['organization_id']))

    @bp.post('/integrations/webhooks')
    @require_role('admin')
    def webhook_create():
        ident=current_identity();d=request.get_json(force=True) or {}
        name=(d.get('name') or '').strip()[:160];url=(d.get('url') or '').strip()
        events=[x for x in d.get('events',[]) if x in WEBHOOK_EVENTS or x=='*']
        if not name or not url:return {'error':'Name and HTTPS endpoint URL are required'},400
        if not events:return {'error':'Select at least one supported event'},400
        try:
            normalized=validate_target(url,current_app.config['SCANNER_ALLOW_PRIVATE'])
        except TargetValidationError as e:return {'error':str(e)},400
        if not normalized.lower().startswith('https://') and not current_app.config['SCANNER_ALLOW_PRIVATE']:
            return {'error':'Webhook endpoints must use HTTPS'},400
        raw='whsec_'+secrets.token_urlsafe(32)
        try:protected=encrypt_secret(raw,current_app.config.get('APP_ENCRYPTION_KEY'))
        except Exception as e:return {'error':'Webhook secret encryption failed: '+str(e)},500
        row=repo().create_webhook_endpoint(ident['organization_id'],name,normalized,protected,events,ident['user_id'])
        audit('WEBHOOK_CREATED','webhook',row['id'],{'name':name,'url':normalized,'events':events})
        return {**row,'secret':raw},201

    @bp.patch('/integrations/webhooks/<endpoint_id>')
    @require_role('admin')
    def webhook_update(endpoint_id):
        ident=current_identity();d=request.get_json(force=True) or {};updates={}
        if 'name' in d:updates['name']=(d.get('name') or '').strip()[:160]
        if 'active' in d:updates['active']=bool(d.get('active'))
        if 'events' in d:
            events=[x for x in d.get('events',[]) if x in WEBHOOK_EVENTS or x=='*']
            if not events:return {'error':'Select at least one supported event'},400
            updates['events']=events
        if 'url' in d:
            try:normalized=validate_target((d.get('url') or '').strip(),current_app.config['SCANNER_ALLOW_PRIVATE'])
            except TargetValidationError as e:return {'error':str(e)},400
            if not normalized.lower().startswith('https://') and not current_app.config['SCANNER_ALLOW_PRIVATE']:
                return {'error':'Webhook endpoints must use HTTPS'},400
            updates['url']=normalized
        if d.get('rotate_secret'):
            raw='whsec_'+secrets.token_urlsafe(32)
            updates['secret_ciphertext']=encrypt_secret(raw,current_app.config.get('APP_ENCRYPTION_KEY'))
        else:raw=None
        row=repo().update_webhook_endpoint(endpoint_id,ident['organization_id'],updates)
        if not row:return {'error':'Webhook endpoint not found'},404
        audit('WEBHOOK_UPDATED','webhook',endpoint_id,{k:v for k,v in updates.items() if k!='secret_ciphertext'})
        return ({**row,'secret':raw} if raw else row)

    @bp.delete('/integrations/webhooks/<endpoint_id>')
    @require_role('admin')
    def webhook_delete(endpoint_id):
        ident=current_identity()
        try:deleted=repo().delete_webhook_endpoint(endpoint_id,ident['organization_id'])
        except ValueError as e:return {'error':str(e)},409
        if not deleted:return {'error':'Webhook endpoint not found'},404
        audit('WEBHOOK_DELETED','webhook',endpoint_id);return {'ok':True}

    @bp.get('/integrations/webhooks/deliveries')
    @require_role('admin')
    def webhook_deliveries():
        ident=current_identity();return jsonify(repo().list_webhook_deliveries(ident['organization_id'],request.args.get('endpoint_id')))

    @bp.post('/integrations/webhooks/<endpoint_id>/test')
    @require_role('admin')
    def webhook_test(endpoint_id):
        ident=current_identity();endpoint=repo().get_webhook_endpoint(endpoint_id,ident['organization_id'])
        if not endpoint:return {'error':'Webhook endpoint not found'},404
        delivery=repo().create_webhook_delivery(endpoint_id,'webhook.test',{'event':'webhook.test','created_at':repo().now(),'data':{'message':'SentinelScope webhook test','workspace_id':ident['organization_id']}})
        job=repo().enqueue_job('webhook',{'delivery_id':delivery['id']},max_attempts=5)
        audit('WEBHOOK_TEST_QUEUED','webhook',endpoint_id,{'delivery_id':delivery['id']})
        return {'delivery':delivery,'job_id':job['id']},202

    @bp.post('/integrations/webhooks/deliveries/<delivery_id>/retry')
    @require_role('admin')
    def webhook_retry(delivery_id):
        ident=current_identity()
        if not repo().retry_webhook_delivery(delivery_id,ident['organization_id']):return {'error':'Delivery not found'},404
        audit('WEBHOOK_RETRY_QUEUED','webhook_delivery',delivery_id);return {'ok':True},202

    # Personal API keys
    @bp.route('/api-keys',methods=['GET','POST'])
    @require_auth
    def api_keys():
        ident=current_identity()
        if ident.get('auth_method')=='api_key':return {'error':'Manage API keys from an interactive session'},403
        if request.method=='GET':return jsonify(repo().list_api_keys(ident['user_id'],ident['organization_id']))
        d=request.get_json(force=True) or {};name=(d.get('name') or '').strip()
        scopes=[s for s in d.get('scopes',['read']) if s in {'read','scan','write','admin'}]
        if not name or not scopes:return {'error':'Name and at least one valid scope are required'},400
        if 'admin' in scopes and not ident.get('system_admin'):return {'error':'System administrator access is required for admin-scoped keys'},403
        days=int(d.get('expires_in_days') or 90);days=max(1,min(days,365))
        raw='wss_'+secrets.token_urlsafe(36);prefix=raw[:12];expires=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
        row=repo().create_api_key(ident['user_id'],ident['organization_id'],name,token_hash(raw),prefix,scopes,expires)
        audit('API_KEY_CREATED','api_key',row['id'],{'name':name,'scopes':scopes})
        return {**row,'token':raw},201

    @bp.delete('/api-keys/<key_id>')
    @require_auth
    def api_key_revoke(key_id):
        ident=current_identity()
        if ident.get('auth_method')=='api_key':return {'error':'Manage API keys from an interactive session'},403
        if not repo().revoke_api_key(key_id,ident['user_id'],ident['organization_id']):return {'error':'API key not found or already revoked'},404
        audit('API_KEY_REVOKED','api_key',key_id);return {'ok':True}

    @bp.route('/notification-preferences',methods=['GET','PUT'])
    @require_auth
    def notification_preferences():
        ident=current_identity()
        if request.method=='GET':return repo().get_notification_preferences(ident['user_id'],ident['organization_id'])
        d=request.get_json(force=True) or {}
        prefs=repo().set_notification_preferences(ident['user_id'],ident['organization_id'],d)
        audit('NOTIFICATION_PREFERENCES_UPDATED','user',ident['user_id'],prefs);return prefs

    @bp.get('/notifications')
    @require_auth
    def notifications():
        ident=current_identity();return {'summary':repo().notification_counts(ident['organization_id'],ident['user_id']),
                                         'items':repo().list_notifications(ident['organization_id'],ident['user_id'],200)}

    @bp.post('/notifications/<notification_id>/read')
    @require_auth
    def notification_read(notification_id):
        ident=current_identity();repo().mark_notification_read(notification_id,ident['user_id']);return {'ok':True}

    @bp.post('/notifications/read-all')
    @require_auth
    def notifications_read_all():
        ident=current_identity();count=repo().mark_all_notifications_read(ident['organization_id'],ident['user_id'])
        return {'ok':True,'updated':count}

    @bp.route('/backups',methods=['GET','POST'])
    @bp.route('/backups/<path:legacy_path>',methods=['GET','POST'])
    @require_role('owner')
    def workspace_backup_disabled(legacy_path=None):
        return {
            'error':'Raw SQLite backups are platform-wide and require System Administrator access. Use workspace JSON export for tenant-scoped portability.'
        },403

    @bp.get('/export/workspace.json')
    @require_role('owner')
    def export_workspace():
        ident=current_identity()
        payload=repo().export_workspace(ident['organization_id'])
        return Response(json.dumps(payload,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename=sentinelscope-workspace-export.json'})

    @bp.get('/metrics')
    @bp.get('/metrics/prometheus')
    @require_role('admin')
    def workspace_metrics_disabled():
        return {'error':'Platform-wide operational metrics require System Administrator access. Use /api/v1/admin/metrics.'},403

    @bp.get('/audit')
    @require_role('admin')
    def audit_list():
        ident=current_identity();rows=repo().list_audit(ident['organization_id'],min(int(request.args.get('limit',500)),5000))
        q=(request.args.get('q') or '').strip().lower();event=(request.args.get('event') or '').strip()
        if event:rows=[r for r in rows if r.get('event')==event]
        if q:rows=[r for r in rows if q in (' '.join([str(r.get('event') or ''),str(r.get('user_email') or ''),str(r.get('resource_type') or ''),str(r.get('resource_id') or ''),json.dumps(r.get('details') or {})])).lower()]
        return jsonify(rows)

    @bp.get('/audit/export.json')
    @require_role('admin')
    def audit_export():
        ident=current_identity();rows=repo().list_audit(ident['organization_id'],10000)
        return Response(json.dumps({'generated_at':datetime.now(timezone.utc).isoformat(),'events':rows},indent=2),mimetype='application/json',
                        headers={'Content-Disposition':'attachment; filename=sentinelscope-audit.json'})

    return bp
