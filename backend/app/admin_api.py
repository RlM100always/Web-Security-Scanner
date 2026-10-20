import json
import os
import platform
import sys
from flask import Blueprint,current_app,request,jsonify,Response,send_file
from .auth import current_identity,require_system_admin
from .mailer import send_email
from .backup import create_sqlite_backup
from .metrics import snapshot,prometheus

def create_admin_blueprint():
    bp=Blueprint("admin_api",__name__)

    def repo(): return current_app.extensions["repo"]

    def ip_addr():
        if current_app.config.get("TRUST_PROXY_HEADERS"):
            return (request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.remote_addr or "")
        return request.remote_addr or ""

    def audit(event,resource_type=None,resource_id=None,details=None):
        ident=current_identity()
        repo().audit(None,ident["user_id"],event,resource_type,resource_id,details or {},ip_addr())

    @bp.get("/overview")
    @require_system_admin
    def overview():
        data=repo().admin_overview()
        data["runtime"]=snapshot(repo())
        data["workers"]=repo().admin_list_workers()
        data["settings"]=repo().get_system_settings()
        data["smtp"]={
            "configured":bool(current_app.config.get("SMTP_HOST")),
            "host":current_app.config.get("SMTP_HOST") or None,
            "port":current_app.config.get("SMTP_PORT"),
            "tls":bool(current_app.config.get("SMTP_USE_TLS")),
            "from":current_app.config.get("EMAIL_FROM"),
        }
        data["system"]={
            "python":sys.version.split()[0],
            "platform":platform.platform(),
            "database":"SQLite WAL",
            "database_path":os.path.basename(repo().path),
            "secret_encryption":"FERNET" if current_app.config.get("APP_ENCRYPTION_KEY") else "DEVELOPMENT_PLAINTEXT_FALLBACK",
        }
        return data

    @bp.get("/users")
    @require_system_admin
    def users():
        return jsonify(repo().admin_list_users(min(int(request.args.get("limit",500)),1000)))

    @bp.patch("/users/<user_id>")
    @require_system_admin
    def user_update(user_id):
        ident=current_identity();d=request.get_json(force=True) or {};target=repo().get_user_by_id(user_id)
        if not target:return {"error":"User not found"},404
        changed={}
        if "active" in d:
            active=bool(d["active"])
            if user_id==ident["user_id"] and not active:return {"error":"You cannot deactivate your own system-admin session"},400
            repo().admin_set_user_active(user_id,active);changed["active"]=active
        if "system_admin" in d:
            enabled=bool(d["system_admin"])
            if target.get("system_admin") and not enabled and repo().system_admin_count()<=1:
                return {"error":"At least one active system administrator must remain"},400
            repo().set_system_admin(user_id,enabled);changed["system_admin"]=enabled
        audit("SYSTEM_USER_UPDATED","user",user_id,changed)
        return {"ok":True,**changed}

    @bp.get("/organizations")
    @require_system_admin
    def organizations():
        return jsonify(repo().admin_list_organizations(min(int(request.args.get("limit",500)),1000)))

    @bp.patch("/organizations/<org_id>")
    @require_system_admin
    def organization_update(org_id):
        d=request.get_json(force=True) or {}
        if "active" not in d:return {"error":"active is required"},400
        active=bool(d["active"])
        if not repo().admin_set_organization_active(org_id,active):return {"error":"Workspace not found"},404
        audit("SYSTEM_WORKSPACE_UPDATED","organization",org_id,{"active":active})
        return {"ok":True,"active":active}

    @bp.get("/scans")
    @require_system_admin
    def scans():
        return jsonify(repo().admin_list_scans(min(int(request.args.get("limit",500)),1000)))

    @bp.post("/scans/<scan_id>/cancel")
    @require_system_admin
    def scan_cancel(scan_id):
        if not repo().request_scan_cancel(scan_id):return {"error":"Only queued or running scans can be cancelled"},409
        audit("SYSTEM_SCAN_CANCEL_REQUESTED","scan",scan_id)
        return {"ok":True}

    @bp.get("/jobs")
    @require_system_admin
    def jobs():
        return jsonify(repo().admin_list_jobs(min(int(request.args.get("limit",500)),1000)))

    @bp.post("/jobs/<job_id>/retry")
    @require_system_admin
    def job_retry(job_id):
        if not repo().admin_retry_job(job_id):return {"error":"Only failed or cancelled jobs can be retried"},409
        audit("SYSTEM_JOB_RETRIED","job",job_id);return {"ok":True}

    @bp.post("/jobs/<job_id>/cancel")
    @require_system_admin
    def job_cancel(job_id):
        if not repo().admin_cancel_job(job_id):return {"error":"Only queued jobs can be cancelled"},409
        audit("SYSTEM_JOB_CANCELLED","job",job_id);return {"ok":True}

    @bp.post("/jobs/recover-stale")
    @require_system_admin
    def jobs_recover_stale():
        d=request.get_json(silent=True) or {};minutes=max(1,min(int(d.get("stale_minutes",10)),1440))
        result=repo().recover_stale_jobs(minutes)
        audit("SYSTEM_STALE_JOBS_RECOVERED","job",None,{"stale_minutes":minutes,**{k:len(v) if isinstance(v,list) else v for k,v in result.items()}})
        return {"ok":True,**result}

    @bp.delete("/jobs/completed")
    @require_system_admin
    def jobs_purge():
        removed=repo().admin_purge_jobs();audit("SYSTEM_JOBS_PURGED","job",None,{"removed":removed})
        return {"ok":True,"removed":removed}

    @bp.get("/workers")
    @require_system_admin
    def workers():
        return jsonify(repo().admin_list_workers())

    @bp.get("/security-events")
    @require_system_admin
    def security_events():
        return repo().admin_security_events(min(int(request.args.get("limit",300)),1000))

    @bp.get("/audit")
    @require_system_admin
    def audit_log():
        return jsonify(repo().admin_list_audit(min(int(request.args.get("limit",1000)),5000)))

    @bp.get("/settings")
    @require_system_admin
    def settings():
        return repo().get_system_settings()

    @bp.put("/settings")
    @require_system_admin
    def settings_update():
        ident=current_identity();d=request.get_json(force=True) or {}
        updates=d.get("settings") if isinstance(d.get("settings"),dict) else d
        if not updates:return {"error":"No settings supplied"},400
        applied={}
        try:
            for key,value in updates.items():
                repo().set_system_setting(key,value,ident["user_id"]);applied[key]=value
        except ValueError as e:return {"error":str(e)},400
        audit("SYSTEM_SETTINGS_UPDATED","settings",None,applied)
        return {"ok":True,"settings":repo().get_system_settings()}

    @bp.post("/broadcast")
    @require_system_admin
    def broadcast():
        ident=current_identity();d=request.get_json(force=True) or {}
        title=(d.get("title") or "").strip();body=(d.get("body") or "").strip();org_id=d.get("organization_id")
        if not title or not body:return {"error":"Title and body are required"},400
        nid=repo().add_notification(org_id,None,"system_broadcast",title,body,{"sent_by":ident["user_id"]})
        audit("SYSTEM_BROADCAST_SENT","notification",nid,{"organization_id":org_id,"title":title})
        return {"ok":True,"notification_id":nid},201

    @bp.post("/email-test")
    @require_system_admin
    def email_test():
        d=request.get_json(force=True) or {};email=(d.get("email") or current_identity()["email"]).strip()
        if not current_app.config.get("SMTP_HOST"):return {"error":"SMTP is not configured"},400
        try:result=send_email(current_app.config,email,"SentinelScope SMTP test","Your SentinelScope SMTP configuration is working.")
        except Exception as e:return {"error":str(e)},502
        audit("SYSTEM_SMTP_TEST","email",email,{"delivered":result.get("delivered")})
        return {"ok":True,**result}

    @bp.get("/backups")
    @require_system_admin
    def backups():
        return jsonify(repo().admin_list_backups())

    @bp.post("/backups")
    @require_system_admin
    def backup_create():
        ident=current_identity();path,size=create_sqlite_backup(repo().path,current_app.config["BACKUP_DIR"])
        repo().record_backup(None,ident["user_id"],os.path.basename(path),size)
        audit("SYSTEM_BACKUP_CREATED","backup",os.path.basename(path),{"size_bytes":size})
        return {"filename":os.path.basename(path),"size_bytes":size},201

    @bp.get("/backups/<filename>")
    @require_system_admin
    def backup_download(filename):
        safe=os.path.basename(filename);path=os.path.join(current_app.config["BACKUP_DIR"],safe)
        if not os.path.exists(path):return {"error":"Backup not found"},404
        return send_file(path,as_attachment=True,download_name=safe)

    @bp.post("/retention/run")
    @require_system_admin
    def retention_run():
        days=max(1,int(repo().system_setting("scan_retention_days",90)))
        removed=repo().purge_retention(days)
        audit("SYSTEM_RETENTION_RUN","scan",None,{"days":days,"removed_scans":removed})
        return {"ok":True,"days":days,"removed_scans":removed}

    @bp.get("/metrics")
    @require_system_admin
    def metrics_json():
        return snapshot(repo())

    @bp.get("/metrics/prometheus")
    @require_system_admin
    def metrics_text():
        return Response(prometheus(repo()),mimetype="text/plain")

    return bp
