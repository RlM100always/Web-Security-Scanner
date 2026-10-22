def create_app(config_object=None):
    import re
    import sqlite3
    from flask import Flask, request
    from flask_cors import CORS
    from werkzeug.middleware.proxy_fix import ProxyFix
    from .config import Config
    from .repository import Repository
    from .api import create_blueprint
    from .admin_api import create_admin_blueprint
    from .auth import current_identity

    config_object = config_object or Config
    app=Flask(__name__)
    app.config.from_object(config_object)
    if app.config.get("TRUST_PROXY_HEADERS"):
        hops=max(1,int(app.config.get("TRUST_PROXY_HOPS",1)))
        app.wsgi_app=ProxyFix(app.wsgi_app,x_for=hops,x_proto=hops,x_host=hops,x_port=hops)

    origins=app.config.get('CORS_ORIGINS','')
    if isinstance(origins,str):
        origins=[x.strip() for x in origins.split(',') if x.strip()]
    if not origins:
        raise RuntimeError("CORS_ORIGINS must contain at least one explicit trusted origin")
    if "*" in origins:
        raise RuntimeError("Wildcard CORS origins are not permitted with credentialed SentinelScope sessions")
    CORS(app, resources={r"/api/*":{"origins":origins}}, supports_credentials=True)

    repo=Repository(app.config["DATABASE_PATH"])
    repo.init_schema()
    repo.sync_system_admin_emails(app.config.get("SYSTEM_ADMIN_EMAILS",[]))

    # Optional shared demo access is explicitly read-only and isolated in its own workspace.
    # Never enable it unless a deployment has intentionally configured a demo password.
    if app.config.get("DEMO_LOGIN_ENABLED"):
        demo_email=str(app.config.get("DEMO_LOGIN_EMAIL","")).strip().lower()
        demo_password=str(app.config.get("DEMO_LOGIN_PASSWORD",""))
        if demo_email and len(demo_password)>=16:
            from .crypto import hash_password
            demo_user=repo.get_user_by_email(demo_email)
            demo_user_id=None
            demo_org_id=None
            if not demo_user:
                try:
                    created=repo.create_signup(demo_email,"SentinelScope Demo",hash_password(demo_password),"SentinelScope Demo Workspace")
                    demo_user_id=created["user_id"]
                    demo_org_id=created["organization_id"]
                except sqlite3.IntegrityError:
                    # Multiple Gunicorn workers can boot at once; another worker may win the insert race.
                    demo_user=repo.get_user_by_email(demo_email)
                    if demo_user and demo_user.get("name")=="SentinelScope Demo":
                        demo_user_id=demo_user["id"]
                        memberships=repo.list_memberships_for_user(demo_user_id)
                        if memberships:
                            demo_org_id=memberships[0]["organization_id"]
                    else:
                        raise
            elif demo_user.get("name")=="SentinelScope Demo":
                demo_user_id=demo_user["id"]
                memberships=repo.list_memberships_for_user(demo_user_id)
                if memberships:
                    demo_org_id=memberships[0]["organization_id"]
                with repo.conn() as c:
                    c.execute("update users set password_hash=?,email_verified=1,active=1 where id=?",(hash_password(demo_password),demo_user_id))
                    c.execute("update memberships set role='viewer',active=1 where user_id=?",(demo_user_id,))
            else:
                app.logger.warning("Read-only demo login was not provisioned because its configured email is already in use.")
            if demo_user_id and demo_org_id:
                with repo.conn() as c:
                    c.execute("update users set email_verified=1,active=1 where id=?",(demo_user_id,))
                    c.execute("update memberships set role='viewer',active=1 where user_id=?",(demo_user_id,))
                # Serialise the sample-workspace check/insert: all Gunicorn workers share this SQLite file.
                with repo.conn() as c:
                    c.execute("BEGIN IMMEDIATE")
                    demo_project=c.execute(
                        "select id from projects where organization_id=? and name=? order by created_at limit 1",
                        (demo_org_id,"Demo security workspace")).fetchone()
                    if demo_project:
                        demo_project_id=demo_project["id"]
                    else:
                        demo_project_id=repo._id()
                        c.execute(
                            "insert into projects(id,name,description,organization_id,created_by,created_at,status,tags_json) values(?,?,?,?,?,?,?,?)",
                            (demo_project_id,"Demo security workspace",
                             "Read-only sample workspace for exploring SentinelScope. The example target is not authorised for scanning.",
                             demo_org_id,demo_user_id,repo.now(),"active",'["demo","read-only"]'))
                    demo_target=c.execute(
                        "select id from targets where project_id=? and name=? limit 1",
                        (demo_project_id,"Example domain (demo only)")).fetchone()
                    if not demo_target:
                        c.execute(
                            "insert into targets(id,project_id,url,name,authorized,verified,created_by,created_at,criticality,environment,tags_json) values(?,?,?,?,?,?,?,?,?,?,?)",
                            (repo._id(),demo_project_id,"https://example.com","Example domain (demo only)",
                             0,0,demo_user_id,repo.now(),"medium","test",'["demo","read-only"]'))
        else:
            app.logger.warning("Read-only demo login is enabled but the configured email or password is invalid.")
    app.extensions["repo"]=repo
    app.register_blueprint(create_blueprint(), url_prefix="/api/v1")
    app.register_blueprint(create_admin_blueprint(), url_prefix="/api/v1/admin")

    @app.before_request
    def csrf_guard():
        identity=current_identity() if request.path.startswith("/api/v1/") else None
        if identity and identity.get("auth_method")=="api_key":
            scopes=set(identity.get("api_scopes") or [])
            if request.path.startswith("/api/v1/admin/") and "admin" not in scopes:
                return {"error":"API key admin scope required"},403
            if request.method in {"GET","HEAD"} and not ({"read","admin"} & scopes):
                return {"error":"API key read scope required"},403
            if request.method not in {"GET","HEAD","OPTIONS"}:
                scan_action=request.method=="POST" and (
                    request.path=="/api/v1/scans" or
                    re.fullmatch(r"/api/v1/scans/[^/]+/rerun",request.path) or
                    re.fullmatch(r"/api/v1/finding-states/[^/]+/verify",request.path) or
                    re.fullmatch(r"/api/v1/schedules/[^/]+/run-now",request.path)
                )
                needed="scan" if scan_action else "write"
                if needed not in scopes and "admin" not in scopes:
                    return {"error":f"API key {needed} scope required"},403
        if request.path.startswith("/api/v1/") and not request.path.startswith("/api/v1/admin/"):
            if repo.system_setting("maintenance_mode",False) and request.path not in {
                "/api/v1/auth/login","/api/v1/auth/logout","/api/v1/auth/me","/api/v1/auth/workspace"
            } and not (identity and identity.get("system_admin")):
                return {"error":repo.system_setting("maintenance_message","SentinelScope is under maintenance."),"maintenance":True},503
            if identity and not identity.get("organization_active") and request.path not in {
                "/api/v1/auth/logout","/api/v1/auth/me","/api/v1/auth/workspace"
            } and not identity.get("system_admin"):
                return {"error":"This workspace has been suspended by a system administrator"},423
        if request.path.startswith("/api/v1/") and request.method not in {"GET","HEAD","OPTIONS"}:
            if request.path in {
                "/api/v1/auth/login",
                "/api/v1/auth/signup",
                "/api/v1/auth/forgot-password",
                "/api/v1/auth/reset-password",
                "/api/v1/auth/email-verification/confirm",
                "/api/v1/auth/invitations/accept"
            }:
                return None
            identity=current_identity()
            if identity and identity.get("auth_method")!="api_key":
                supplied=request.headers.get("X-CSRF-Token","")
                if not supplied or supplied != identity.get("csrf_token"):
                    return {"error":"CSRF token missing or invalid"},403

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options","nosniff")
        response.headers.setdefault("Referrer-Policy","no-referrer")
        response.headers.setdefault("X-Frame-Options","DENY")
        response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control","no-store" if request.path.startswith("/api/") else "no-cache")
        return response

    @app.get('/health')
    def health():
        return {"status":"ok","service":"web-security-scanner","database":"sqlite","queue":"sqlite-worker"}

    return app
