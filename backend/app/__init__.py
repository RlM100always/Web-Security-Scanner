def create_app(config_object=None):
    import re
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
