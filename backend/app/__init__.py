def create_app(config_object=None):
    from flask import Flask, request
    from flask_cors import CORS
    from .config import Config
    from .repository import Repository
    from .api import create_blueprint
    from .auth import current_identity

    config_object = config_object or Config
    app=Flask(__name__)
    app.config.from_object(config_object)

    origins=app.config.get('CORS_ORIGINS','*')
    if isinstance(origins,str):
        origins=[x.strip() for x in origins.split(',') if x.strip()]
    CORS(app, resources={r"/api/*":{"origins":origins}}, supports_credentials=True)

    repo=Repository(app.config["DATABASE_PATH"])
    repo.init_schema()
    app.extensions["repo"]=repo
    app.register_blueprint(create_blueprint(), url_prefix="/api/v1")

    @app.before_request
    def csrf_guard():
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
            if identity:
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
