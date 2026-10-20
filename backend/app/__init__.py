def create_app(config_object=None):
    from flask import Flask
    from flask_cors import CORS
    from .config import Config
    from .repository import Repository
    from .api import create_blueprint
    config_object = config_object or Config
    app=Flask(__name__)
    app.config.from_object(config_object)
    origins=app.config.get('CORS_ORIGINS','*')
    if isinstance(origins,str) and ',' in origins: origins=[x.strip() for x in origins.split(',') if x.strip()]
    CORS(app, resources={r"/api/*":{"origins": origins}})
    repo=Repository(app.config["DATABASE_PATH"])
    repo.init_schema()
    app.extensions["repo"]=repo
    app.register_blueprint(create_blueprint(), url_prefix="/api/v1")
    @app.get('/health')
    def health(): return {"status":"ok","service":"web-security-scanner"}
    return app
