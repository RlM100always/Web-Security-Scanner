from functools import wraps
from flask import request, current_app, g
from .crypto import hash_password, verify_password, token_hash

ROLES = {"owner": 40, "admin": 30, "analyst": 20, "viewer": 10}


def current_identity():
    if hasattr(g, "identity"):
        return g.identity
    auth=request.headers.get("Authorization","")
    if auth.lower().startswith("bearer "):
        bearer=auth.split(None,1)[1].strip()
        identity=current_app.extensions["repo"].api_key_identity(token_hash(bearer)) if bearer else None
        if identity:
            identity["auth_method"]="api_key"
        g.identity=identity
        return g.identity
    session_token=request.cookies.get("wss_session")
    if not session_token:
        g.identity=None
        return None
    identity=current_app.extensions["repo"].session_identity(token_hash(session_token))
    if identity:
        identity["auth_method"]="session"
    g.identity=identity
    return g.identity


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        identity = current_identity()
        if not identity:
            return {"error": "Authentication required"}, 401
        return fn(*args, **kwargs)
    return wrapper


def require_role(min_role="viewer"):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            identity = current_identity()
            if not identity:
                return {"error": "Authentication required"}, 401
            if ROLES.get(identity.get("role", ""), 0) < ROLES[min_role]:
                return {"error": "Insufficient permission"}, 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_system_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        identity=current_identity()
        if not identity:
            return {"error":"Authentication required"},401
        if not identity.get("system_admin"):
            return {"error":"System administrator access required"},403
        return fn(*args, **kwargs)
    return wrapper


def require_scope(scope):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args,**kwargs):
            identity=current_identity()
            if not identity:return {"error":"Authentication required"},401
            if identity.get("auth_method")=="api_key":
                scopes=set(identity.get("api_scopes") or [])
                if scope not in scopes and "admin" not in scopes:
                    return {"error":f"API key scope '{scope}' required"},403
            return fn(*args,**kwargs)
        return wrapper
    return decorator
