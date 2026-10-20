from functools import wraps
from flask import request, current_app, g
from .crypto import hash_password, verify_password, token_hash

ROLES = {"owner": 40, "admin": 30, "analyst": 20, "viewer": 10}


def current_identity():
    if hasattr(g, "identity"):
        return g.identity
    token = request.cookies.get("wss_session")
    auth = request.headers.get("Authorization", "")
    if not token and auth.lower().startswith("bearer "):
        token = auth.split(None, 1)[1].strip()
    if not token:
        g.identity = None
        return None
    g.identity = current_app.extensions["repo"].session_identity(token_hash(token))
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
