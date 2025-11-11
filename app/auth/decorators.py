from functools import wraps
from flask import abort
from flask_login import current_user


def role_required(*roles):
    """Require that the current user has at least one of the given global roles.
    Usage: @role_required('admin')
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)
            user_role_names = {r.name for r in current_user.roles}
            if not user_role_names.intersection(roles):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator