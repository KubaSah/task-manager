from flask import abort
from flask_login import current_user

from ..models import Membership, Project, Task


def get_project_role(user_id: int, project_id: int) -> str | None:
    """
    Zwraca rolę użytkownika w projekcie lub None, jeśli nie jest członkiem.
    
    Args:
        user_id: ID użytkownika
        project_id: ID projektu
    
    Returns:
        Rola ('owner'|'admin'|'member'|'viewer') lub None
    """
    m = Membership.query.filter_by(user_id=user_id, project_id=project_id).first()
    return m.role if m else None


def require_project_membership(project_id: int, roles: tuple[str, ...] | None = None):
    """
    Wymusza członkostwo w projekcie; opcjonalnie wymaga konkretnej roli.
    
    Args:
        project_id: ID projektu do weryfikacji
        roles: Jeśli podane, użytkownik musi mieć jedną z tych ról; None = każda rola OK
    
    Returns:
        Rola użytkownika w projekcie
    
    Raises:
        HTTP 403 jeśli użytkownik nie ma dostępu
    """
    if not current_user.is_authenticated:
        abort(403)
    role = get_project_role(current_user.id, project_id)
    if role is None:
        abort(403)
    if roles and role not in roles:
        abort(403)
    return role


def require_task_membership(task_id: int, roles: tuple[str, ...] | None = None):
    """
    Wymusza członkostwo w projekcie, do którego należy zadanie.
    
    Args:
        task_id: ID zadania
        roles: Opcjonalna lista wymaganych ról
    
    Returns:
        Rola użytkownika w projekcie zadania
    
    Raises:
        HTTP 404 jeśli zadanie nie istnieje, HTTP 403 jeśli brak dostępu
    """
    from ..models import Task as TaskModel
    from .. import db
    t: TaskModel | None = db.session.get(TaskModel, task_id)
    if not t:
        abort(404)
    return require_project_membership(t.project_id, roles)
