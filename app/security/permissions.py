from flask import abort
from flask_login import current_user

from ..models import Membership, Project, Task


def get_project_role(user_id: int, project_id: int) -> str | None:
    m = Membership.query.filter_by(user_id=user_id, project_id=project_id).first()
    return m.role if m else None


def require_project_membership(project_id: int, roles: tuple[str, ...] | None = None):
    if not current_user.is_authenticated:
        abort(403)
    role = get_project_role(current_user.id, project_id)
    if role is None:
        abort(403)
    if roles and role not in roles:
        abort(403)
    return role


def require_task_membership(task_id: int, roles: tuple[str, ...] | None = None):
    from ..models import Task as TaskModel
    t: TaskModel | None = TaskModel.query.get(task_id)
    if not t:
        abort(404)
    return require_project_membership(t.project_id, roles)
