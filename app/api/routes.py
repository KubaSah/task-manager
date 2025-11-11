from flask import Blueprint, jsonify, request, abort
from flask_login import login_required, current_user
from bleach import clean
from math import ceil

from .. import db, limiter
from ..models import Task, Project, Comment, Membership
from ..security.permissions import require_project_membership
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

bp = Blueprint('api', __name__)


@bp.get('/health')
def health():
    return jsonify(status='ok')


def _paginate_query(query, page: int, per_page: int):
    total = query.count()
    items = query.offset((page-1)*per_page).limit(per_page).all()
    return items, total, ceil(total / per_page) if per_page else 1


@bp.get('/tasks')
@limiter.limit("5 per minute")
@login_required
def list_tasks():
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 20))))
    # Only tasks from user's projects
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    q = Task.query.filter(Task.project_id.in_(pids)).order_by(Task.created_at.desc()) if pids else Task.query.filter(False)
    items, total, pages = _paginate_query(q, page, per_page)
    return jsonify({
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': pages,
        'items': [
            {
                'id': t.id,
                'project_id': t.project_id,
                'title': t.title,
                'status': t.status,
                'priority': t.priority,
                'created_at': t.created_at.isoformat() if t.created_at else None
            } for t in items
        ]
    })


def _json_required(keys):
    data = request.get_json(silent=True)
    if not data:
        abort(400)
    for k in keys:
        if k not in data:
            abort(400)
    return data


@bp.post('/tasks')
@limiter.limit("30 per minute")
@login_required
def create_task():
    data = _json_required(['title', 'project_id'])
    project = Project.query.get(data['project_id'])
    if not project:
        abort(404)
    # Require membership for the target project
    require_project_membership(project.id)
    title = str(data['title']).strip()
    if not title:
        abort(400)
    desc = clean(str(data.get('description') or ''), tags=['b','i','em','strong','code'], strip=True)
    priority = data.get('priority', 'medium')
    if priority not in ('low','medium','high'):
        abort(400)
    t = Task(project=project, title=title, description=desc, priority=priority, created_by=current_user)
    db.session.add(t)
    db.session.commit()
    return jsonify({'id': t.id}), 201


@bp.get('/tasks/<int:task_id>')
@limiter.limit("60 per minute")
@login_required
def get_task(task_id: int):
    t = Task.query.get_or_404(task_id)
    require_project_membership(t.project_id)
    return jsonify({
        'id': t.id,
        'project_id': t.project_id,
        'title': t.title,
        'description': t.description,
        'status': t.status,
        'priority': t.priority,
        'assignee_id': t.assignee_id,
        'created_by_id': t.created_by_id,
        'created_at': t.created_at.isoformat() if t.created_at else None,
    })


@bp.patch('/tasks/<int:task_id>')
@limiter.limit("30 per minute")
@login_required
def update_task(task_id: int):
    t = Task.query.get_or_404(task_id)
    require_project_membership(t.project_id)
    data = request.get_json(silent=True) or {}
    if 'title' in data:
        title = str(data['title']).strip()
        if not title:
            abort(400)
        t.title = title
    if 'description' in data:
        t.description = clean(str(data['description']), tags=['b','i','em','strong','code'], strip=True)
    if 'status' in data:
        if data['status'] not in ('todo','in_progress','done'):
            abort(400)
        t.status = data['status']
    if 'priority' in data:
        if data['priority'] not in ('low','medium','high'):
            abort(400)
        t.priority = data['priority']
    db.session.commit()
    return jsonify({'ok': True})


@bp.post('/tasks/<int:task_id>/comments')
@limiter.limit("30 per minute")
@login_required
def add_comment(task_id: int):
    t = Task.query.get_or_404(task_id)
    require_project_membership(t.project_id)
    data = _json_required(['content'])
    content = clean(str(data['content']), tags=['b','i','em','strong','code'], strip=True)
    c = Comment(task=t, content=content, author=current_user)
    db.session.add(c)
    db.session.commit()
    return jsonify({'comment_id': c.id}), 201