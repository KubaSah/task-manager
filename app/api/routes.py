from flask import Blueprint, jsonify, request, abort
from flask_login import login_required, current_user
from bleach import clean
from math import ceil

from .. import db, limiter
from ..models import Task, Project, Comment, Membership, ApiToken, User
from ..security.permissions import require_project_membership
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from hashlib import sha256

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
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    q = Task.query.filter(Task.project_id.in_(pids)) if pids else Task.query.filter(False)
    
    text = (request.args.get('q') or '').strip()
    status = request.args.get('status')
    priority = request.args.get('priority')
    project_id = request.args.get('project_id', type=int)
    if text:
        like = f"%{text}%"
        q = q.filter((Task.title.ilike(like)) | (Task.description.ilike(like)))
    if status in ('todo','in_progress','done'):
        q = q.filter(Task.status == status)
    if priority in ('low','medium','high'):
        q = q.filter(Task.priority == priority)
    if project_id and project_id in pids:
        q = q.filter(Task.project_id == project_id)
    q = q.order_by(Task.created_at.desc())
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


@bp.get('/tokens')
@login_required
def list_tokens():
    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(ApiToken.created_at.desc()).all()
    return jsonify([
        {
            'id': t.id,
            'name': t.name,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'last_used_at': t.last_used_at.isoformat() if t.last_used_at else None,
            'revoked': t.revoked,
        } for t in tokens
    ])


@bp.post('/tokens')
@login_required
def create_token():
    import secrets
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip() or None
    raw = secrets.token_urlsafe(32)
    th = sha256(raw.encode('utf-8')).hexdigest()
    t = ApiToken(user_id=current_user.id, name=name, token_hash=th)
    db.session.add(t)
    db.session.commit()
    return jsonify({'token': raw, 'id': t.id}), 201


@bp.delete('/tokens/<int:token_id>')
@login_required
def revoke_token(token_id: int):
    t = db.get_or_404(ApiToken, token_id)
    if t.user_id != current_user.id:
        abort(403)
    t.revoked = True
    db.session.commit()
    return jsonify({'ok': True})


@bp.post('/tasks')
@limiter.limit("30 per minute")
@login_required
def create_task():
    data = _json_required(['title', 'project_id'])
    project = db.session.get(Project, data['project_id'])
    if not project:
        abort(404)
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
    t = db.get_or_404(Task, task_id)
    require_project_membership(t.project_id)
    return jsonify({
        'id': t.id,
        'project_id': t.project_id,
        'title': t.title,
        'description': t.description,
        'status': t.status,
        'priority': t.priority,
        'assignee_id': t.assignee_id,
        'creator_id': t.creator_id,
        'created_at': t.created_at.isoformat() if t.created_at else None,
    })


@bp.patch('/tasks/<int:task_id>')
@limiter.limit("30 per minute")
@login_required
def update_task(task_id: int):
    t = db.get_or_404(Task, task_id)
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
    t = db.get_or_404(Task, task_id)
    require_project_membership(t.project_id)
    data = _json_required(['content'])
    content = clean(str(data['content']), tags=['b','i','em','strong','code'], strip=True)
    c = Comment(task=t, content=content, author=current_user)
    db.session.add(c)
    db.session.commit()
    return jsonify({'comment_id': c.id}), 201