from flask import Blueprint, render_template, redirect, url_for, request, flash, Response
from flask_login import login_required, current_user
from ..models import ApiToken, AuditLog, Project, Membership
from .. import db
from hashlib import sha256
import secrets

bp = Blueprint('core', __name__)

@bp.route('/')
def index():
    return render_template('index.html')


@bp.get('/settings/account')
@login_required
def account_page():
    return render_template('core/account.html')

@bp.get('/settings/tokens')
@login_required
def tokens_page():
    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(ApiToken.created_at.desc()).all()
    return render_template('core/tokens.html', tokens=tokens)


@bp.post('/settings/tokens')
@login_required
def create_token_page():
    name = (request.form.get('name') or '').strip() or None
    raw = secrets.token_urlsafe(32)
    th = sha256(raw.encode('utf-8')).hexdigest()
    t = ApiToken(user_id=current_user.id, name=name, token_hash=th)
    db.session.add(t)
    db.session.commit()
    flash(f'Nowy token: {raw} (zapisz go teraz, nie pokażemy go ponownie)', 'info')
    return redirect(url_for('core.tokens_page'))


@bp.post('/settings/tokens/<int:token_id>/revoke')
@login_required
def revoke_token_page(token_id: int):
    t = ApiToken.query.get_or_404(token_id)
    if t.user_id != current_user.id:
        flash('Brak uprawnień', 'danger')
        return redirect(url_for('core.tokens_page'))
    t.revoked = True
    db.session.commit()
    flash('Token unieważniony', 'info')
    return redirect(url_for('core.tokens_page'))


@bp.get('/audit')
@login_required
def audit_page():
    # Ogranicz wgląd do logów związanych z projektami użytkownika lub własnych akcji
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    q = AuditLog.query
    if pids:
        q = q.filter((AuditLog.project_id.in_(pids)) | (AuditLog.actor_id == current_user.id))
    else:
        q = q.filter(AuditLog.actor_id == current_user.id)
    project_id = request.args.get('project', type=int)
    if project_id and (project_id in pids):
        q = q.filter(AuditLog.project_id == project_id)
    page = max(1, int(request.args.get('page', 1)))
    per_page = 50
    logs = q.order_by(AuditLog.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()
    total = q.count()
    pages = (total + per_page - 1) // per_page if total else 1
    # Dla filtra projektów przygotuj listę
    projects = Project.query.filter(Project.id.in_(pids)).all() if pids else []
    return render_template('core/audit.html', logs=logs, projects=projects, page=page, pages=pages, total=total)


@bp.get('/api-explorer')
@login_required
def api_explorer():
    """Widok UI pokazujący dostępne API endpointy i przykładowe odpowiedzi."""
    import json
    from ..models import Task
    # Przykładowe dane dla demonstracji
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    sample_tasks = Task.query.filter(Task.project_id.in_(pids)).limit(5).all() if pids else []
    tasks_json = json.dumps([
        {
            'id': t.id,
            'project_id': t.project_id,
            'title': t.title,
            'status': t.status,
            'priority': t.priority,
            'created_at': t.created_at.isoformat() if t.created_at else None
        } for t in sample_tasks
    ], indent=2, ensure_ascii=False)
    
    endpoints = [
        {'method': 'GET', 'path': '/api/tasks', 'desc': 'Lista zadań (paginacja, filtry: q, status, priority, project_id)'},
        {'method': 'POST', 'path': '/api/tasks', 'desc': 'Utwórz zadanie (title, project_id, description?, priority?)'},
        {'method': 'GET', 'path': '/api/tasks/<id>', 'desc': 'Szczegóły zadania'},
        {'method': 'PATCH', 'path': '/api/tasks/<id>', 'desc': 'Edycja zadania (title?, description?, status?, priority?)'},
        {'method': 'POST', 'path': '/api/tasks/<id>/comments', 'desc': 'Dodaj komentarz'},
        {'method': 'GET', 'path': '/api/tokens', 'desc': 'Lista tokenów API'},
        {'method': 'POST', 'path': '/api/tokens', 'desc': 'Utwórz token (name?)'},
        {'method': 'DELETE', 'path': '/api/tokens/<id>', 'desc': 'Unieważnij token'},
    ]
    return render_template('core/api_explorer.html', endpoints=endpoints, sample_tasks_json=tasks_json)


@bp.get('/audit/export')
@login_required
def audit_export():
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    q = AuditLog.query
    if pids:
        q = q.filter((AuditLog.project_id.in_(pids)) | (AuditLog.actor_id == current_user.id))
    else:
        q = q.filter(AuditLog.actor_id == current_user.id)
    project_id = request.args.get('project', type=int)
    if project_id and (project_id in pids):
        q = q.filter(AuditLog.project_id == project_id)
    logs = q.order_by(AuditLog.created_at.desc()).limit(5000).all()
    def generate():
        yield 'id,created_at,action,entity_type,entity_id,project_id,actor_id,meta\n'
        for e in logs:
            meta = (e.meta or '').replace('\n',' ').replace('\r',' ').replace('"','""')
            line = f'{e.id},{e.created_at},{e.action},{e.entity_type},{e.entity_id or ""},{e.project_id or ""},{e.actor_id or ""},"{meta}"\n'
            yield line
    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=audit.csv'})