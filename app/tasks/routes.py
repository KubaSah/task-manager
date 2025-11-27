from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from bleach import clean

from .. import db
from ..models import Task, Project, Comment, Membership, User
from ..security.permissions import require_project_membership
from ..security.audit import log_action
from ..forms import TaskForm, CommentForm

bp = Blueprint('tasks', __name__)


@bp.get('/')
@login_required
def list_tasks():
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    q = Task.query.filter(Task.project_id.in_(pids)) if pids else Task.query.filter(False)
    
    text = (request.args.get('q') or '').strip()
    status = request.args.get('status')
    priority = request.args.get('priority')
    project_id = request.args.get('project', type=int)
    if text:
        like = f"%{text}%"
        q = q.filter((Task.title.ilike(like)) | (Task.description.ilike(like)))
    if status in ('todo','in_progress','done'):
        q = q.filter(Task.status == status)
    if priority in ('low','medium','high'):
        q = q.filter(Task.priority == priority)
    if project_id and project_id in pids:
        q = q.filter(Task.project_id == project_id)
    tasks = q.order_by(Task.created_at.desc()).limit(300).all()
    
    projects = Project.query.filter(Project.id.in_(pids)).order_by(Project.name.asc()).all() if pids else []
    return render_template('tasks/list.html', tasks=tasks, projects=projects, selected_project=project_id)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_task():
    form = TaskForm()
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    user_projects = Project.query.filter(Project.id.in_([m.project_id for m in memberships])).all() if memberships else []
    form.project_id.choices = [(p.id, f"{p.key} — {p.name}") for p in user_projects]

    preselected_pid = request.args.get('project', type=int)
    if preselected_pid and not any(p.id == preselected_pid for p in user_projects):
        flash('Nie masz dostępu do wybranego projektu', 'danger')
        return redirect(url_for('tasks.list_tasks'))

    if form.validate_on_submit():
        target_pid = preselected_pid or form.project_id.data
        project = db.session.get(Project, target_pid) if target_pid else None
        if not project:
            flash('Wybierz projekt', 'danger')
            return redirect(url_for('tasks.create_task'))
        require_project_membership(project.id)
        desc = clean(form.description.data or '', tags=['b','i','em','strong','code'], strip=True)
        t = Task(project=project,
                 title=form.title.data.strip(),
                 description=desc,
                 status=form.status.data,
                 priority=form.priority.data,
                 created_by=current_user,
                 assignee=current_user)
        db.session.add(t)
        db.session.commit()
        flash('Zadanie utworzone', 'success')
        return redirect(url_for('tasks.task_detail', task_id=t.id))
    return render_template('tasks/create.html', form=form, preselected_pid=preselected_pid)


@bp.get('/<int:task_id>')
@login_required
def task_detail(task_id: int):
    t = db.get_or_404(Task, task_id)
    require_project_membership(t.project_id)
    memberships = Membership.query.filter_by(project_id=t.project_id).all()
    member_users = User.query.filter(User.id.in_([m.user_id for m in memberships])).all() if memberships else []
    assignee_choices = [(u.id, u.name) for u in member_users]
    comment_form = CommentForm()
    return render_template('tasks/detail.html', task=t, comment_form=comment_form, assignee_choices=assignee_choices)


@bp.post('/<int:task_id>/comment')
@login_required
def add_comment(task_id: int):
    t = db.get_or_404(Task, task_id)
    require_project_membership(t.project_id)
    form = CommentForm()
    if form.validate_on_submit():
        content = clean(form.content.data, tags=['b','i','em','strong','code'], strip=True)
        c = Comment(task=t, content=content, author=current_user)
        db.session.add(c)
        db.session.commit()
        flash('Dodano komentarz', 'success')
    else:
        flash('Błąd walidacji komentarza', 'danger')
    return redirect(url_for('tasks.task_detail', task_id=task_id))


@bp.post('/<int:task_id>/status')
@login_required
def update_status(task_id: int):
    t = db.get_or_404(Task, task_id)
    role = require_project_membership(t.project_id)
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if role == 'viewer':
        if is_ajax:
            return jsonify({'ok': False, 'error': 'forbidden'}), 403
        flash('Brak uprawnień do zmiany statusu', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    new_status = request.form.get('status')
    if new_status not in ('todo','in_progress','done'):
        if is_ajax:
            return jsonify({'ok': False, 'error': 'invalid_status'}), 400
        flash('Niepoprawny status', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    t.status = new_status
    db.session.commit()
    log_action('task.status', 'task', t.id, t.project_id, meta={'status': new_status})
    db.session.commit()
    if is_ajax:
        return jsonify({'ok': True, 'status': new_status})
    flash('Zmieniono status', 'info')
    return redirect(url_for('tasks.task_detail', task_id=task_id))


@bp.post('/<int:task_id>/assignee')
@login_required
def update_assignee(task_id: int):
    t = db.get_or_404(Task, task_id)
    role = require_project_membership(t.project_id)
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if role == 'viewer':
        if is_ajax:
            return jsonify({'ok': False, 'error': 'forbidden'}), 403
        flash('Brak uprawnień do zmiany przypisania', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    new_assignee_id = request.form.get('assignee', type=int)
    if new_assignee_id is None:
        if is_ajax:
            return jsonify({'ok': False, 'error': 'missing_assignee'}), 400
        flash('Brak wskazanego użytkownika', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    # Only allow assignee among project members
    membership = Membership.query.filter_by(project_id=t.project_id, user_id=new_assignee_id).first()
    if not membership:
        if is_ajax:
            return jsonify({'ok': False, 'error': 'not_project_member'}), 400
        flash('Użytkownik nie jest członkiem projektu', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    t.assignee_id = new_assignee_id
    db.session.commit()
    log_action('task.assignee', 'task', t.id, t.project_id, meta={'assignee_id': new_assignee_id})
    db.session.commit()
    if is_ajax:
        return jsonify({'ok': True, 'assignee_id': new_assignee_id})
    flash('Zmieniono przypisanie zadania', 'success')
    return redirect(url_for('tasks.task_detail', task_id=task_id))


@bp.post('/<int:task_id>/delete')
@login_required
def delete_task(task_id: int):
    t = db.get_or_404(Task, task_id)
    role = require_project_membership(t.project_id)
    if role not in ('owner','admin') and t.creator_id != current_user.id:
        flash('Brak uprawnień do usunięcia zadania', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    db.session.delete(t)
    db.session.commit()
    log_action('task.delete', 'task', task_id, t.project_id)
    db.session.commit()
    flash('Usunięto zadanie', 'info')
    return redirect(url_for('tasks.list_tasks'))


@bp.post('/<int:task_id>/comment/<int:comment_id>/delete')
@login_required
def delete_comment(task_id: int, comment_id: int):
    t = db.get_or_404(Task, task_id)
    require_project_membership(t.project_id)
    c = db.get_or_404(Comment, comment_id)
    if c.task_id != t.id:
        flash('Komentarz nie należy do zadania', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    role = require_project_membership(t.project_id)
    if c.author_id != current_user.id and role not in ('owner','admin'):
        flash('Brak uprawnień do usunięcia komentarza', 'danger')
        return redirect(url_for('tasks.task_detail', task_id=task_id))
    db.session.delete(c)
    db.session.commit()
    log_action('comment.delete', 'comment', comment_id, t.project_id)
    db.session.commit()
    flash('Usunięto komentarz', 'info')
    return redirect(url_for('tasks.task_detail', task_id=task_id))