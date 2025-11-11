from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from bleach import clean

from .. import db
from ..models import Task, Project, Comment, Membership
from ..security.permissions import require_project_membership
from ..forms import TaskForm, CommentForm

bp = Blueprint('tasks', __name__)


@bp.get('/')
@login_required
def list_tasks():
    # Only tasks from user's projects
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    pids = [m.project_id for m in memberships]
    tasks = Task.query.filter(Task.project_id.in_(pids)).order_by(Task.created_at.desc()).limit(100).all() if pids else []
    return render_template('tasks/list.html', tasks=tasks)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_task():
    form = TaskForm()
    if form.validate_on_submit():
        project_id = request.args.get('project')
        project = Project.query.get(project_id) if project_id else None
        if not project:
            flash('Brak poprawnego projektu', 'danger')
            return redirect(url_for('tasks.list_tasks'))
        # Require membership for the target project
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
    return render_template('tasks/create.html', form=form)


@bp.get('/<int:task_id>')
@login_required
def task_detail(task_id: int):
    t = Task.query.get_or_404(task_id)
    require_project_membership(t.project_id)
    comment_form = CommentForm()
    return render_template('tasks/detail.html', task=t, comment_form=comment_form)


@bp.post('/<int:task_id>/comment')
@login_required
def add_comment(task_id: int):
    t = Task.query.get_or_404(task_id)
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
    t = Task.query.get_or_404(task_id)
    require_project_membership(t.project_id)
    new_status = request.form.get('status')
    if new_status not in ('todo','in_progress','done'):
        flash('Niepoprawny status', 'danger')
    else:
        t.status = new_status
        db.session.commit()
        flash('Zmieniono status', 'info')
    return redirect(url_for('tasks.task_detail', task_id=task_id))