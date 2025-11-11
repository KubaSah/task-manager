from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from bleach import clean

from .. import db
from ..models import Project, Membership
from ..security.permissions import require_project_membership
from ..forms import ProjectForm
 

bp = Blueprint('projects', __name__)


@bp.get('/')
@login_required
def list_projects():
    # Show only projects where user has membership
    memberships = Membership.query.filter_by(user_id=current_user.id).all()
    project_ids = [m.project_id for m in memberships]
    projects = Project.query.filter(Project.id.in_(project_ids)).order_by(Project.created_at.desc()).all() if project_ids else []
    roles_by_project = {m.project_id: m.role for m in memberships}
    return render_template('projects/list.html', projects=projects, roles_by_project=roles_by_project)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_project():
    form = ProjectForm()
    if form.validate_on_submit():
        # basic sanitization
        description = clean(form.description.data or '', tags=[], strip=True)
        p = Project(name=form.name.data.strip(), key=form.key.data.strip(), description=description, owner=current_user)
        db.session.add(p)
        db.session.flush()
        # Add membership as owner
        owner_membership = Membership(user_id=current_user.id, project_id=p.id, role='owner')
        db.session.add(owner_membership)
        db.session.commit()
        flash('Projekt utworzony', 'success')
        return redirect(url_for('projects.list_projects'))
    return render_template('projects/create.html', form=form)


@bp.route('/<int:project_id>')
@login_required
def project_detail(project_id: int):
    p = Project.query.get_or_404(project_id)
    role = require_project_membership(project_id)
    return render_template('projects/detail.html', project=p, role=role)


@bp.route('/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id: int):
    p = Project.query.get_or_404(project_id)
    # Require owner or admin (project-level)
    _ = require_project_membership(project_id, roles=('owner','admin'))
    db.session.delete(p)
    db.session.commit()
    flash('Projekt usunięty', 'info')
    return redirect(url_for('projects.list_projects'))