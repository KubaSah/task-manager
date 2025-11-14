from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from bleach import clean

from .. import db
from ..models import Project, Membership, User
from ..security.permissions import require_project_membership
from ..security.audit import log_action
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
        log_action('project.create', 'project', p.id, p.id)
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
    log_action('project.delete', 'project', project_id, project_id)
    db.session.commit()
    flash('Projekt usunięty', 'info')
    return redirect(url_for('projects.list_projects'))


@bp.get('/<int:project_id>/members')
@login_required
def project_members(project_id: int):
    p = Project.query.get_or_404(project_id)
    role = require_project_membership(project_id)
    memberships = Membership.query.filter_by(project_id=project_id).all()
    can_manage = role in ('owner', 'admin')
    return render_template('projects/members.html', project=p, memberships=memberships, can_manage=can_manage, role=role)


@bp.post('/<int:project_id>/members/add')
@login_required
def add_member(project_id: int):
    _ = require_project_membership(project_id, roles=('owner', 'admin'))
    email = (request.form.get('email') or '').strip().lower()
    role = (request.form.get('role') or 'member').strip()
    if role not in ('admin', 'member', 'viewer'):
        role = 'member'
    if not email:
        flash('Podaj email użytkownika', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Użytkownik o podanym email nie istnieje', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    existing = Membership.query.filter_by(user_id=user.id, project_id=project_id).first()
    if existing:
        flash('Użytkownik jest już członkiem projektu', 'info')
        return redirect(url_for('projects.project_members', project_id=project_id))
    m = Membership(user_id=user.id, project_id=project_id, role=role)
    db.session.add(m)
    db.session.commit()
    log_action('project.member.add', 'membership', m.id, project_id, meta={'user_id': user.id, 'role': role})
    db.session.commit()
    flash('Dodano członka projektu', 'success')
    return redirect(url_for('projects.project_members', project_id=project_id))


@bp.post('/<int:project_id>/members/<int:membership_id>/role')
@login_required
def change_member_role(project_id: int, membership_id: int):
    _ = require_project_membership(project_id, roles=('owner', 'admin'))
    m = Membership.query.get_or_404(membership_id)
    if m.project_id != project_id:
        flash('Nieprawidłowy projekt', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    new_role = (request.form.get('role') or '').strip()
    if m.role == 'owner':
        flash('Nie można zmienić roli właściciela (transfer własności wkrótce)', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    if new_role not in ('admin', 'member', 'viewer'):
        flash('Nieprawidłowa rola', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    m.role = new_role
    db.session.commit()
    log_action('project.member.role_change', 'membership', m.id, project_id, meta={'new_role': new_role, 'user_id': m.user_id})
    db.session.commit()
    flash('Zmieniono rolę', 'success')
    return redirect(url_for('projects.project_members', project_id=project_id))


@bp.post('/<int:project_id>/members/<int:membership_id>/remove')
@login_required
def remove_member(project_id: int, membership_id: int):
    _ = require_project_membership(project_id, roles=('owner', 'admin'))
    m = Membership.query.get_or_404(membership_id)
    if m.project_id != project_id:
        flash('Nieprawidłowy projekt', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    if m.role == 'owner':
        flash('Nie można usunąć właściciela projektu', 'danger')
        return redirect(url_for('projects.project_members', project_id=project_id))
    db.session.delete(m)
    db.session.commit()
    log_action('project.member.remove', 'membership', membership_id, project_id, meta={'user_id': m.user_id})
    db.session.commit()
    flash('Usunięto członka projektu', 'info')
    return redirect(url_for('projects.project_members', project_id=project_id))