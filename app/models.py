from datetime import datetime, timezone
from typing import Optional

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import CheckConstraint, UniqueConstraint, Index
from sqlalchemy.orm import validates

from . import db


def now_utc():
    return datetime.now(timezone.utc)


user_roles = db.Table(
    'user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    db.UniqueConstraint('user_id', 'role_id', name='uq_user_role')
)


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    avatar_url: Optional[str] = db.Column(db.String(512))
    provider = db.Column(db.String(50), nullable=False)
    provider_id = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255))
    
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False, server_default='0')
    account_locked_until = db.Column(db.DateTime)
    last_failed_login = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)
    updated_at = db.Column(db.DateTime, default=now_utc, onupdate=now_utc, nullable=False)

    roles = db.relationship('Role', secondary=user_roles, backref='users', lazy='dynamic')
    memberships = db.relationship('Membership', back_populates='user', cascade='all, delete-orphan')
    identities = db.relationship('UserIdentity', back_populates='user', cascade='all, delete-orphan')

    __table_args__ = (
        UniqueConstraint('provider', 'provider_id', name='uq_provider_identity'),
    )

    def get_id(self):
        return str(self.id)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class UserIdentity(db.Model):
    __tablename__ = 'user_identities'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    provider_id = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)

    user = db.relationship('User', back_populates='identities')

    __table_args__ = (
        UniqueConstraint('provider', 'provider_id', name='uq_identity_provider_id'),
        Index('ix_identity_user_provider', 'user_id', 'provider'),
    )


class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    key = db.Column(db.String(20), nullable=False, unique=True)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))

    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)
    updated_at = db.Column(db.DateTime, default=now_utc, onupdate=now_utc, nullable=False)

    owner = db.relationship('User', foreign_keys=[owner_id])
    tasks = db.relationship('Task', back_populates='project', cascade='all, delete-orphan')
    memberships = db.relationship('Membership', back_populates='project', cascade='all, delete-orphan')

    __table_args__ = (
        Index('ix_project_key', 'key'),
    )


class Membership(db.Model):
    __tablename__ = 'memberships'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')  # 'owner' | 'admin' | 'member' | 'viewer'

    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)

    user = db.relationship('User', back_populates='memberships')
    project = db.relationship('Project', back_populates='memberships')

    __table_args__ = (
        UniqueConstraint('user_id', 'project_id', name='uq_user_project'),
        CheckConstraint("role in ('owner','admin','member','viewer')", name='ck_membership_role'),
    )


class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False, default='todo')
    priority = db.Column(db.String(10), nullable=False, default='medium')

    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    creator_id = db.Column('created_by_id', db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))

    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)
    updated_at = db.Column(db.DateTime, default=now_utc, onupdate=now_utc, nullable=False)

    project = db.relationship('Project', back_populates='tasks')
    assignee = db.relationship('User', foreign_keys=[assignee_id])
    created_by = db.relationship('User', foreign_keys=[creator_id])
    comments = db.relationship('Comment', back_populates='task', cascade='all, delete-orphan')

    __table_args__ = (
        CheckConstraint("status in ('todo','in_progress','done')", name='ck_task_status'),
        CheckConstraint("priority in ('low','medium','high')", name='ck_task_priority'),
        Index('ix_task_project_status', 'project_id', 'status'),
    )

    @validates('title')
    def validate_title(self, key, value):
        if not value or not value.strip():
            raise ValueError('Title cannot be empty')
        return value.strip()


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    content = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)
    updated_at = db.Column(db.DateTime, default=now_utc, onupdate=now_utc, nullable=False)

    task = db.relationship('Task', back_populates='comments')
    author = db.relationship('User')


class ApiToken(db.Model):
    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(120))
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)
    last_used_at = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User')


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='SET NULL'))
    meta = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=now_utc, nullable=False)

    actor = db.relationship('User', foreign_keys=[actor_id])
    project = db.relationship('Project', foreign_keys=[project_id])