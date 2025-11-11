from app import create_app, db
from app.models import User, Project, Membership, Task
from config import TestingConfig
import pytest


@pytest.fixture()
def app_ctx():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture()
def client(app_ctx):
    return app_ctx.test_client()


def login_as(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True


def setup_project_with_members():
    owner = User(email='owner@example.com', name='Owner', provider='github', provider_id='o1')
    other = User(email='other@example.com', name='Other', provider='github', provider_id='o2')
    db.session.add_all([owner, other])
    db.session.flush()
    project = Project(name='PermProj', key='PERM', owner=owner)
    db.session.add(project)
    db.session.flush()
    db.session.add(Membership(user_id=owner.id, project_id=project.id, role='owner'))
    db.session.add(Membership(user_id=other.id, project_id=project.id, role='member'))
    db.session.commit()
    return project, owner, other


def test_project_visibility(client):
    project, owner, other = setup_project_with_members()
    login_as(client, owner)
    r = client.get('/projects/')
    assert b'PERM' in r.data
    login_as(client, other)
    r2 = client.get('/projects/')
    assert b'PERM' in r2.data


def test_project_access_control(client):
    project, owner, other = setup_project_with_members()
    login_as(client, other)
    # Member can view detail
    r = client.get(f'/projects/{project.id}')
    assert r.status_code == 200
    # Member cannot delete (requires owner/admin)
    r2 = client.post(f'/projects/{project.id}/delete')
    assert r2.status_code in (403, 302)  # 302 could redirect unauthorized


def test_task_access_control(client):
    project, owner, other = setup_project_with_members()
    task = Task(project=project, title='Secure Task', created_by=owner)
    db.session.add(task)
    db.session.commit()
    login_as(client, other)
    r = client.get(f'/tasks/{task.id}')
    assert r.status_code == 200
    login_as(client, owner)
    r2 = client.post(f'/tasks/{task.id}/status', data={'status': 'in_progress'})
    assert r2.status_code in (302, 200)