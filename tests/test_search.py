from app import db
from app.models import User, Project, Membership, Task
from config import TestingConfig
import pytest


@pytest.fixture()
def app_ctx():
    from app import create_app
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture()
def client(app_ctx):
    return app_ctx.test_client()


def login_as(client, user_id: int):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True


def setup_sample():
    u1 = User(email='u1@example.com', name='U1', provider='github', provider_id='u1')
    u2 = User(email='u2@example.com', name='U2', provider='github', provider_id='u2')
    p1 = Project(name='Alpha Project', key='ALP', owner=u1)
    p2 = Project(name='Beta Project', key='BET', owner=u2)
    db.session.add_all([u1, u2, p1, p2])
    db.session.flush()
    db.session.add_all([
        Membership(user_id=u1.id, project_id=p1.id, role='owner'),
        Membership(user_id=u2.id, project_id=p2.id, role='owner'),
    ])
    t1 = Task(project=p1, title='Alpha task', description='hello world', status='todo', priority='low', created_by=u1, assignee=u1)
    t2 = Task(project=p2, title='Beta task', description='secret', status='todo', priority='low', created_by=u2, assignee=u2)
    db.session.add_all([t1, t2])
    db.session.commit()
    return u1.id, u2.id, p1.id, p2.id, t1.id, t2.id


def test_search_shows_only_accessible(client):
    u1_id, _, p1_id, p2_id, t1_id, t2_id = setup_sample()
    login_as(client, u1_id)

    # Search for 'Project' should include only Alpha Project for u1
    r = client.get('/search?q=Project')
    assert r.status_code in (200, 302)  # login may redirect, but we logged in
    html = r.get_data(as_text=True)
    assert 'Alpha Project' in html
    assert 'Beta Project' not in html

    # Search for 'task' shows only tasks from p1
    r2 = client.get('/search?q=task')
    html2 = r2.get_data(as_text=True)
    assert 'Alpha task' in html2
    assert 'Beta task' not in html2


def test_search_empty_query_ok(client):
    u1_id, *_ = setup_sample()
    login_as(client, u1_id)
    r = client.get('/search')
    assert r.status_code in (200, 302)
