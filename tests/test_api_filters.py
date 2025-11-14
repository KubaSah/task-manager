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


def seed_data():
    u = User(email='filter@example.com', name='Filter User', provider='github', provider_id='u2')
    p1 = Project(name='Proj One', key='P1', owner=u)
    p2 = Project(name='Proj Two', key='P2', owner=u)
    db.session.add_all([u, p1, p2])
    db.session.flush()
    db.session.add_all([
        Membership(user_id=u.id, project_id=p1.id, role='owner'),
        Membership(user_id=u.id, project_id=p2.id, role='owner'),
    ])
    # Tasks
    t1 = Task(title='Alpha', description='First task', project_id=p1.id, status='done', priority='high', creator_id=u.id)
    t2 = Task(title='Bravo', description='Second task', project_id=p1.id, status='todo', priority='medium', creator_id=u.id)
    t3 = Task(title='Charlie', description='Third task', project_id=p2.id, status='in_progress', priority='low', creator_id=u.id)
    db.session.add_all([t1, t2, t3])
    db.session.commit()
    return u, p1, p2, t1, t2, t3


def test_filter_by_status(client):
    u, p1, p2, t1, t2, t3 = seed_data()
    login_as(client, u)
    r = client.get('/api/tasks?status=todo')
    assert r.status_code == 200
    data = r.get_json()
    titles = [item['title'] for item in data['items']]
    assert titles == ['Bravo']


def test_filter_by_priority(client):
    u, p1, p2, t1, t2, t3 = seed_data()
    login_as(client, u)
    r = client.get('/api/tasks?priority=high')
    assert r.status_code == 200
    data = r.get_json()
    titles = [item['title'] for item in data['items']]
    assert titles == ['Alpha']


def test_filter_by_project_id(client):
    u, p1, p2, t1, t2, t3 = seed_data()
    login_as(client, u)
    r = client.get(f'/api/tasks?project_id={p2.id}')
    assert r.status_code == 200
    data = r.get_json()
    titles = [item['title'] for item in data['items']]
    assert titles == ['Charlie']


def test_filter_by_query_text(client):
    u, p1, p2, t1, t2, t3 = seed_data()
    login_as(client, u)
    # Query matches title 'Alpha'
    r = client.get('/api/tasks?q=alp')
    assert r.status_code == 200
    data = r.get_json()
    titles = [item['title'] for item in data['items']]
    assert titles == ['Alpha']
