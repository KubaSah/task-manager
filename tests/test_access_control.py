from app import create_app, db
from app.models import User, Project, Membership, Task
from config import TestingConfig


def login_as(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True


def seed_two_projects():
    u1 = User(email='a1@example.com', name='A1', provider='github', provider_id='a1')
    u2 = User(email='a2@example.com', name='A2', provider='github', provider_id='a2')
    p1 = Project(name='P1', key='P1', owner=u1)
    p2 = Project(name='P2', key='P2', owner=u2)
    db.session.add_all([u1, u2, p1, p2])
    db.session.flush()
    db.session.add_all([
        Membership(user_id=u1.id, project_id=p1.id, role='owner'),
        Membership(user_id=u2.id, project_id=p2.id, role='owner'),
    ])
    t1 = Task(title='T1', description='X', project_id=p1.id, status='todo', priority='medium', creator_id=u1.id)
    t2 = Task(title='T2', description='Y', project_id=p2.id, status='todo', priority='medium', creator_id=u2.id)
    db.session.add_all([t1, t2])
    db.session.commit()
    return u1, u2, p1, p2, t1, t2


def test_idor_api_cannot_list_other_project_tasks():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        u1, u2, p1, p2, t1, t2 = seed_two_projects()
        client = app.test_client()
        login_as(client, u1)
        r = client.get('/api/tasks')
        assert r.status_code == 200
        items = r.get_json()['items']
        ids = {it['id'] for it in items}
        assert t1.id in ids
        assert t2.id not in ids


def test_idor_api_get_task_forbidden_for_non_member():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        u1, u2, p1, p2, t1, t2 = seed_two_projects()
        client = app.test_client()
        login_as(client, u1)
        r = client.get(f'/api/tasks/{t2.id}')
        assert r.status_code in (403, 404)


def test_idor_html_task_detail_forbidden_for_non_member():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        u1, u2, p1, p2, t1, t2 = seed_two_projects()
        client = app.test_client()
        login_as(client, u1)
        r = client.get(f'/tasks/{t2.id}')
        assert r.status_code in (403, 404)
