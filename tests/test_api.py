from app import create_app, db
from app.models import User, Project, Membership
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


def test_api_requires_login(client):
    resp = client.get('/api/tasks')
    assert resp.status_code in (302, 401, 403)


def test_create_and_get_task(client):
    # Create user and project
    u = User(email='api@example.com', name='Api User', provider='github', provider_id='u1')
    p = Project(name='API Project', key='API', owner=u)
    db.session.add_all([u, p])
    db.session.flush()
    db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
    db.session.commit()

    login_as(client, u)

    # Create task
    r = client.post('/api/tasks', json={'title': 'Hello', 'project_id': p.id, 'description': '<script>x</script>'})
    assert r.status_code == 201
    tid = r.get_json()['id']

    # Fetch task
    r2 = client.get(f'/api/tasks/{tid}')
    assert r2.status_code == 200
    data = r2.get_json()
    assert data['title'] == 'Hello'
    assert '<script>' not in (data.get('description') or '')