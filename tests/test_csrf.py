from app import create_app, db
from config import TestingConfig
from app.models import User, Project, Membership


def test_csrf_reject_without_token_on_project_create():
    app = create_app()
    app.config.from_object(TestingConfig)
    # Enable CSRF explicitly for this test case
    app.config['WTF_CSRF_ENABLED'] = True
    with app.app_context():
        db.create_all()
        u = User(email='csrf@example.com', name='CSRF', provider='github', provider_id='c1')
        db.session.add(u)
        db.session.commit()
    client = app.test_client()
    # Log in manually
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'
        sess['_fresh'] = True
    # Missing CSRF token in form post
    resp = client.post('/projects/create', data={'name': 'X', 'key': 'CSRF', 'description': 'Test'})
    # Expect 400 or 403 depending on CSRF failure handler
    assert resp.status_code in (400, 403)


def test_csrf_accept_with_token_on_project_create():
    app = create_app()
    app.config.from_object(TestingConfig)
    # Enable CSRF explicitly for this test case
    app.config['WTF_CSRF_ENABLED'] = True
    with app.app_context():
        db.create_all()
        u = User(email='csrf2@example.com', name='CSRF2', provider='github', provider_id='c2')
        db.session.add(u)
        db.session.commit()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'
        sess['_fresh'] = True
    # First GET to retrieve CSRF token embedded in form
    get_resp = client.get('/projects/create')
    assert get_resp.status_code == 200
    # Extract token (simple parse)
    import re
    m = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', get_resp.get_data(as_text=True))
    assert m, 'CSRF token not found in form'
    token = m.group(1)
    post_resp = client.post('/projects/create', data={'csrf_token': token, 'name': 'Ok', 'key': 'OK1', 'description': 'Desc'})
    assert post_resp.status_code in (302, 200)