from app import create_app, db
from app.models import User, Project, Membership, ApiToken
from config import TestingConfig
from hashlib import sha256


def login_as(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True


def test_create_and_use_bearer_token():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        u = User(email='tok@example.com', name='Tok', provider='github', provider_id='t1')
        p = Project(name='TokProj', key='TOK', owner=u)
        db.session.add_all([u, p])
        db.session.flush()
        db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
        db.session.commit()
        client = app.test_client()
        login_as(client, u)
        # Create token via API
        r = client.post('/api/tokens', json={'name': 'ci'})
        assert r.status_code == 201
        raw = r.get_json()['token']
        assert raw
        # Use token to access API without session
        client2 = app.test_client()
        r2 = client2.get('/api/tasks', headers={'Authorization': f'Bearer {raw}'})
        assert r2.status_code in (200, 204, 200)
        # Revoke and ensure no longer works
        # find token id
        toks = ApiToken.query.filter_by(user_id=u.id).all()
        assert toks
        tid = toks[0].id
        rev = client.delete(f'/api/tokens/{tid}')
        assert rev.status_code == 200
        r3 = client2.get('/api/tasks', headers={'Authorization': f'Bearer {raw}'})
        assert r3.status_code in (302, 401, 403) or r3.status_code == 429
