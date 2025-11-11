from app import create_app, db
from app.models import User, Project, Membership
from config import TestingConfig


def test_rate_limit_applies_on_api_list():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.drop_all()
        db.create_all()
        u = User(email='rl@example.com', name='RL', provider='github', provider_id='r1')
        p = Project(name='RL Project', key='RLP', owner=u)
        db.session.add_all([u, p])
        db.session.flush()
        db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
        db.session.commit()
        uid = u.id
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(uid)
        sess['_fresh'] = True

    # Make 6 requests where limit is 5/minute
    statuses = []
    for _ in range(6):
        r = client.get('/api/tasks')
        statuses.append(r.status_code)
    assert statuses[-1] == 429
