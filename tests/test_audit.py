from app import create_app, db
from app.models import User, Project, Membership, Task, AuditLog
from config import TestingConfig


def login_as(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True


def setup(ctx):
    u = User(email='au@example.com', name='Au', provider='github', provider_id='a1')
    p = Project(name='AuProj', key='AUD', owner=u)
    db.session.add_all([u, p])
    db.session.flush()
    db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
    db.session.commit()
    return u, p


def test_audit_task_status_logged():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        u, p = setup(app)
        t = Task(project=p, title='A', created_by=u)
        db.session.add(t)
        db.session.commit()
        client = app.test_client()
        login_as(client, u)
        r = client.post(f'/tasks/{t.id}/status', data={'status': 'in_progress'})
        assert r.status_code in (302, 200)
        # There should be at least one audit log for task.status
        al = AuditLog.query.filter_by(entity_type='task', entity_id=t.id, action='task.status').first()
        assert al is not None
