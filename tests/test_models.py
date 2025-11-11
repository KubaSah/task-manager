from app import db, create_app
from app.models import User, Project, Task
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


def test_user_creation(app_ctx):
    u = User(email="test@example.com", name="Test", provider="github", provider_id="123")
    db.session.add(u)
    db.session.commit()
    assert u.id is not None
    assert User.query.filter_by(email="test@example.com").count() == 1


def test_task_constraints(app_ctx):
    u = User(email="x@example.com", name="X", provider="google", provider_id="999")
    p = Project(name="Project One", key="PRJ1", owner=u)
    db.session.add_all([u, p])
    db.session.commit()

    t = Task(project=p, title="Sample Task", created_by=u)
    db.session.add(t)
    db.session.commit()
    assert t.status == 'todo'
    assert t.priority == 'medium'

    # Status constraint enforcement
    t.status = 'in_progress'
    db.session.commit()
    assert t.status == 'in_progress'
