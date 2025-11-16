import pytest
import os
from app import create_app, db
from config import TestingConfig


@pytest.fixture(scope='session', autouse=True)
def _set_testing_env():
    """Force testing env for all tests so create_app picks SQLite in-memory DB."""
    os.environ['FLASK_ENV'] = 'testing'


@pytest.fixture()
def app():
    app = create_app()
    app.config.from_object(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
