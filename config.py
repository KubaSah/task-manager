import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-change")
    _env = os.environ.get('FLASK_ENV', 'development')
    APP_VERSION = os.environ.get('APP_VERSION', '0.1.0')

    _raw_db_url = os.environ.get("DATABASE_URL")
    if not _raw_db_url and _env != 'testing':
        host = os.environ.get('POSTGRES_HOST')
        dbname = os.environ.get('POSTGRES_DB')
        user = os.environ.get('POSTGRES_USER')
        password = os.environ.get('POSTGRES_PASSWORD')
        port = os.environ.get('POSTGRES_PORT', '5432')
        if all([host, dbname, user, password]):
            _raw_db_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
        else:
            raise RuntimeError(
                "Postgres configuration incomplete. Set DATABASE_URL lub POSTGRES_HOST, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD (opcjonalnie POSTGRES_PORT)."
            )
    if _env == 'testing':
        _raw_db_url = "sqlite:///:memory:"

    if _raw_db_url and _raw_db_url.startswith("postgres://"):
        _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)

    _sslmode = os.environ.get("DATABASE_SSLMODE")
    if _sslmode and _raw_db_url.startswith('postgresql://') and 'sslmode=' not in _raw_db_url:
        connector = '&' if '?' in _raw_db_url else '?'
        _raw_db_url = f"{_raw_db_url}{connector}sslmode={_sslmode}"
    _timeout = os.environ.get("DATABASE_CONNECT_TIMEOUT")
    if _timeout and _raw_db_url.startswith('postgresql://') and 'connect_timeout=' not in _raw_db_url:
        connector = '&' if '?' in _raw_db_url else '?'
        _raw_db_url = f"{_raw_db_url}{connector}connect_timeout={_timeout}"

    SQLALCHEMY_DATABASE_URI = _raw_db_url
    _pool_size = int(os.environ.get('DATABASE_POOL_SIZE', '5'))
    _pool_overflow = int(os.environ.get('DATABASE_POOL_MAX_OVERFLOW', '2'))
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_size": _pool_size,
        "max_overflow": _pool_overflow,
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    WTF_CSRF_ENABLED = True
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    CSP = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'object-src': ["'none'"],
    }
    OAUTH_GOOGLE_CLIENT_ID = os.environ.get("OAUTH_GOOGLE_CLIENT_ID", "")
    OAUTH_GOOGLE_CLIENT_SECRET = os.environ.get("OAUTH_GOOGLE_CLIENT_SECRET", "")
    OAUTH_GITHUB_CLIENT_ID = os.environ.get("OAUTH_GITHUB_CLIENT_ID", "")
    OAUTH_GITHUB_CLIENT_SECRET = os.environ.get("OAUTH_GITHUB_CLIENT_SECRET", "")
    OAUTH_REDIRECT_BASE = os.environ.get("OAUTH_REDIRECT_BASE", "http://localhost:5001")
    OAUTH_GOOGLE_SCOPE = [
        'openid', 'email', 'profile'
    ]
    OAUTH_GITHUB_SCOPE = 'read:user user:email'

class DevelopmentConfig(BaseConfig):
    DEBUG = True

class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    WTF_CSRF_ENABLED = False

class ProductionConfig(BaseConfig):
    SESSION_COOKIE_SECURE = True

config_map = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}


def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    return config_map.get(env, DevelopmentConfig)
