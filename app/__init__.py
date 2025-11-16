import logging
from logging.handlers import RotatingFileHandler
import os
import secrets

from flask import Flask, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

from config import get_config
from hashlib import sha256
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix

# Extensions
csrf = CSRFProtect()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)


def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config())

    # Init extensions
    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)

    # Security headers via Talisman
    # CSP will be set dynamically with nonce in after_request
    Talisman(
        app,
        content_security_policy=False,  # Disable Talisman's CSP, we'll set it manually
        force_https=app.config.get('SESSION_COOKIE_SECURE', False),
        session_cookie_http_only=True,
        frame_options='DENY',
        permissions_policy={
            "geolocation": "()",
            "camera": "()",
            "microphone": "()",
            "payment": "()",
            "usb": "()",
            "interest-cohort": "()",
        },
        referrer_policy='strict-origin-when-cross-origin',
    )

    # Ensure correct URL scheme / remote IP when behind Heroku's reverse proxy
    # This allows url_for(..., _external=True) to generate https links and Talisman force_https to work.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    login_manager.login_view = 'auth.login'
    from .models import User, ApiToken  # imported after app & db setup

    @login_manager.user_loader
    def load_user(user_id: str):
        if not user_id.isdigit():
            return None
        return db.session.get(User, int(user_id))

    @login_manager.request_loader
    def load_user_from_request(req):
        """Stateless bearer token auth for API requests.
        Looks for Authorization: Bearer <token> and returns the associated user without creating a session.
        """
        auth = req.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return None
        token = auth.split(' ', 1)[1].strip()
        if not token:
            return None
        th = sha256(token.encode('utf-8')).hexdigest()
        # Force session to reload from DB (fresh state for revoked tokens)
        db.session.expire_all()
        tok = db.session.execute(
            db.select(ApiToken).filter_by(token_hash=th, revoked=False)
        ).scalar_one_or_none()
        if not tok:
            return None
        user = db.session.get(User, tok.user_id)
        if not user:
            return None
        # Update last_used_at (timezone aware)
        tok.last_used_at = datetime.now(timezone.utc)
        db.session.commit()
        return user

    # Blueprints registration
    from .auth.routes import bp as auth_bp
    from .core.routes import bp as core_bp
    from .projects.routes import bp as projects_bp
    from .tasks.routes import bp as tasks_bp
    from .api.routes import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(core_bp)
    app.register_blueprint(projects_bp, url_prefix='/projects')
    app.register_blueprint(tasks_bp, url_prefix='/tasks')
    app.register_blueprint(api_bp, url_prefix='/api')

    # Import models so Alembic sees metadata
    from . import models  # noqa: F401

    # Logging setup
    setup_logging(app)

    # Request ID for correlation (simple header or generated)
    @app.before_request
    def attach_request_id():
        rid = request.headers.get('X-Request-ID') or os.urandom(8).hex()
        g.request_id = rid
    
    # CSP nonce generation for inline scripts/styles
    @app.before_request
    def generate_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.after_request
    def add_security_headers(resp):
        # Add X-Request-ID
        resp.headers['X-Request-ID'] = getattr(g, 'request_id', '-')
        
        # Add CSP with nonce
        nonce = getattr(g, 'csp_nonce', '')
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
            f"style-src 'self' 'nonce-{nonce}'",
            "img-src 'self' data:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        resp.headers['Content-Security-Policy'] = '; '.join(csp_directives)
        
        return resp

    # Error handlers minimal (expand later)
    @app.errorhandler(400)
    def bad_request(e):
        return ("Bad Request", 400)

    @app.errorhandler(403)
    def forbidden(e):
        app.logger.warning('403 Forbidden')
        return ("Forbidden", 403)

    @app.errorhandler(404)
    def not_found(e):
        app.logger.info('404 Not Found')
        return ("Not Found", 404)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return ("Too Many Requests", 429)

    @app.errorhandler(500)
    def server_error(e):
        return ("Internal Server Error", 500)

    return app


def setup_logging(app):
    log_dir = os.path.join(app.instance_path, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    fmt = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s: %(message)s')
    # On Heroku (DYNO env var) use stdout; filesystem is ephemeral and logs should go to aggregated logging
    if 'DYNO' in os.environ:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(fmt)
        stream_handler.setLevel(logging.INFO)
        app.logger.addHandler(stream_handler)
    else:
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'), maxBytes=1_000_000, backupCount=5
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Logging initialized')
