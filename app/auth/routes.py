import os
import secrets
from urllib.parse import urljoin

from flask import Blueprint, render_template, current_app, redirect, request, session, url_for, abort, flash
from flask_login import login_user, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from .. import db, limiter
from ..models import User, Role, UserIdentity
from .decorators import role_required

oauth = OAuth()

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def init_oauth_clients():
    if 'oauth_inited' in current_app.config:
        return
    oauth.init_app(current_app)
    cfg = current_app.config
    if cfg.get('OAUTH_GOOGLE_CLIENT_ID') and cfg.get('OAUTH_GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=cfg['OAUTH_GOOGLE_CLIENT_ID'],
            client_secret=cfg['OAUTH_GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            authorize_params={'prompt': 'consent'},
            client_kwargs={'scope': ' '.join(cfg['OAUTH_GOOGLE_SCOPE'])}
        )
    if cfg.get('OAUTH_GITHUB_CLIENT_ID') and cfg.get('OAUTH_GITHUB_CLIENT_SECRET'):
        oauth.register(
            name='github',
            client_id=cfg['OAUTH_GITHUB_CLIENT_ID'],
            client_secret=cfg['OAUTH_GITHUB_CLIENT_SECRET'],
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            api_base_url='https://api.github.com/',
            client_kwargs={'scope': cfg['OAUTH_GITHUB_SCOPE']}
        )
    current_app.config['oauth_inited'] = True


@bp.route('/login', methods=['GET'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('core.index'))
    
    google_enabled = bool(current_app.config.get('OAUTH_GOOGLE_CLIENT_ID'))
    github_enabled = bool(current_app.config.get('OAUTH_GITHUB_CLIENT_ID'))
    
    return render_template('auth/login.html', 
                          google_enabled=google_enabled,
                          github_enabled=github_enabled)


def _build_redirect_uri(provider: str) -> str:
    base = current_app.config['OAUTH_REDIRECT_BASE']
    return urljoin(base, url_for('auth.oauth_callback', provider=provider, _external=False))


@bp.get('/login/<provider>')
@limiter.limit("5 per minute")
def oauth_login(provider: str):
    if provider not in ('google', 'github'):
        abort(404)
    client = oauth.create_client(provider)
    if not client:
        abort(503)
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce
    redirect_uri = _build_redirect_uri(provider)
    return client.authorize_redirect(redirect_uri, state=state)


@bp.get('/callback/<provider>')
@limiter.limit("5 per minute")
def oauth_callback(provider: str):
    if provider not in ('google', 'github'):
        abort(404)
    client = oauth.create_client(provider)
    if not client:
        abort(503)
    sent_state = request.args.get('state')
    if not sent_state or sent_state != session.get('oauth_state'):
        abort(403)
    token = client.authorize_access_token()
    if provider == 'google':
        userinfo = client.userinfo()
        email = userinfo.get('email')
        name = userinfo.get('name') or email
        avatar = userinfo.get('picture')
        provider_id = userinfo.get('sub')
    else:
        userinfo = client.get('user').json()
        emails_resp = client.get('user/emails').json()
        primary_email = next((e['email'] for e in emails_resp if e.get('primary')), None)
        email = primary_email or userinfo.get('email') or f"{userinfo.get('login')}@users.noreply.github.com"
        name = userinfo.get('name') or userinfo.get('login')
        avatar = userinfo.get('avatar_url')
        provider_id = str(userinfo.get('id'))

    if not email:
        abort(403)
    identity = UserIdentity.query.filter_by(provider=provider, provider_id=provider_id).first()
    if identity:
        user = identity.user
    else:
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name, avatar_url=avatar, provider=provider, provider_id=provider_id)
            role = Role.query.filter_by(name='user').first()
            if not role:
                role = Role(name='user', description='Standard user')
                db.session.add(role)
            user.roles.append(role)
            db.session.add(user)
            db.session.flush()
        ident = UserIdentity(user=user, provider=provider, provider_id=provider_id)
        db.session.add(ident)
        db.session.commit()
    login_user(user)
    current_app.logger.info(f"auth_login_success user_id={user.id} provider={provider}")
    return redirect(url_for('core.index'))


@bp.get('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        current_app.logger.info(f"auth_logout user_id={current_user.get_id()}")
    session.pop('oauth_state', None)
    session.pop('oauth_nonce', None)
    return redirect(url_for('core.index'))


@bp.get('/debug/oauth-config')
def debug_oauth_config():
    return {
        "oauth_redirect_base": current_app.config.get('OAUTH_REDIRECT_BASE'),
        "google_callback_url": _build_redirect_uri('google'),
        "github_callback_url": _build_redirect_uri('github'),
        "google_client_id": current_app.config.get('OAUTH_GOOGLE_CLIENT_ID', 'NOT SET')[:20] + '...',
        "github_client_id": current_app.config.get('OAUTH_GITHUB_CLIENT_ID', 'NOT SET'),
        "flask_env": current_app.config.get('FLASK_ENV'),
        "session_cookie_secure": current_app.config.get('SESSION_COOKIE_SECURE'),
    }


@bp.get('/admin/roles')
@role_required('admin')
def manage_roles():
    roles = Role.query.all()
    return {"roles": [r.name for r in roles]}