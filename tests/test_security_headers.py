from app import create_app
from config import TestingConfig


def test_security_headers_present_on_api():
    app = create_app()
    app.config.from_object(TestingConfig)
    client = app.test_client()
    resp = client.get('/api/health')
    # Basic security headers asserted
    assert resp.headers.get('Content-Security-Policy') is not None
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    # Request ID propagation
    assert resp.headers.get('X-Request-ID') is not None


def test_security_headers_present_on_html():
    app = create_app()
    app.config.from_object(TestingConfig)
    client = app.test_client()
    resp = client.get('/')
    assert resp.status_code in (200, 302)  # 302 if login redirect
    # Headers present as in API
    assert resp.headers.get('Content-Security-Policy') is not None
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
