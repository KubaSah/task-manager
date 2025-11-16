#!/usr/bin/env python3
"""
Skrypt testowy do debugowania GitHub OAuth callback
Użycie: python test_github_oauth.py
"""
import os
from app import create_app

app = create_app()

with app.app_context():
    print("=" * 60)
    print("GitHub OAuth Configuration Check")
    print("=" * 60)
    
    # Check environment variables
    github_client_id = os.environ.get("OAUTH_GITHUB_CLIENT_ID")
    github_secret = os.environ.get("OAUTH_GITHUB_CLIENT_SECRET")
    redirect_base = os.environ.get("OAUTH_REDIRECT_BASE")
    
    print(f"\n✓ OAUTH_GITHUB_CLIENT_ID: {'SET' if github_client_id else 'NOT SET'}")
    if github_client_id:
        print(f"  Value: {github_client_id[:10]}...{github_client_id[-4:]}")
    
    print(f"✓ OAUTH_GITHUB_CLIENT_SECRET: {'SET' if github_secret else 'NOT SET'}")
    if github_secret:
        print(f"  Value: {github_secret[:4]}...{github_secret[-4:]}")
    
    print(f"✓ OAUTH_REDIRECT_BASE: {redirect_base}")
    
    # Check app config
    print(f"\n✓ App OAUTH_GITHUB_SCOPE: {app.config.get('OAUTH_GITHUB_SCOPE')}")
    
    # Expected callback URL
    expected_callback = f"{redirect_base}/auth/callback/github"
    print(f"\n✓ Expected callback URL: {expected_callback}")
    
    print("\n" + "=" * 60)
    print("GitHub OAuth App Settings Check:")
    print("=" * 60)
    print("\nW ustawieniach GitHub OAuth App sprawdź:")
    print(f"1. Authorization callback URL = {expected_callback}")
    print("2. Application name i description są ustawione")
    print("3. Scope w aplikacji pozwala na 'user:email'")
    print("\nJeśli callback URL się nie zgadza, zaktualizuj w:")
    print("https://github.com/settings/developers")
    print("=" * 60)
