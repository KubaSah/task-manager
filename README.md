# Secure Taskboard (Flask)

Projekt inżynierski: Bezpieczna aplikacja webowa do zarządzania zadaniami (inspirowana JIRA) z mechanizmami ochrony przed wybranymi atakami z OWASP Top 10.

## Wstęp
Aplikacja wykorzystuje Flask (app factory, blueprints) oraz zestaw rozszerzeń zapewniających bezpieczeństwo: CSRF, nagłówki bezpieczeństwa (CSP, HSTS, X-Frame-Options), rate limiting, walidacja danych i sanitizacja treści.

## Uruchomienie (dev)
1. Utwórz i aktywuj wirtualne środowisko
2. `pip install -r requirements.txt`
3. Skopiuj `.env.example` do `.env` i uzupełnij wartości
4. `flask --app run run --debug` lub `python run.py`

## Struktura
```
app/
  auth/       # logowanie (OAuth SSO w trakcie implementacji)
  core/       # strona główna
  projects/   # moduł projektów
  tasks/      # moduł zadań
  api/        # endpointy JSON (zdrowie, później CRUD)
config.py     # konfiguracja środowiskowa
run.py        # punkt wejścia
```

## Mapowanie zabezpieczeń -> OWASP Top 10 (wersja robocza)
| Obszar | Implementacja | OWASP Top 10 2021 | Status |
|--------|---------------|------------------|--------|
| Kontrola dostępu | Flask-Login (planowane role) | A01: Broken Access Control | W toku |
| Walidacja i sanitizacja | WTForms, bleach (jeszcze nie użyte), ORM | A03: Injection | Częściowo |
| Uwierzytelnianie | OAuth 2.0 (Google/GitHub) przez Authlib | A07: Identification & Auth Failures | Plan |
| Zarządzanie sesją | Secure / HttpOnly cookies, limit czasu | A07 | Wstępnie |
| CSRF | Flask-WTF CSRFProtect | A01 / A05 | Wstępnie |
| Nagłówki bezpieczeństwa | Flask-Talisman (CSP, HSTS opcjonalnie) | A05: Security Misconfiguration | Wstępnie |
| Rate limiting | Flask-Limiter | A06: Vulnerable & Outdated Components (indirect), A10: SSRF (redukcja) | Wstępnie |
| Logowanie i monitoring | RotatingFileHandler, request id | A09: Security Logging & Monitoring Failures | Wstępnie |
| Szyfrowanie w transporcie | HSTS (gdy HTTPS) | A02: Cryptographic Failures | Plan |
| Ochrona przed XSS | Jinja autoescape, CSP, bleach (plan) | A03 / A05 | Częściowo |

Szczegóły zostaną rozszerzone po implementacji kolejnych modułów.

## Następne kroki
- Modele danych i migracje
- Integracja OAuth (Google, GitHub) z kontrolą stanu/nonce
- RBAC (role: admin, member)
- Pełne CRUD i API z paginacją
- Testy jednostkowe i bezpieczeństwa

## Licencja
Internal academic project.
