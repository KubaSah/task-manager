# Secure Taskboard (Flask)

Projekt inżynierski: Bezpieczna aplikacja webowa do zarządzania zadaniami (inspirowana JIRA) z mechanizmami ochrony przed wybranymi atakami z OWASP Top 10.

## Wstęp
Aplikacja wykorzystuje Flask (app factory, blueprints) oraz zestaw rozszerzeń zapewniających bezpieczeństwo: CSRF, nagłówki bezpieczeństwa (CSP, HSTS, X-Frame-Options), rate limiting, walidacja danych i sanitizacja treści.

## Uruchomienie (dev)
1. Utwórz i aktywuj wirtualne środowisko
2. `pip install -r requirements.txt`
3. Skopiuj `.env.example` do `.env` i uzupełnij wartości (OAuth klucze opcjonalne)
4. Zainicjuj DB: `flask db upgrade`
5. Start: `flask --app run run --debug` lub `python run.py`

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
| Kontrola dostępu | Flask-Login, role projektowe (owner/admin/member/viewer) | A01: Broken Access Control | W toku |
| Walidacja i sanitizacja | WTForms, bleach (opis/komentarze), ORM | A03: Injection | Częściowo |
| Uwierzytelnianie | OAuth 2.0 (Google/GitHub) przez Authlib, multi-provider linking | A07: Identification & Auth Failures | W toku |
| Zarządzanie sesją | Secure / HttpOnly cookies, limit czasu | A07 | Wstępnie |
| CSRF | Flask-WTF CSRFProtect (formularze i AJAX z tokenem) | A01 / A05 | Wstępnie |
| Nagłówki bezpieczeństwa | Flask-Talisman (CSP, HSTS opcjonalnie) | A05: Security Misconfiguration | Wstępnie |
| Rate limiting | Flask-Limiter (np. /api/tasks: 5/min) | A06: Vulnerable & Outdated Components (indirect), A10: SSRF (redukcja) | Wstępnie |
| Logowanie i monitoring | RotatingFileHandler, request id, AuditLog | A09: Security Logging & Monitoring Failures | Wstępnie |
| Szyfrowanie w transporcie | HSTS (gdy HTTPS) | A02: Cryptographic Failures | Plan |
| Ochrona przed XSS | Jinja autoescape, CSP, bleach (plan) | A03 / A05 | Częściowo |

Szczegóły zostaną rozszerzone po implementacji kolejnych modułów.

## Reset bazy danych (SQLite)
Uwaga: operacja destrukcyjna — usunie wszystkie dane.

Opcja A (szybko):
- Zatrzymaj aplikację
- Usuń plik `app.db`
- Usuń folder `instance/` (opcjonalnie logi)
- Uruchom: `flask db upgrade`

Opcja B (alembic downgrade/upgrade):
- `flask db downgrade base`
- `flask db upgrade`

## API Tokens
- Tworzenie tokenu: `POST /api/tokens` (JSON: `{ "name": "mój token" }`) — odpowiedź zawiera jednorazowo surowy token
- Lista tokenów: `GET /api/tokens`
- Unieważnienie: `DELETE /api/tokens/<id>`
- Użycie: dodaj nagłówek `Authorization: Bearer <TOKEN>` do żądań API (działa alternatywnie do sesji)
- Bezpieczeństwo: w bazie przechowywany jest wyłącznie hash (sha256), pole `last_used_at` aktualizowane przy każdym użyciu

## API – Tasks
- Lista zadań: `GET /api/tasks`
  - Parametry zapytania (opcjonalne):
    - `page` (domyślnie 1), `per_page` (domyślnie 20, max 100)
    - `q` – fulltext po tytule i opisie (ILIKE)
    - `status` – jedno z: `todo`, `in_progress`, `done`
    - `priority` – jedno z: `low`, `medium`, `high`
    - `project_id` – ograniczenie do jednego projektu (musi należeć do użytkownika)
  - Wymaga uwierzytelnienia (sesja lub `Authorization: Bearer <TOKEN>`)
  - Zwraca: `{ page, per_page, total, pages, items: [...] }`

## Audit log
Zapisywane operacje (wybrane):
- Utworzenie/usunięcie projektu
- Dodanie/usunięcie członka, zmiana roli
- Zmiana statusu zadania, zmiana assignee, usunięcie zadania
- Usunięcie komentarza

Struktura rekordów: `actor_id`, `action`, `entity_type`, `entity_id`, `project_id`, `meta`, `created_at`.

## Wyszukiwanie i filtrowanie zadań
- Widok tablicy zadań (`/tasks`) obsługuje parametry `q` (tekst w tytule/opisie), `status`, `priority`, `project`.
- Drag&drop działa także po filtrowaniu (UI aktualizuje się optymistycznie).

## Testy
- CSRF: testy sprawdzające odrzucanie POST bez tokenu oraz akceptację z tokenem
- Rate limiting: test limitu na `/api/tasks` (5/min)

## Licencja
Internal academic project.
