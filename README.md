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

## Mapowanie zabezpieczeń -> OWASP Top 10 (aktualne)

Wybrane obszary (zgodnie z tematem pracy) oraz implementacje i walidacja testami:

| OWASP 2021 | Cel | Implementacja | Walidacja |
|------------|-----|---------------|-----------|
| A01 Broken Access Control | Brak IDOR, izolacja projektów | Kontrole w `security/permissions.py`, sprawdzanie członkostwa na wszystkich widokach/endpointach; role per-projekt | Testy: `tests/test_access_control.py`, `tests/test_permissions.py` |
| A02 Cryptographic Failures | Bezpieczeństwo danych w tranzycie i tajemnic | HTTPS wymuszony w produkcji (Talisman force_https + HSTS), ciasteczka `Secure`/`HttpOnly`/`SameSite=Lax`, brak haseł w DB (OAuth), tokeny API przechowywane jako SHA-256 | Testy nagłówków: `tests/test_security_headers.py` |
| A03 Injection | XSS/SQLi mitigacje | ORM (parametryzacja), Jinja autoescape, `bleach` dla opisów/komentarzy, CSP; usunięty `|safe` w komentarzach | Testy: `tests/test_injection.py`, `tests/test_api.py` |
| A05 Security Misconfiguration | Twarde nagłówki + bezpieczna konfiguracja | Flask-Talisman: CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy; Rate limiting; ProxyFix; brak DEBUG w prod | Testy: `tests/test_security_headers.py`, `tests/test_rate_limit.py` |
| A07 Identification & Authentication Failures | Silne logowanie i sesje | OAuth (Google/GitHub) via Authlib, brak haseł lokalnych; rate limiting na login/callback; sesje: `HttpOnly`, `Secure`, `SameSite=Lax`, 8h TTL | Testy integracyjne (logowanie pośrednio), możliwość dodania testu e2e |
| A09 Security Logging & Monitoring | Ślad audytowy działań | `AuditLog` dla zmian statusu, przypisania, usuwania; X-Request-ID; logi aplikacji | Testy: `tests/test_audit.py` |

Pozostałe (A04, A06, A08, A10) nie są głównym celem implementacyjnym, ale: mamy pełne wersjonowanie zależności (A06), CI z `pip-audit` i `bandit`, ograniczamy powierzchnię SSRF (brak user-controlled SSRF, jedynie zaufane wywołania OAuth), a projekt dokumentuje decyzje projektowe (A04).

### Kryteria sukcesu (dla pracy inż.)
- Funkcjonalna aplikacja do zarządzania zadaniami (projekty, zadania, komentarze, filtrowanie, DnD).
- Uwierzytelnianie wyłącznie przez OAuth, brak przechowywania haseł użytkowników.
- Twarde nagłówki bezpieczeństwa i bezpieczne cookies (HttpOnly, Secure, SameSite=Lax).
- Izolacja danych per projekt i role (owner/admin/member/viewer) – weryfikowane testami automatycznymi.
- Ochrona przed XSS/SQL Injection – weryfikowane testami.
- Rate limiting na krytycznych endpointach (login, API) – testy.
- Audyt kluczowych akcji – testy.
- CI: testy + skan zależności (pip-audit) + analiza statyczna (bandit) na każdym PR.

### Braki i plan
- CSP bez `unsafe-inline` z nonce – do wdrożenia (wymaga wstrzykiwania nonce w szablonach i konfiguracji Talisman).
- Dodatkowe testy A01 (np. próba filtrowania po cudzym `project_id` w API powinna zwrócić puste/403) – częściowo dodane, można rozszerzyć.
- Dokumentacja modelu zagrożeń (Threat Model) i diagram architektury – do uzupełnienia w README.
- Produkcja: upewnić się, że `OAUTH_REDIRECT_BASE` ustawione na HTTPS domeny, a dostawcy OAuth mają poprawne redirect URIs.

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
- CSRF: testy sprawdzające odrzucanie POST bez tokenu oraz akceptację z tokenem (`tests/test_csrf.py`).
- Rate limiting: test limitu na `/api/tasks` (`tests/test_rate_limit.py`).
- Nagłówki bezpieczeństwa: `tests/test_security_headers.py`.
- XSS/SQLi: `tests/test_injection.py`.
- Dostęp: `tests/test_access_control.py`, `tests/test_permissions.py`.

## Licencja
Internal academic project.
