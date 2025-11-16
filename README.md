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

## Threat Model (Model Zagrożeń)

### Aktorzy i Cele
- **Użytkownik zwykły (Authenticated User)**: Chce zarządzać swoimi projektami i zadaniami, ale nie powinien mieć dostępu do danych innych użytkowników.
- **Administrator projektu (Project Owner/Admin)**: Zarządza projektem, dodaje/usuwa członków, może usuwać zadania. Potrzebuje pełnej kontroli nad swoim projektem.
- **Atakujący zewnętrzny (Unauthenticated Attacker)**: Próbuje uzyskać nieautoryzowany dostęp, przeprowadzić XSS, SQL Injection, CSRF, ujawnić dane użytkowników.
- **Atakujący z konta (Compromised User)**: Posiada konto, ale próbuje eskalować uprawnienia lub uzyskać dostęp do cudzych projektów (IDOR).

### Aktywa do Ochrony
- **Dane użytkowników**: Email, nazwa, avatar (pochodzą z OAuth, nie przechowujemy haseł).
- **Projekty i zadania**: Tytuły, opisy, komentarze – prywatne dla członków projektu.
- **Sesje i tokeny**: Ciasteczka sesji HTTP, tokeny API (SHA-256 hash w DB).
- **Integralność systemu**: Kontrola dostępu, poprawność danych, dostępność.

### Główne Zagrożenia i Mechanizmy Obrony

| Zagrożenie | Wektor ataku | Mechanizm ochrony |
|------------|--------------|-------------------|
| **A01 IDOR** | Atakujący z konta próbuje GET /tasks/{id} lub /api/tasks?project_id=X dla cudzego projektu | `require_project_membership()` w każdym route; membership sprawdzane przed zwróceniem danych; testy `test_access_control.py` |
| **A02 Dane w tranzycie** | MITM przechwytuje sesje lub tokeny przez HTTP | Talisman force_https w prod, HSTS, SESSION_COOKIE_SECURE=True, SameSite=Lax |
| **A03 XSS** | Wstrzykiwanie `<script>` w opisy/komentarze/nazwy projektów | Jinja autoescape; bleach.clean() w forms (opis/komentarz); usunięte `|safe`; CSP (częściowo, plan: nonces); testy `test_injection.py` |
| **A03 SQL Injection** | Parametr `?q=<payload>` lub POST z SQLi | SQLAlchemy ORM parametryzuje zapytania; testy `test_injection.py` weryfikują brak crashu |
| **A05 CSRF** | Atakujący zewnętrzny próbuje POST z cudzej strony | Flask-WTF CSRFProtect; tokeny w formularzach; AJAX wymaga X-CSRF-Token; SameSite=Lax; testy `test_csrf.py` |
| **A05 Clickjacking** | Embedding w iframe na złośliwej stronie | X-Frame-Options: DENY (Talisman); CSP frame-ancestors 'none' |
| **A05 Content sniffing** | Przeglądarka interpretuje JSON jako HTML i wykonuje skrypty | X-Content-Type-Options: nosniff (Talisman) |
| **A06 Podatne zależności** | Stare wersje bibliotek z CVE | pip-audit + bandit w CI (GitHub Actions); requirements.txt z konkretnymi wersjami |
| **A07 Brute-force login** | Wielokrotne próby logowania | Rate limiting (Flask-Limiter) na `/auth/login/*` i `/auth/callback/*`; OAuth wymaga state (CSRF token) |
| **A07 Session hijacking** | Przechwycenie ciasteczka sesji | HttpOnly, Secure, SameSite=Lax; 8h TTL (automatyczne wygaśnięcie); brak localStorage |
| **A09 Brak audytu** | Działania użytkowników nieśledzane | `AuditLog` dla kluczowych akcji (status, assignee, delete); X-Request-ID w nagłówkach; testy `test_audit.py` |

### Założenia i Ograniczenia
- **Zaufany OAuth provider**: Zakładamy, że Google/GitHub nie są skompromitowane; weryfikujemy state/nonce, ale nie kontrolujemy bezpieczeństwa po stronie OAuth.
- **HTTPS w produkcji**: Wymuszamy HSTS i Secure cookies; jeśli deploy nie ma HTTPS (błąd konfiguracji), ochrona sesji spada.
- **SQLite w testach**: Nie testujemy pełnej izolacji Postgres, ale ORM działa tak samo; produkcja = Postgres.
- **Brak zaawansowanego SIEM**: Logi aplikacji trafiają do pliku (dev) lub stdout (Heroku); nie ma realtime alertów (można dodać np. Sentry).
- **CSP 'unsafe-inline'**: Aktualnie dopuszczamy inline JS/CSS dla prostoty; plan: migracja na nonces przed wdrożeniem produkcyjnym krytycznych funkcji.

### Diagram architektury (uproszczony)
```
[Użytkownik] --(HTTPS)--> [Reverse Proxy/Heroku] --(ProxyFix)--> [Flask App (Talisman)]
                                                                      |
                                                      +---------------+---------------+
                                                      |               |               |
                                                 [Blueprints]  [SQLAlchemy ORM]  [Authlib OAuth]
                                                      |               |               |
                                                   [Routes]      [PostgreSQL]     [Google/GitHub]
                                                      |
                                              [CSRFProtect, Limiter]
```

- **Reverse Proxy**: Heroku router; ProxyFix odczytuje X-Forwarded-Proto/For do poprawnego generowania URL.
- **Talisman**: Stosuje nagłówki bezpieczeństwa (CSP, HSTS, XFO, nosniff, Referrer-Policy, Permissions-Policy).
- **Flask-Limiter**: Throttling per-IP na login/API.
- **CSRFProtect**: Weryfikuje tokeny w POST/PATCH/DELETE.
- **Authlib**: Obsługuje flow OAuth2 (authorize, callback, token, userinfo).

---

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

## Deployment Checklist

### 1. Zmienne środowiskowe (produkcja)
Upewnij się, że następujące zmienne środowiskowe są ustawione:

```bash
# Aplikacja
SECRET_KEY=<losowy, 32+ znaki>
DATABASE_URL=postgresql://user:password@host:5432/dbname
FLASK_ENV=production

# OAuth Redirect Base (HTTPS!)
OAUTH_REDIRECT_BASE=https://twoja-domena.com

# Google OAuth (opcjonalnie)
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=xxx

# GitHub OAuth (opcjonalnie)
GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx

# Sesje i bezpieczeństwo
SESSION_COOKIE_SECURE=1
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=28800  # 8 godzin w sekundach
```

### 2. Konfiguracja OAuth Providers

#### Google Cloud Console
1. Przejdź do [Google Cloud Console](https://console.cloud.google.com/)
2. Wybierz swój projekt lub utwórz nowy
3. Przejdź do **APIs & Services** → **Credentials**
4. Edytuj swój OAuth 2.0 Client ID
5. W sekcji **Authorized redirect URIs** dodaj:
   ```
   https://twoja-domena.com/auth/callback/google
   ```
6. Zapisz zmiany

#### GitHub OAuth Apps
1. Przejdź do [GitHub Developer Settings](https://github.com/settings/developers)
2. Wybierz swoją aplikację OAuth lub utwórz nową
3. Ustaw **Homepage URL**: `https://twoja-domena.com`
4. Ustaw **Authorization callback URL**: `https://twoja-domena.com/auth/callback/github`
5. Zapisz zmiany

### 3. Baza danych
```bash
# Uruchom migracje
flask db upgrade

# Opcjonalnie: zweryfikuj strukturę
flask db current
```

### 4. HTTPS i bezpieczeństwo
- ✅ Upewnij się, że aplikacja jest dostępna tylko przez HTTPS
- ✅ Sprawdź, czy `SESSION_COOKIE_SECURE=1` jest ustawione
- ✅ Zweryfikuj nagłówki bezpieczeństwa (użyj [SecurityHeaders.com](https://securityheaders.com))
- ✅ Upewnij się, że `DEBUG=False` w produkcji
- ✅ Sprawdź logi aplikacji pod kątem błędów konfiguracji

### 5. Heroku (przykład)
Jeśli deployu jesz na Heroku:

```bash
# Ustaw zmienne środowiskowe
heroku config:set SECRET_KEY="xxx"
heroku config:set OAUTH_REDIRECT_BASE="https://twoja-app.herokuapp.com"
heroku config:set GOOGLE_CLIENT_ID="xxx"
heroku config:set GOOGLE_CLIENT_SECRET="xxx"
heroku config:set GITHUB_CLIENT_ID="xxx"
heroku config:set GITHUB_CLIENT_SECRET="xxx"

# Heroku automatycznie ustawia DATABASE_URL dla PostgreSQL
# Zweryfikuj:
heroku config:get DATABASE_URL

# Push i migracje
git push heroku main
heroku run flask db upgrade
```

### 6. Weryfikacja po wdrożeniu
- [ ] Zaloguj się przez Google OAuth
- [ ] Zaloguj się przez GitHub OAuth
- [ ] Utwórz projekt testowy
- [ ] Utwórz zadanie testowe
- [ ] Sprawdź drag & drop na tablicy zadań
- [ ] Zweryfikuj logi audytu w `/settings/audit`
- [ ] Przetestuj filtry i wyszukiwanie
- [ ] Sprawdź API Explorer (`/settings/api-explorer`)
- [ ] Wygeneruj i przetestuj API token

### 7. Monitoring i logi
- Skonfiguruj monitoring uptime (np. UptimeRobot, Pingdom)
- Przejrzyj logi aplikacji regularnie
- Ustaw alerty dla błędów 500
- Monitoruj użycie bazy danych

### 8. Bezpieczeństwo CI/CD
- ✅ GitHub Actions uruchamia testy przy każdym PR
- ✅ `pip-audit` skanuje zależności
- ✅ `bandit` analizuje kod pod kątem podatności
- Rozważ dodanie SAST/DAST w pipeline

## Licencja
Internal academic project.
