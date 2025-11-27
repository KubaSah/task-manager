# System Zarządzania Zadaniami

Aplikacja webowa do zarządzania projektami i zadaniami z zaawansowanymi mechanizmami bezpieczeństwa.

## O projekcie
System umożliwia zespołom zarządzanie projektami i zadaniami w bezpieczny sposób. Aplikacja wykorzystuje Flask z uwierzytelnianiem OAuth, kontrolą dostępu opartą na rolach oraz wielowarstwową ochroną przed typowymi zagrożeniami.

## Uruchomienie lokalne
1. Sklonuj repozytorium
2. Utwórz i aktywuj wirtualne środowisko:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```
3. Zainstaluj zależności:
   ```bash
   pip install -r requirements.txt
   ```
4. Skonfiguruj zmienne środowiskowe (utwórz plik `.env`):
   ```
   SECRET_KEY=twoj-losowy-klucz
   DATABASE_URL=postgresql://user:password@localhost/dbname
   OAUTH_GOOGLE_CLIENT_ID=...
   OAUTH_GOOGLE_CLIENT_SECRET=...
   OAUTH_GITHUB_CLIENT_ID=...
   OAUTH_GITHUB_CLIENT_SECRET=...
   OAUTH_REDIRECT_BASE=http://localhost:5001
   ```
5. Zainicjuj bazę danych:
   ```bash
   flask db upgrade
   ```
6. Uruchom aplikację:
   ```bash
   python run.py
   ```

## Struktura projektu
```
app/
  auth/       - uwierzytelnianie OAuth (Google, GitHub)
  core/       - strona główna, ustawienia, wyszukiwanie
  projects/   - zarządzanie projektami
  tasks/      - zarządzanie zadaniami
  api/        - API REST
  security/   - kontrola dostępu i audyt
  static/     - pliki CSS i JavaScript
  templates/  - szablony HTML
config.py     - konfiguracja aplikacji
run.py        - punkt startowy
```

## Funkcjonalności

### Zarządzanie projektami
- Tworzenie projektów z unikalnym kluczem
- System ról: właściciel, administrator, członek, obserwator
- Dodawanie członków zespołu
- Przekazywanie własności projektu

### Zarządzanie zadaniami
- Tworzenie i edycja zadań
- Statusy: do zrobienia, w toku, zrobione
- Priorytety: niski, średni, wysoki
- Przypisywanie zadań do członków zespołu
- Komentarze do zadań
- Filtrowanie i wyszukiwanie

### Bezpieczeństwo
- Uwierzytelnianie OAuth (bez przechowywania haseł)
- Kontrola dostępu oparta na rolach
- Ochrona przed CSRF
- Rate limiting
- Bezpieczne nagłówki HTTP
- Sanityzacja danych wejściowych
- Dziennik audytu działań

### API
- Tokeny API dla integracji
- Endpointy REST dla zadań
- Dokumentacja w API Explorer

## Implementowane zabezpieczenia (OWASP Top 10)

| Zagrożenie | Implementacja | Walidacja |
|------------|---------------|-----------|
| A01 Broken Access Control | Kontrola członkostwa w projektach, izolacja danych, weryfikacja uprawnień na poziomie ról | `tests/test_access_control.py`, `tests/test_permissions.py` |
| A02 Cryptographic Failures | HTTPS w produkcji, bezpieczne ciasteczka (Secure, HttpOnly, SameSite), tokeny API jako SHA-256 | `tests/test_security_headers.py` |
| A03 Injection | SQLAlchemy ORM (parametryzacja), autoescape w Jinja2, sanityzacja HTML przez bleach, CSP | `tests/test_injection.py` |
| A05 Security Misconfiguration | Flask-Talisman (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), rate limiting, ProxyFix | `tests/test_security_headers.py`, `tests/test_rate_limit.py` |
| A07 Authentication Failures | OAuth (Google/GitHub), brak lokalnych haseł, rate limiting na logowanie, bezpieczne sesje | Testy integracyjne |
| A09 Security Logging | Dziennik audytu dla kluczowych działań, X-Request-ID w nagłówkach | `tests/test_audit.py` |

## Testy

Projekt zawiera kompleksowy zestaw testów jednostkowych i integracyjnych:

```bash
pytest
```

Kategorie testów:
- `test_access_control.py` - kontrola dostępu i izolacja danych
- `test_permissions.py` - weryfikacja systemu ról
- `test_injection.py` - ochrona przed XSS i SQL Injection
- `test_csrf.py` - ochrona przed atakami CSRF
- `test_security_headers.py` - weryfikacja nagłówków bezpieczeństwa
- `test_rate_limit.py` - limitowanie liczby żądań
- `test_audit.py` - dziennik audytu
- `test_api.py` - endpointy API
- `test_tokens.py` - tokeny API

## Wyszukiwanie

Pasek wyszukiwania w górnym menu pozwala przeszukiwać:
- Projekty (nazwa, klucz, opis)
- Zadania (tytuł, opis)

Wyszukiwanie uwzględnia tylko projekty i zadania, do których użytkownik ma dostęp.

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

## API

### Uwierzytelnianie
- Sesja (ciasteczko)
- Token Bearer: `Authorization: Bearer <TOKEN>`

### Tworzenie tokenu API
```bash
curl -X POST https://twoja-domena.com/api/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "mój token"}' \
  --cookie "session=..."
```

### Zarządzanie tokenami
- `GET /api/tokens` - lista tokenów użytkownika
- `POST /api/tokens` - utworzenie nowego tokenu (zwraca surowy token jednorazowo)
- `DELETE /api/tokens/<id>` - unieważnienie tokenu

### Endpointy zadań
- `GET /api/tasks` - lista zadań (parametry: page, per_page, q, status, priority, project_id)
- `POST /api/tasks` - utworzenie zadania
- `GET /api/tasks/<id>` - szczegóły zadania
- `PATCH /api/tasks/<id>` - edycja zadania
- `POST /api/tasks/<id>/comments` - dodanie komentarza

Dokumentacja interaktywna: `/api-explorer`

## Dziennik audytu

System rejestruje kluczowe operacje:
- Zarządzanie projektami (tworzenie, usuwanie)
- Zarządzanie członkami (dodawanie, usuwanie, zmiana roli)
- Operacje na zadaniach (zmiana statusu, przypisanie, usuwanie)
- Operacje na komentarzach (usuwanie)

Dostęp do logów: `/audit`
Export do CSV: `/audit/export`

## Deployment

### Konfiguracja zmiennych środowiskowych

```bash
SECRET_KEY=<losowy-32-znakowy-klucz>
DATABASE_URL=postgresql://user:password@host:5432/dbname
FLASK_ENV=production
OAUTH_REDIRECT_BASE=https://twoja-domena.com
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
SESSION_COOKIE_SECURE=1
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=28800
```

### Konfiguracja OAuth

#### Google Cloud Console
1. Przejdź do [Google Cloud Console](https://console.cloud.google.com/)
2. Wybierz projekt lub utwórz nowy
3. **APIs & Services** → **Credentials**
4. Dodaj Authorized redirect URI: `https://twoja-domena.com/auth/callback/google`

#### GitHub OAuth
1. [GitHub Developer Settings](https://github.com/settings/developers)
2. Utwórz nową aplikację OAuth
3. Homepage URL: `https://twoja-domena.com`
4. Authorization callback URL: `https://twoja-domena.com/auth/callback/github`

### Inicjalizacja bazy danych
```bash
flask db upgrade
```

### Weryfikacja wdrożenia
- [ ] Logowanie przez Google OAuth
- [ ] Logowanie przez GitHub OAuth
- [ ] Tworzenie projektu
- [ ] Tworzenie zadania
- [ ] Filtrowanie i wyszukiwanie
- [ ] API Explorer
- [ ] Dziennik audytu

## Technologie

- **Backend**: Flask 3.x, SQLAlchemy
- **Baza danych**: PostgreSQL (produkcja), SQLite (testy)
- **Uwierzytelnianie**: OAuth 2.0 (Google, GitHub) via Authlib
- **Bezpieczeństwo**: Flask-Talisman, Flask-WTF (CSRF), Flask-Limiter
- **Frontend**: Jinja2, TailwindCSS
- **Testy**: pytest

## Licencja

Projekt akademicki.
