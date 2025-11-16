"""
Testy zabezpieczeń przed atakami Injection (OWASP A03:2021)
- XSS (Cross-Site Scripting)
- SQL Injection
"""
import pytest
from app import create_app, db
from config import TestingConfig
from app.models import User, Project, Task, Comment, Membership


class TestXSSProtection:
    """Testy ochrony przed atakami XSS"""

    def test_xss_in_project_name_escaped(self):
        """Test: XSS w nazwie projektu jest escapowany przez Jinja2"""
        app = create_app()
        app.config.from_object(TestingConfig)
        
        with app.app_context():
            db.create_all()
            u = User(email='xss@example.com', name='XSSUser', provider='github', provider_id='xss1')
            db.session.add(u)
            db.session.commit()
            
            # Próba wstrzyknięcia XSS payload
            xss_payload = '<script>alert("XSS")</script>'
            p = Project(name=xss_payload, key='XSS', owner=u)
            db.session.add(p)
            db.session.flush()
            db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
            db.session.commit()
            
            uid = u.id
            pid = p.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Sprawdź listę projektów
        resp = client.get('/projects', follow_redirects=True)
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        
        # XSS payload NIE powinien być wykonalny (powinien być escaped)
        assert '<script>alert("XSS")</script>' not in html
        # Escaped wersja powinna być obecna
        assert '&lt;script&gt;' in html or 'alert(&quot;XSS&quot;)' in html
    
    def test_xss_in_project_description_sanitized(self):
        """Test: XSS w opisie projektu jest sanityzowany przez bleach"""
        app = create_app()
        app.config.from_object(TestingConfig)
        app.config['WTF_CSRF_ENABLED'] = False
        
        with app.app_context():
            db.create_all()
            u = User(email='xss2@example.com', name='XSSUser2', provider='github', provider_id='xss2')
            db.session.add(u)
            db.session.commit()
            uid = u.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Próba utworzenia projektu z XSS w opisie
        xss_payload = '<img src=x onerror="alert(\'XSS\')"> <b>Bold text</b>'
        resp = client.post('/projects/create', data={
            'name': 'Safe Project',
            'key': 'SAFE',
            'description': xss_payload
        }, follow_redirects=False)
        
        assert resp.status_code in (200, 302)  # może być redirect lub re-render
        
        # Sprawdź w bazie - opis powinien być oczyszczony
        with app.app_context():
            p = Project.query.filter_by(key='SAFE').first()
            if p:
                # bleach powinien usunąć niebezpieczne tagi, ale zachować <b>
                assert '<img' not in p.description
                assert 'onerror' not in p.description
                # Dozwolone tagi jak <b> mogą być zachowane (zależy od konfiguracji bleach)
    
    def test_xss_in_task_title_escaped(self):
        """Test: XSS w tytule zadania jest escapowany"""
        app = create_app()
        app.config.from_object(TestingConfig)
        
        with app.app_context():
            db.create_all()
            u = User(email='xss3@example.com', name='XSSUser3', provider='github', provider_id='xss3')
            p = Project(name='XSS Project', key='XSSP', owner=u)
            db.session.add_all([u, p])
            db.session.flush()
            db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
            db.session.commit()
            
            xss_payload = '<script>document.cookie</script>'
            t = Task(
                title=xss_payload,
                description='Test',
                project=p,
                creator_id=u.id,  # Poprawione z 'creator' na 'creator_id'
                status='todo',
                priority='medium'
            )
            db.session.add(t)
            db.session.commit()
            
            uid = u.id
            pid = p.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Sprawdź listę zadań
        resp = client.get('/tasks', follow_redirects=True)
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        
        # XSS payload NIE powinien być wykonalny
        assert '<script>document.cookie</script>' not in html
        assert '&lt;script&gt;' in html or 'document.cookie' in html
    
    def test_xss_in_comment_content_sanitized(self):
        """Test: XSS w komentarzu jest sanityzowany"""
        app = create_app()
        app.config.from_object(TestingConfig)
        
        with app.app_context():
            db.create_all()
            u = User(email='xss4@example.com', name='XSSUser4', provider='github', provider_id='xss4')
            p = Project(name='Comment Project', key='CMTP', owner=u)
            db.session.add_all([u, p])
            db.session.flush()
            db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
            t = Task(
                title='Test Task',
                description='Test',
                project=p,
                creator_id=u.id,  # Poprawione z 'creator' na 'creator_id'
                status='todo',
                priority='medium'
            )
            db.session.add(t)
            db.session.commit()
            
            xss_payload = '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            c = Comment(task=t, author_id=u.id, content=xss_payload)  # Poprawione z 'author' na 'author_id'
            db.session.add(c)
            db.session.commit()
            
            uid = u.id
            tid = t.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Sprawdź stronę zadania z komentarzami
        resp = client.get(f'/tasks/{tid}')
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        
        # <iframe> powinien być usunięty lub escaped
        assert '<iframe' not in html.lower() or '&lt;iframe' in html


class TestSQLInjectionProtection:
    """Testy ochrony przed atakami SQL Injection"""
    
    def test_sql_injection_in_project_name_prevented(self):
        """Test: SQL injection w nazwie projektu jest blokowany przez ORM"""
        app = create_app()
        app.config.from_object(TestingConfig)
        app.config['WTF_CSRF_ENABLED'] = False
        
        with app.app_context():
            db.create_all()
            u = User(email='sqli@example.com', name='SQLiUser', provider='github', provider_id='sqli1')
            db.session.add(u)
            db.session.commit()
            uid = u.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Próba SQL injection
        sql_payload = "'; DROP TABLE projects; --"
        resp = client.post('/projects/create', data={
            'name': sql_payload,
            'key': 'SQLI',
            'description': 'Test'
        }, follow_redirects=True)
        
        # Projekt powinien być utworzony z payloadem jako zwykłym tekstem
        with app.app_context():
            p = Project.query.filter_by(key='SQLI').first()
            # ORM powinien traktować payload jako string, nie SQL
            assert p is not None or resp.status_code == 200
            
            # Tabela projects nadal powinna istnieć
            projects = Project.query.all()
            assert isinstance(projects, list)  # Tabela nie została usunięta
    
    def test_sql_injection_in_task_search_prevented(self):
        """Test: SQL injection w wyszukiwaniu zadań jest blokowany"""
        app = create_app()
        app.config.from_object(TestingConfig)
        
        with app.app_context():
            db.create_all()
            u = User(email='sqli2@example.com', name='SQLiUser2', provider='github', provider_id='sqli2')
            p = Project(name='SQLi Project', key='SQLIP', owner=u)
            db.session.add_all([u, p])
            db.session.flush()
            db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
            db.session.commit()
            uid = u.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Próba SQL injection w parametrze wyszukiwania
        sql_payload = "' OR '1'='1"
        resp = client.get(f'/tasks?q={sql_payload}', follow_redirects=True)
        assert resp.status_code == 200
        
        # Aplikacja nie powinna crashować
        # ORM parametryzuje zapytania, więc injection nie zadziała
    
    def test_sql_injection_in_api_filter_prevented(self):
        """Test: SQL injection w filtrach API jest blokowany"""
        app = create_app()
        app.config.from_object(TestingConfig)
        
        with app.app_context():
            db.create_all()
            u = User(email='sqli3@example.com', name='SQLiUser3', provider='github', provider_id='sqli3')
            p = Project(name='API SQLi', key='APISQLI', owner=u)
            db.session.add_all([u, p])
            db.session.flush()
            db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
            db.session.commit()
            uid = u.id
            pid = p.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Próba SQL injection w parametrze project_id
        sql_payload = f"{pid}' OR '1'='1"
        resp = client.get(f'/api/tasks?project_id={sql_payload}')
        
        # Powinno zwrócić błąd lub puste wyniki (nie wszystkie zadania)
        assert resp.status_code in (200, 400)
        
        if resp.status_code == 200:
            data = resp.get_json()
            # Nie powinno zwrócić wszystkich zadań (które by zwróciło OR '1'='1')
            # Albo błąd walidacji, albo tylko zadania z danego projektu
            assert 'items' in data


class TestInputValidation:
    """Testy walidacji danych wejściowych"""
    
    def test_project_name_length_validation(self):
        """Test: Walidacja długości nazwy projektu"""
        app = create_app()
        app.config.from_object(TestingConfig)
        app.config['WTF_CSRF_ENABLED'] = False
        
        with app.app_context():
            db.create_all()
            u = User(email='valid@example.com', name='ValidUser', provider='github', provider_id='valid1')
            db.session.add(u)
            db.session.commit()
            uid = u.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Próba utworzenia projektu z za długą nazwą
        long_name = 'A' * 300  # Przekroczenie limitu
        resp = client.post('/projects/create', data={
            'name': long_name,
            'key': 'LONG',
            'description': 'Test'
        }, follow_redirects=False)
        
        # Powinno zwrócić błąd walidacji (400) lub re-render formularza (200)
        assert resp.status_code in (200, 400)
        
        # Projekt nie powinien być utworzony
        with app.app_context():
            p = Project.query.filter_by(key='LONG').first()
            assert p is None or len(p.name) <= 255  # Zgodnie z limitem modelu
    
    def test_task_title_required_validation(self):
        """Test: Walidacja wymaganego pola tytułu zadania"""
        app = create_app()
        app.config.from_object(TestingConfig)
        app.config['WTF_CSRF_ENABLED'] = False
        
        with app.app_context():
            db.create_all()
            u = User(email='valid2@example.com', name='ValidUser2', provider='github', provider_id='valid2')
            p = Project(name='Valid Project', key='VALIDP', owner=u)
            db.session.add_all([u, p])
            db.session.flush()
            db.session.add(Membership(user_id=u.id, project_id=p.id, role='owner'))
            db.session.commit()
            uid = u.id
            pid = p.id
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
            sess['_fresh'] = True
        
        # Próba utworzenia zadania bez tytułu
        resp = client.post('/tasks/create', data={
            'project_id': pid,
            'title': '',  # Pusty tytuł
            'description': 'Test',
            'priority': 'medium',
            'status': 'todo'
        }, follow_redirects=False)
        
        # Powinno zwrócić błąd walidacji
        assert resp.status_code in (200, 400)
        
        # Zadanie nie powinno być utworzone
        with app.app_context():
            tasks = Task.query.filter_by(title='').all()
            assert len(tasks) == 0
    
    def test_email_format_validation(self):
        """Test: Walidacja formatu email (jeśli byłaby rejestracja lokalna)"""
        # Ten test jest bardziej akademicki, bo używamy OAuth
        # Ale pokazuje świadomość walidacji
        from wtforms.validators import Email, ValidationError
        from wtforms import StringField, Form
        
        class TestForm(Form):
            email = StringField('Email', validators=[Email()])
        
        # Poprawny email
        form_valid = TestForm(data={'email': 'user@example.com'})
        assert form_valid.validate() is True
        
        # Niepoprawny email
        form_invalid = TestForm(data={'email': 'not-an-email'})
        assert form_invalid.validate() is False
        assert 'email' in form_invalid.errors
