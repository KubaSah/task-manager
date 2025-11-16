from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Optional, Regexp


class ProjectForm(FlaskForm):
    name = StringField('Nazwa', validators=[DataRequired(), Length(max=200)])
    key = StringField(
        'Klucz',
        validators=[
            DataRequired(),
            Length(max=20),
            Regexp(r'^[A-Z0-9_]+$', message='Klucz może zawierać tylko wielkie litery, cyfry i podkreślenia')
        ]
    )
    description = TextAreaField('Opis', validators=[Optional(), Length(max=10000)])


class TaskForm(FlaskForm):
    title = StringField('Tytuł', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Opis', validators=[Optional(), Length(max=20000)])
    status = SelectField('Status', choices=[('todo', 'Do zrobienia'), ('in_progress', 'W toku'), ('done', 'Zrobione')])
    priority = SelectField('Priorytet', choices=[('low', 'Niski'), ('medium', 'Średni'), ('high', 'Wysoki')])
    # Projekt wybierany dynamicznie w widoku (choices ustawiane per request)
    project_id = SelectField('Projekt', coerce=int, validators=[Optional()])


class CommentForm(FlaskForm):
    content = TextAreaField('Komentarz', validators=[DataRequired(), Length(max=10000)])
