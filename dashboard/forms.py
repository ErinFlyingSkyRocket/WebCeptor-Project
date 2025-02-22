from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(),
        Length(min=3, max=50),
        Regexp(r"^[A-Za-z0-9_]+$", message="Only letters, numbers, and underscores allowed.")
    ])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, max=100)
    ])
    submit = SubmitField("Login")
