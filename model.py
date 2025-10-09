from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from argon2.exceptions import VerifyMismatchError, InvalidHash
from time import sleep
from dotenv import dotenv_values

# Import the db and ph instances from extensions.py
from extensions import db, ph

secrets = dotenv_values('.env')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(97), nullable=False)

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(97), nullable=False)

class RegisterForm(FlaskForm):
    new_username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'New Username'})
    new_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'New Password'})
    new_password2 = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Confirm Password'})
    admin_username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Admin Username'})
    admin_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Admin Password'})
    admin_password2 = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Admin Second Password'})
    submit = SubmitField("Register")

    def validate_new_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("That username already exists, please choose another one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'password'})
    submit = SubmitField('Log In')

def hash_credentials(p1, p2=''):
    combined = f'{p1}||{p2}||{secrets["PEPPER"]}'
    return ph.hash(combined)

def verify_credentials(hashed, p1, p2=''):
    combined = f'{p1}||{p2}||{secrets["PEPPER"]}'
    try:
        return ph.verify(hashed, combined)
    except (VerifyMismatchError, InvalidHash):
        sleep(2)
        return False