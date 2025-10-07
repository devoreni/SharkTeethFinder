from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
import click
from flask.cli import with_appcontext
from dotenv import dotenv_values
import os
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from time import sleep
import re

secrets = dotenv_values('.env')
basedir = os.path.abspath(os.path.dirname(__file__))
ph = PasswordHasher(
    time_cost=3,
    memory_cost=64*1024,
    parallelism=4,
    hash_len=32
)
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "sen.db")}'
app.config['SECRET_KEY'] = secrets['SESSION_COOKIE_SECRET_KEY']
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    new_username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'New Username'}
    )
    new_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'New Password'}
    )
    new_password2 = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Confirm Password'}
    )

    admin_username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Admin Username'}
    )
    admin_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Admin Password'}
    )
    admin_password2 = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'Admin Second Password'}
    )

    submit = SubmitField("Register")

    def validate_new_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError("That username already exists, please choose another one.")
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'username'}
    )
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                               render_kw={'placeholder': 'password'}
    )

    submit = SubmitField('Log In')
        
def hash_credentials(p1, p2=''):
    combined = f'{p1}||{p2}||{secrets['PEPPER']}'
    return ph.hash(combined)

def verify_credentials(hashed, p1, p2=''):
    combined = f'{p1}||{p2}||{secrets['PEPPER']}'
    try:
        ph.verify(hashed, combined)
        return True
    except (VerifyMismatchError, InvalidHash):
        sleep(2)
        return False
    except Exception as e:
        sleep(2)
        print(f'Unexpected Error: {e}')
        return False


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        if (user := User.query.filter_by(username=form.username.data).first()) is None:
            return render_template('index.html', form=form)
        if verify_credentials(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('index.html', form=form)

@app.route('/SharkToothFinder', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_account', methods=['GET', 'POST'])
def create():
    form = RegisterForm()

    if form.validate_on_submit():
        if form.new_password.data != form.new_password2.data:
            return render_template('create_account.html', form=form, error='New user passwords do not match')
        admin = Admin.query.filter_by(username=form.admin_username.data).first()
        if not admin or not verify_credentials(admin.password, form.admin_password.data, form.admin_password2.data):
            return render_template('create_account.html', form=form, error='Admin information not correct')
        hashed = hash_credentials(form.new_password.data)
        new_user = User(username=form.new_username.data, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('create_account.html', form=form)

@app.cli.command('create-db')
def create_db():
    from sqlalchemy.exc import OperationalError, IntegrityError
    from app import User, Admin
    try:
        with open(os.path.join(basedir, "sen.db"), 'x') as f:
            print(f'Created sen.db at {os.path.join(basedir, "sen.db")}')
    except FileExistsError:
        print('sen.db already exists, continuing...')
    try:
        print(f'creating tables at {os.path.abspath("sen.db")}')
        print(f"Registered tables: {db.Model.metadata.tables.keys()}")
        db.create_all()
        print('Database table created successfully')
    except OperationalError as e:
        print('Database operation failed. It might already exist or be locked.')
        print(f'Error: {e}')
    except IntegrityError as e:
        print('Integrity error while creating tables.')
        print(f'Error: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')

@app.cli.command('create-admin')
@click.argument('username')
@with_appcontext
def create_admin(username):
    from getpass import getpass
    password = getpass('Enter password: ')
    if len(password) < 4 or re.search(r'[ "\']', password):
        print('Invalid')
        return
    password_match = getpass('Re-enter password: ')
    if password != password_match:
        print('Passwords do not match')
        return
    password2 = getpass('Enter Second Password: ')
    if len(password2) < 1 or re.search(r'[ "\']', password):
        print('Invalid')
        return
    password2_match = getpass('Re-enter Second Password: ')
    if password2 != password2_match:
        print('Second Passwords do not match')
        return
    
    try:
        hashed = hash_credentials(password, password2)
        new_admin = Admin(username=username, password=hashed)
        db.session.add(new_admin)
        db.session.commit()
        print(f'Admin user {username} created successfully')
    except Exception as e:
        print(f'An unexpected error occured: {e}')



if __name__ == '__main__':
    app.run(debug=True)