from flask import Flask, render_template, url_for, redirect, request, flash
from flask_login import login_user, login_required, logout_user
from sqlalchemy import select
import base64
import io
import os
import click
import cv2
from dotenv import load_dotenv
import json

from extensions import db, login_manager, ph
import model
import vision

def setup_database(app):
    with app.app_context():
        db.create_all()
        print('Database tables created/checked')

    admins_json = os.environ.get("INITIAL_ADMINS")
    if not admins_json:
        print("No Initial Admins found")
        return

    try:
        admins_to_create = json.loads(admins_json)
    except json.JSONDecodeError:
        print("Error in decoding admins")
        return
    except Exception as e:
        print(f"An unexpected error occurred {e}")
        return

    for admin_data in admins_to_create:
        username = admin_data.get('username')
        pass_1 = admin_data.get('password')
        pass_2 = admin_data.get('password_2')

        if not username or not pass_1 or not pass_2:
            print('Issue creating admin, username, password, or second password missing')
            continue

        admin_exists = db.session.scalar(
            select(model.Admin).where(model.Admin.username == username)
        )

        if admin_exists:
            print(f'admin {username} already exists, skipping')
            continue

        hashed_password = model.hash_credentials(pass_1, pass_2)
        new_admin = model.Admin(username=username, password=hashed_password)
        db.session.add(new_admin)

    db.session.commit()

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    load_dotenv()

    db_url = os.environ.get('DATABASE_URL')
    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "sen.db")}'
    app.config['SECRET_KEY'] = os.environ.get('SESSION_COOKIE_SECRET_KEY')
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'index'

    setup_database(app)

    @login_manager.user_loader
    def load_user(user_id):
        with app.app_context():
            return db.session.get(model.User, int(user_id))

    @app.route('/', methods=['GET', 'POST'])
    def index():
        form = model.LoginForm()
        if form.validate_on_submit():
            statement = select(model.User).where(model.User.username == form.username.data)
            user = db.session.scalar(statement)
            if user and model.verify_credentials(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
        return render_template('index.html', form=form)

    @app.route('/SharkToothFinder', methods=['GET', 'POST'])
    @login_required
    def home():
        if request.method == 'POST':
            if 'image-file' not in request.files:
                flash('No file part')
                return redirect(request.url)

            file = request.files['image-file']

            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)

            if file:
                image_bytes = file.read()

                processed_image_np, obj_count = vision.get_image(image_bytes, file.filename)

                if processed_image_np is None:
                    flash('Could not process image file')
                    return redirect(request.url)

                _, buffer = cv2.imencode('.png', processed_image_np)
                img_base64 = base64.b64encode(buffer).decode('utf-8')

                return render_template('home.html', processed_image=img_base64, object_count=obj_count)

        # Get request
        return render_template('home.html')

    @app.route('/logout', methods=['GET', 'POST'])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/create_account', methods=['GET', 'POST'])
    def create():
        form = model.RegisterForm()
        if form.validate_on_submit():
            if form.new_password.data != form.new_password2.data:
                return render_template('create_account.html', form=form, error='New user passwords do not match')
            statement = select(model.Admin).where(model.Admin.username == form.admin_username.data)
            admin = db.session.scalar(statement)
            if not admin or not model.verify_credentials(admin.password, form.admin_password.data,
                                                         form.admin_password2.data):
                return render_template('create_account.html', form=form, error='Admin information not correct')

            hashed = model.hash_credentials(form.new_password.data)
            new_user = model.User(username=form.new_username.data, password=hashed)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index'))
        return render_template('create_account.html', form=form)

    # CLI commands
    @app.cli.command('create-db')
    def create_db_command():
        with app.app_context():
            db.create_all()
        print('Database tables created successfully.')

    @app.cli.command('create-admin')
    @click.argument('username')
    def create_admin_command(username):
        from getpass import getpass
        password = getpass('Enter password: ')
        password_match = getpass('Re-enter password: ')
        if password != password_match:
            print('Passwords do not match')
            return

        password2 = getpass('Enter Second Password: ')
        password2_match = getpass('Re-enter Second Password: ')
        if password2 != password2_match:
            print('Second Passwords do not match')
            return

        with app.app_context():
            hashed = model.hash_credentials(password, password2)
            new_admin = model.Admin(username=username, password=hashed)
            db.session.add(new_admin)
            db.session.commit()
            print(f'Admin user {username} created successfully')

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)