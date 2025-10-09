from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from argon2 import PasswordHasher

db = SQLAlchemy()
login_manager = LoginManager()
ph = PasswordHasher(
    time_cost=3,
    memory_cost=64*1024,
    parallelism=4,
    hash_len=32
)