from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_cors import CORS

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
socketio = SocketIO(cors_allowed_origins="*")
CORS_ALLOWED_ORIGINS = "*"

from models import User  # Import User model here

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))
