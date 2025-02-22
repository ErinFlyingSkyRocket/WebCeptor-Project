import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "password")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/mitm_logs")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOGIN_VIEW = "auth.login"
