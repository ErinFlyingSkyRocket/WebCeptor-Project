from extensions import db
from flask import Flask
from config import Config

def init_db(app):
    """Initialize the database and create tables if they don't exist."""
    with app.app_context():
        db.create_all()
        print("[INFO] Database tables are set up successfully.")
