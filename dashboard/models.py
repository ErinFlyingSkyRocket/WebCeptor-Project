from extensions import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class InterceptedData(db.Model):
    __tablename__ = "intercepted_data"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50))
    data_type = db.Column(db.String(10), nullable=False)
    url = db.Column(db.Text, nullable=False)
    headers = db.Column(db.JSON)
    cookies = db.Column(db.JSON)
    query_params = db.Column(db.JSON)
    request_body = db.Column(db.JSON)
    response_body = db.Column(db.JSON)
    received_at = db.Column(db.DateTime, default=db.func.current_timestamp())
