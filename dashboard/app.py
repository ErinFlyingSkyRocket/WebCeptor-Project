from flask import Flask, request
from flask_apscheduler import APScheduler
from extensions import db, bcrypt, login_manager, socketio
from routes import auth_bp, dashboard_bp, main_bp, search_bp
from flask_login import current_user
from datetime import datetime, timedelta
from models import InterceptedData

app = Flask(__name__, template_folder="templates")
app.config.from_object("config.Config")

# Initialize Extensions
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
socketio.init_app(app)

# REGISTER BLUEPRINTS
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
app.register_blueprint(main_bp)
app.register_blueprint(search_bp)

# Initialize Scheduler
scheduler = APScheduler()

def delete_old_logs():
    """Deletes logs older than 7 days at midnight."""
    with app.app_context():
        try:
            seven_days_ago = datetime.now() - timedelta(days=7)
            deleted_count = db.session.query(InterceptedData).filter(InterceptedData.received_at < seven_days_ago).delete()
            db.session.commit()
            print(f"[CLEANUP] Deleted {deleted_count} old logs at midnight")
        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] Failed to delete old logs: {e}")

# Schedule the cleanup task to run every day at 00:00
scheduler.add_job(id="daily_cleanup", func=delete_old_logs, trigger="cron", hour=0, minute=0)

@socketio.on("connect")
def handle_connect():
    session_token = request.cookies.get("session")
    if not current_user.is_authenticated and not session_token:
        return False  # Reject unauthorized WebSocket connection
    print(f"User {current_user.username} connected to WebSocket")

@socketio.on("disconnect")
def handle_disconnect():
    print(f"User {current_user.username} disconnected from WebSocket")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure tables are created before running
        delete_old_logs()  # Run cleanup once at startup
    scheduler.init_app(app)
    scheduler.start()
    socketio.run(app, host="0.0.0.0", port=9090, debug=True)
