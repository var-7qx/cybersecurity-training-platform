import os
import sqlite3
import secrets
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from core.telemetry_client import (
    CW_PLATFORM,
    CW_ECOMMERCE,
    CW_BOOKING,
    CW_BANKING,
    CW_SOCIAL,
    VALID_APP_IDS,
    VALID_SEVERITIES,
    compute_signature,
    verify_signature,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "my_collections.db"
LAB_MODE = os.environ.get("LAB_MODE", "1") == "1"
# The app intentionally binds to loopback only in run.py. Do not expose this lab to a network.
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Local HTTP lab only. Set True behind HTTPS in production.
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB maximum payload size
)

def get_db_path():
    return Path(app.config.get("DATABASE_PATH") or (BASE_DIR / "instance" / "my_collections.db"))

def init_db(conn):
    conn.executescript("""
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','manager','editor','user','guest'))
    );
    CREATE TABLE IF NOT EXISTS collections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      event TEXT NOT NULL,
      username TEXT,
      detail TEXT,
      remote_addr TEXT
    );
    CREATE TABLE IF NOT EXISTS soc_idempotency (
      app_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (app_id, event_id)
    );
    """)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    new_columns = [
        ("http_method", "TEXT"),
        ("path", "TEXT"),
        ("status_code", "INTEGER"),
        ("user_agent", "TEXT"),
        ("app_id", "TEXT NOT NULL DEFAULT 'cw_platform'"),
        ("severity", "TEXT NOT NULL DEFAULT 'INFO'"),
        ("event_id", "TEXT"),
    ]
    for col_name, col_type in new_columns:
        if col_name not in cols:
            conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col_name} {col_type}")
    conn.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_app_event
    ON audit_log(app_id, event_id)
    WHERE event_id IS NOT NULL;
    """)
    conn.commit()

def db():
    if "db" not in g:
        db_path = get_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        init_db(g.db)
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def get_client_ip():
    """
    Returns the real socket remote IP address.
    Strictly ignores X-Forwarded-For, X-Real-IP, and any client-supplied headers
    to prevent header spoofing during penetration testing and training.
    """
    if request and request.remote_addr:
        return request.remote_addr
    return "127.0.0.1"

def get_app_secret(app_id):
    """
    Retrieves the provisioned HMAC-SHA256 secret for an application identifier.
    Fails closed: returns None if the key is not explicitly configured in environment or app config.
    """
    env_map = {
        CW_PLATFORM: "CW_SOC_SECRET_PLATFORM",
        CW_ECOMMERCE: "CW_SOC_SECRET_ECOMMERCE",
        CW_BOOKING: "CW_SOC_SECRET_BOOKING",
        CW_BANKING: "CW_SOC_SECRET_BANKING",
        CW_SOCIAL: "CW_SOC_SECRET_SOCIAL",
    }
    env_var = env_map.get(app_id)
    if not env_var:
        return None
    secret = os.environ.get(env_var)
    if not secret and app.config.get("SOC_SECRETS"):
        secret = app.config["SOC_SECRETS"].get(app_id)
    return secret

def audit(
    event,
    username=None,
    detail="",
    http_method=None,
    path=None,
    status_code=None,
    user_agent=None,
    remote_addr=None,
    app_id=CW_PLATFORM,
    severity="INFO",
    event_id=None,
):
    ip = remote_addr if remote_addr is not None else get_client_ip()
    method = http_method if http_method is not None else (request.method if request else "N/A")
    req_path = path if path is not None else (request.path if request else "N/A")
    ua = user_agent if user_agent is not None else (request.headers.get("User-Agent", "")[:250] if request else "")
    now_utc = datetime.now(timezone.utc).isoformat()
    detail_str = str(detail)[:250] if detail is not None else ""
    evt_id = event_id or str(uuid.uuid4())
    sev = severity if severity in VALID_SEVERITIES else "INFO"
    appl = app_id if app_id in VALID_APP_IDS else CW_PLATFORM

    conn = db()
    try:
        conn.execute(
            "INSERT INTO soc_idempotency (app_id, event_id) VALUES (?, ?)",
            (appl, evt_id),
        )
    except sqlite3.IntegrityError:
        pass

    conn.execute(
        """INSERT INTO audit_log (
            created_at, event, username, detail, remote_addr,
            http_method, path, status_code, user_agent,
            app_id, severity, event_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (now_utc, event, username, detail_str, ip, method, req_path, status_code, ua, appl, sev, evt_id),
    )
    conn.commit()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/admin") or request.path.startswith("/soc"):
                audit(
                    "unauthorized_admin_access",
                    username=None,
                    detail=f"Unauthenticated access attempt to {request.path}",
                    status_code=302,
                )
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def current_user():
    if not session.get("user_id"):
        return None
    return db().execute(
        "SELECT id, username, role, display_name FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            audit(
                "unauthorized_admin_access",
                username=user["username"] if user else None,
                detail=f"Access denied to {request.path}: requires admin role",
                status_code=403,
            )
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_user():
    return {"current_user": current_user(), "lab_mode": LAB_MODE}

@app.get("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        # Parameterized SQL is deliberate: the baseline app is not SQL-injectable.
        user = db().execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            audit("login_success", username=username, status_code=302)
            return redirect(url_for("dashboard"))
        audit("login_failure", username=username, detail="Invalid username or password", status_code=200)
        # Keep the response generic to avoid username enumeration.
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.get("/logout")
def logout():
    user = current_user()
    audit("logout", username=user["username"] if user else None, status_code=302)
    session.clear()
    return redirect(url_for("index"))

@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return render_template("dashboard.html", user=user)

@app.get("/collections")
@login_required
def collections():
    user = current_user()
    items = db().execute(
        "SELECT id, title, category, description FROM collections WHERE owner_id = ? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    return render_template("collections.html", items=items)

@app.get("/admin")
@login_required
@admin_required
def admin():
    users = db().execute("SELECT id, username, display_name, role FROM users ORDER BY id").fetchall()
    logs = db().execute(
        "SELECT created_at, event, username, detail, remote_addr, http_method, path, status_code FROM audit_log ORDER BY id DESC LIMIT 30"
    ).fetchall()
    return render_template("admin.html", users=users, logs=logs)

@app.get("/soc/telemetry")
@app.get("/admin/telemetry")
@login_required
@admin_required
def soc_telemetry():
    event_filter = request.args.get("event", "").strip()
    app_filter = request.args.get("app", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100

    conn = db()
    total_events = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT remote_addr) FROM audit_log WHERE remote_addr IS NOT NULL").fetchone()[0]
    failed_logins = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event = 'login_failure'").fetchone()[0]
    unauthorized_probes = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event = 'unauthorized_admin_access'").fetchone()[0]
    not_found_scans = conn.execute("SELECT COUNT(*) FROM audit_log WHERE event = 'not_found'").fetchone()[0]
    high_critical = conn.execute("SELECT COUNT(*) FROM audit_log WHERE severity IN ('HIGH', 'CRITICAL')").fetchone()[0]

    stats = {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "failed_logins": failed_logins,
        "unauthorized_probes": unauthorized_probes,
        "not_found_scans": not_found_scans,
        "high_critical": high_critical,
    }

    query = """SELECT id, created_at, event, username, detail, remote_addr,
                      http_method, path, status_code, user_agent,
                      app_id, severity, event_id
               FROM audit_log"""
    conditions = []
    params = []

    if event_filter:
        conditions.append("event = ?")
        params.append(event_filter)
    if app_filter:
        conditions.append("app_id = ?")
        params.append(app_filter)
    if severity_filter:
        conditions.append("severity = ?")
        params.append(severity_filter)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    logs = conn.execute(query, tuple(params)).fetchall()

    return render_template(
        "soc_telemetry.html",
        logs=logs,
        stats=stats,
        current_filter=event_filter,
        current_app=app_filter,
        current_severity=severity_filter,
    )

@app.post("/api/v1/soc/ingest")
def soc_ingest():
    # 0. Content-Type enforcement
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    app_id_header = request.headers.get("X-CW-App-ID")
    ts_header = request.headers.get("X-CW-Timestamp")
    event_id_header = request.headers.get("X-CW-Event-ID")
    signature_header = request.headers.get("X-CW-Signature")

    # 1. Check required headers
    if not all([app_id_header, ts_header, event_id_header, signature_header]):
        return jsonify({
            "error": "Missing required authentication headers (X-CW-App-ID, X-CW-Timestamp, X-CW-Event-ID, X-CW-Signature)"
        }), 400

    if app_id_header not in VALID_APP_IDS:
        return jsonify({"error": f"Invalid application identifier '{app_id_header}'"}), 400

    # 2. Timestamp freshness validation (within 300 seconds)
    try:
        ts_val = float(ts_header)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid timestamp format in X-CW-Timestamp header"}), 400

    current_ts = datetime.now(timezone.utc).timestamp()
    if abs(current_ts - ts_val) > 300:
        return jsonify({"error": "Timestamp outside acceptable skew window (300 seconds)"}), 400

    # 3. Payload parsing & strict schema validation
    raw_body = request.get_data(as_text=True)
    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    # Verify header-to-payload identity matching
    if app_id_header != payload.get("app_id"):
        return jsonify({"error": "Header X-CW-App-ID does not match payload app_id"}), 400
    if event_id_header != payload.get("event_id"):
        return jsonify({"error": "Header X-CW-Event-ID does not match payload event_id"}), 400

    # Validate and cap: event_type (required string, 1-100 chars)
    event_type = payload.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return jsonify({"error": "Field 'event_type' must be a non-empty string"}), 400
    if len(event_type) > 100:
        return jsonify({"error": "Field 'event_type' exceeds maximum length of 100 characters"}), 400

    # Validate: severity (required string, in VALID_SEVERITIES)
    severity = payload.get("severity", "INFO")
    if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
        return jsonify({
            "error": f"Invalid severity level '{severity}'. Allowed: {sorted(VALID_SEVERITIES)}"
        }), 400

    # Validate and cap: username (optional, string or null, max 100 chars)
    username = payload.get("username")
    if username is not None:
        if not isinstance(username, str):
            return jsonify({"error": "Field 'username' must be a string or null"}), 400
        if len(username) > 100:
            return jsonify({"error": "Field 'username' exceeds maximum length of 100 characters"}), 400

    # Validate and cap: path (optional, string or null, max 250 chars)
    req_path = payload.get("path")
    if req_path is not None:
        if not isinstance(req_path, str):
            return jsonify({"error": "Field 'path' must be a string or null"}), 400
        if len(req_path) > 250:
            return jsonify({"error": "Field 'path' exceeds maximum length of 250 characters"}), 400
    req_path = req_path or "/"

    # Validate and cap: source_ip (optional, string or null, max 45 chars)
    source_ip = payload.get("source_ip")
    if source_ip is not None:
        if not isinstance(source_ip, str):
            return jsonify({"error": "Field 'source_ip' must be a string or null"}), 400
        if len(source_ip) > 45:
            return jsonify({"error": "Field 'source_ip' exceeds maximum length of 45 characters"}), 400
    source_ip = source_ip or get_client_ip()

    # Validate and cap: user_agent (optional, string or null, max 250 chars)
    ua = payload.get("user_agent")
    if ua is not None:
        if not isinstance(ua, str):
            return jsonify({"error": "Field 'user_agent' must be a string or null"}), 400
        if len(ua) > 250:
            return jsonify({"error": "Field 'user_agent' exceeds maximum length of 250 characters"}), 400
    ua = ua or ""

    # Validate and cap: details (optional, dict/list/str/int/float/bool or null, max 250 chars serialized)
    details = payload.get("details")
    if details is not None:
        if not isinstance(details, (dict, list, str, int, float, bool)):
            return jsonify({"error": "Field 'details' contains unsupported type"}), 400
        details_str = json.dumps(details) if isinstance(details, (dict, list)) else str(details)
        if len(details_str) > 250:
            return jsonify({"error": "Field 'details' exceeds maximum length of 250 characters"}), 400
    else:
        details_str = ""

    # Validate: status_code (optional, int or null, 100-599)
    status_code = payload.get("status_code")
    if status_code is not None:
        if not isinstance(status_code, int) or isinstance(status_code, bool) or not (100 <= status_code <= 599):
            return jsonify({"error": "Field 'status_code' must be an integer between 100 and 599 or null"}), 400

    # Validate: http_method (optional, string or null, max 16 chars)
    method = payload.get("http_method")
    if method is not None:
        if not isinstance(method, str):
            return jsonify({"error": "Field 'http_method' must be a string or null"}), 400
        if len(method) > 16:
            return jsonify({"error": "Field 'http_method' exceeds maximum length of 16 characters"}), 400
    method = method or "POST"

    # Validate: timestamp (optional, string or null, max 50 chars)
    iso_ts = payload.get("timestamp")
    if iso_ts is not None:
        if not isinstance(iso_ts, str):
            return jsonify({"error": "Field 'timestamp' must be a string or null"}), 400
        if len(iso_ts) > 50:
            return jsonify({"error": "Field 'timestamp' exceeds maximum length of 50 characters"}), 400
    iso_ts = iso_ts or datetime.now(timezone.utc).isoformat()

    # 4. HMAC authentication (Fail closed)
    secret = get_app_secret(app_id_header)
    if not secret:
        return jsonify({"error": "Authentication failed: service secret not configured"}), 401

    if not verify_signature(
        secret=secret,
        timestamp=ts_header,
        app_id=app_id_header,
        event_id=event_id_header,
        raw_body=raw_body,
        presented_signature=signature_header,
    ):
        return jsonify({"error": "Invalid HMAC signature"}), 401

    # 5. Atomic Idempotency Check & Insert
    conn = db()
    try:
        conn.execute(
            "INSERT INTO soc_idempotency (app_id, event_id) VALUES (?, ?)",
            (app_id_header, event_id_header),
        )
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Duplicate event detected", "event_id": event_id_header}), 409

    conn.execute(
        """INSERT INTO audit_log (
            created_at, event, username, detail, remote_addr,
            http_method, path, status_code, user_agent,
            app_id, severity, event_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            iso_ts,
            event_type[:100],
            username[:100] if username else None,
            details_str[:250],
            source_ip[:45],
            method[:16],
            req_path[:250],
            status_code,
            ua[:250],
            app_id_header,
            severity,
            event_id_header,
        ),
    )
    conn.commit()
    return jsonify({"status": "accepted", "event_id": event_id_header}), 201

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_error):
    user = current_user()
    audit(
        "not_found",
        username=user["username"] if user else None,
        detail=f"Page not found: {request.path}",
        status_code=404,
    )
    return render_template("error.html", code=404, message="The requested page was not found."), 404

@app.errorhandler(413)
def request_entity_too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Payload exceeds maximum allowed size (1 MB)"}), 413
    return render_template("error.html", code=413, message="Request payload too large."), 413

@app.errorhandler(415)
def unsupported_media_type(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return render_template("error.html", code=415, message="Unsupported media type."), 415

if __name__ == "__main__":
    # Hard guard: this app must never bind to 0.0.0.0.
    app.run(host="127.0.0.1", port=5000, debug=False)
