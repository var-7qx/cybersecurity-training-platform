import os
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

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
    """)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    new_columns = [
        ("http_method", "TEXT"),
        ("path", "TEXT"),
        ("status_code", "INTEGER"),
        ("user_agent", "TEXT"),
    ]
    for col_name, col_type in new_columns:
        if col_name not in cols:
            conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col_name} {col_type}")
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

def audit(event, username=None, detail="", http_method=None, path=None, status_code=None, user_agent=None, remote_addr=None):
    ip = remote_addr if remote_addr is not None else get_client_ip()
    method = http_method if http_method is not None else (request.method if request else "N/A")
    req_path = path if path is not None else (request.path if request else "N/A")
    ua = user_agent if user_agent is not None else (request.headers.get("User-Agent", "")[:250] if request else "")
    now_utc = datetime.now(timezone.utc).isoformat()
    detail_str = str(detail)[:250] if detail is not None else ""

    db().execute(
        """INSERT INTO audit_log (
            created_at, event, username, detail, remote_addr,
            http_method, path, status_code, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (now_utc, event, username, detail_str, ip, method, req_path, status_code, ua),
    )
    db().commit()

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
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100

    total_events = db().execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    unique_ips = db().execute("SELECT COUNT(DISTINCT remote_addr) FROM audit_log WHERE remote_addr IS NOT NULL").fetchone()[0]
    failed_logins = db().execute("SELECT COUNT(*) FROM audit_log WHERE event = 'login_failure'").fetchone()[0]
    unauthorized_probes = db().execute("SELECT COUNT(*) FROM audit_log WHERE event = 'unauthorized_admin_access'").fetchone()[0]
    not_found_scans = db().execute("SELECT COUNT(*) FROM audit_log WHERE event = 'not_found'").fetchone()[0]

    stats = {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "failed_logins": failed_logins,
        "unauthorized_probes": unauthorized_probes,
        "not_found_scans": not_found_scans,
    }

    if event_filter:
        logs = db().execute(
            """SELECT id, created_at, event, username, detail, remote_addr,
                      http_method, path, status_code, user_agent
               FROM audit_log
               WHERE event = ?
               ORDER BY id DESC LIMIT ?""",
            (event_filter, limit),
        ).fetchall()
    else:
        logs = db().execute(
            """SELECT id, created_at, event, username, detail, remote_addr,
                      http_method, path, status_code, user_agent
               FROM audit_log
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()

    return render_template("soc_telemetry.html", logs=logs, stats=stats, current_filter=event_filter)

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

if __name__ == "__main__":
    # Hard guard: this app must never bind to 0.0.0.0.
    app.run(host="127.0.0.1", port=5000, debug=False)
