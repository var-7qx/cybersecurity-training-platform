import os
import sys
import secrets
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parent
DB = ROOT / "instance" / "my_collections.db"

# Synthetic account definitions without hardcoded credentials.
# Passwords are cryptographically generated via Python's secrets module during initialization.
ACCOUNT_DEFS = [
    ("admin", "Administrator", "admin"),
    ("analyst", "Security Analyst", "user"),
    ("manager", "Collection Manager", "manager"),
    ("editor", "Content Editor", "editor"),
    ("guest", "Guest Account", "guest"),
    ("user01", "Test User 01", "user"),
    ("user02", "Test User 02", "user"),
    ("user03", "Test User 03", "user"),
    ("user04", "Test User 04", "user"),
    ("user05", "Test User 05", "user"),
    ("user06", "Test User 06", "user"),
    ("user07", "Test User 07", "user"),
    ("user08", "Test User 08", "user"),
    ("user09", "Test User 09", "user"),
    ("user10", "Test User 10", "user"),
    ("user11", "Test User 11", "user"),
    ("user12", "Test User 12", "user"),
    ("user13", "Test User 13", "user"),
    ("user14", "Test User 14", "user"),
    ("user15", "Test User 15", "user"),
]

def generate_synthetic_password():
    """
    Generate a cryptographically strong, high-entropy synthetic password
    using Python's secrets module for all accounts.
    """
    return secrets.token_urlsafe(20)

def seed_database(target_db=None, credentials_path=None):
    db_file = Path(target_db) if target_db else DB
    out_file = Path(credentials_path) if credentials_path else (ROOT / "LAB_CREDENTIALS.txt")

    # Safety guard: Check if database exists and already has active accounts
    if db_file.exists():
        try:
            uri_path = f"file:{db_file.resolve().as_posix()}?mode=ro"
            with sqlite3.connect(uri_path, uri=True) as check_con:
                table_check = check_con.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'"
                ).fetchone()[0]
                if table_check > 0:
                    count = check_con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                    if count > 0:
                        print(f"Safety Guard: Database at {db_file} already exists and contains {count} accounts.")
                        print("Aborting: will not modify, reset, or overwrite existing accounts or password hashes.")
                        print("To re-seed from scratch, stop the server, manually remove instance/my_collections.db, and re-run seed.py.")
                        return False
        except sqlite3.Error as e:
            print(f"Database safety check failed with error: {e}")
            print("Failing closed: cannot verify database safety. Aborting seed operation.")
            return False

    # Generate synthetic accounts and randomized strong credentials
    accounts = []
    for username, display_name, role in ACCOUNT_DEFS:
        password = generate_synthetic_password()
        accounts.append((username, password, display_name, role))

    db_file.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_file)
    try:
        with con:
            con.execute("PRAGMA foreign_keys = ON;")
            con.executescript("""
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
              remote_addr TEXT,
              http_method TEXT,
              path TEXT,
              status_code INTEGER,
              user_agent TEXT
            );
            """)

            # Safe inserts without ON CONFLICT DO UPDATE to protect existing accounts
            for username, password, display_name, role in accounts:
                con.execute(
                    "INSERT INTO users(username, password_hash, display_name, role) VALUES(?, ?, ?, ?)",
                    (username, generate_password_hash(password), display_name, role),
                )

            sample_collections = [
                ("analyst", "Wallpaper Archive", "Images", "Dummy wallpapers for access-control practice."),
                ("analyst", "Learning Notes", "Documents", "Synthetic notes for the local lab."),
                ("user01", "Private Album", "Images", "Dummy record belonging to user01."),
                ("manager", "Project Assets", "Files", "Synthetic manager-owned sample."),
            ]
            for username, title, category, desc in sample_collections:
                owner_row = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                if owner_row:
                    con.execute(
                        "INSERT INTO collections(owner_id, title, category, description) VALUES(?, ?, ?, ?)",
                        (owner_row[0], title, category, desc),
                    )
    except sqlite3.Error as err:
        print(f"Transaction failed during seed operation: {err}")
        print("Transaction rolled back: no records were modified.")
        con.close()
        return False
    finally:
        con.close()

    # Plaintext credentials are written ONLY to the local lab file (excluded by .gitignore).
    # Passwords are never printed to stdout or console.
    out_file.write_text(
        "MY COLLECTIONS - LOCAL LAB CREDENTIALS\n"
        "Synthetic accounts only. Do not reuse these passwords anywhere.\n"
        "Keep this file private and never commit/upload it.\n\n" +
        "\n".join(f"{u:<10} {p:<30} role={r}" for u, p, _, r in accounts) + "\n",
        encoding="utf-8",
    )
    print(f"Seeded {len(accounts)} test accounts with strong synthetic credentials.")
    print(f"Credentials saved locally to: {out_file.name}")
    print(f"Database: {db_file.name}")
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print("Error: seed.py does not accept command-line options.")
        print("To seed a fresh lab, delete instance/my_collections.db first and run: python seed.py")
        sys.exit(1)
    success = seed_database()
    if not success:
        sys.exit(1)
