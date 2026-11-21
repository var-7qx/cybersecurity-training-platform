import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from werkzeug.security import generate_password_hash

from app import app, db, close_db, init_db


class Phase1TelemetryTestCase(unittest.TestCase):
    def setUp(self):
        self.orig_db_path = app.config.get("DATABASE_PATH")
        # Configure app for testing with an explicit, ephemeral test SECRET_KEY
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = f"test-only-ephemeral-key-{secrets.token_hex(16)}"

        # Create an isolated temporary test database fixture
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_collections.db"
        app.config["DATABASE_PATH"] = self.test_db_path

        # Generate dynamic test credentials for this test execution
        self.admin_username = "test_admin"
        self.admin_password = f"Admin!{secrets.token_urlsafe(12)}"

        self.user_username = "test_user"
        self.user_password = f"User!{secrets.token_urlsafe(12)}"

        self.other_username = "test_other"
        self.other_password = f"Other!{secrets.token_urlsafe(12)}"

        # Seed isolated test database with 20 accounts and 4 collections
        conn = sqlite3.connect(self.test_db_path)
        init_db(conn)

        test_accounts = [
            (self.admin_username, generate_password_hash(self.admin_password), "Test Administrator", "admin"),
            (self.user_username, generate_password_hash(self.user_password), "Test Standard User", "user"),
            (self.other_username, generate_password_hash(self.other_password), "Test Other User", "user"),
            ("test_manager", generate_password_hash(secrets.token_urlsafe(12)), "Test Manager", "manager"),
            ("test_editor", generate_password_hash(secrets.token_urlsafe(12)), "Test Editor", "editor"),
        ]
        for i in range(1, 16):
            u = f"test_user{i:02d}"
            p = generate_password_hash(secrets.token_urlsafe(12))
            test_accounts.append((u, p, f"Test User {i:02d}", "user"))

        conn.executemany("INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)", test_accounts)

        admin_id = conn.execute("SELECT id FROM users WHERE username = ?", (self.admin_username,)).fetchone()[0]
        user_id = conn.execute("SELECT id FROM users WHERE username = ?", (self.user_username,)).fetchone()[0]
        other_id = conn.execute("SELECT id FROM users WHERE username = ?", (self.other_username,)).fetchone()[0]

        conn.execute("INSERT INTO collections (owner_id, title, category, description) VALUES (?, ?, ?, ?)",
                     (user_id, "User Wallpaper Archive", "Images", "Test wallpapers"))
        conn.execute("INSERT INTO collections (owner_id, title, category, description) VALUES (?, ?, ?, ?)",
                     (user_id, "User Learning Notes", "Documents", "Test notes"))
        conn.execute("INSERT INTO collections (owner_id, title, category, description) VALUES (?, ?, ?, ?)",
                     (other_id, "Other Private Album", "Images", "Private records belonging to other user"))
        conn.execute("INSERT INTO collections (owner_id, title, category, description) VALUES (?, ?, ?, ?)",
                     (admin_id, "Admin Operations Guide", "Documents", "Admin collections"))

        conn.commit()
        conn.close()

        self.client = app.test_client()

    def tearDown(self):
        with app.app_context():
            close_db()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        app.config["DATABASE_PATH"] = self.orig_db_path

    def _get_latest_audit_log(self):
        conn = sqlite3.connect(self.test_db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        return dict(row) if row else None

    # -------------------------------------------------------------
    # 1. Existing Login & RBAC Regression Tests
    # -------------------------------------------------------------
    def test_existing_accounts_and_password_hashes_preserved(self):
        """Verify all 20 synthetic accounts and baseline collections exist."""
        conn = sqlite3.connect(self.test_db_path)
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        collections_count = conn.execute("SELECT COUNT(*) FROM collections").fetchone()[0]
        conn.close()

        self.assertEqual(user_count, 20)
        self.assertEqual(collections_count, 4)

    def test_successful_login_behavior(self):
        """Admin can log in successfully and receives a redirect to dashboard."""
        resp = self.client.post("/login", data={"username": self.admin_username, "password": self.admin_password})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers.get("Location", ""))

        with self.client.session_transaction() as sess:
            self.assertIsNotNone(sess.get("user_id"))

    def test_failed_login_behavior(self):
        """Failed login displays generic error message and does not create session."""
        wrong_password = f"WrongPassword!{secrets.token_hex(4)}"
        resp = self.client.post("/login", data={"username": self.admin_username, "password": wrong_password}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid username or password.", resp.data)

        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("user_id"))

    def test_user_collections_scoped_to_owner(self):
        """Logged-in users only see their own collections."""
        self.client.post("/login", data={"username": self.user_username, "password": self.user_password})
        resp = self.client.get("/collections")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"User Wallpaper Archive", resp.data)
        self.assertIn(b"User Learning Notes", resp.data)
        self.assertNotIn(b"Other Private Album", resp.data)

    # -------------------------------------------------------------
    # 2. SOC Telemetry Event Capture Tests
    # -------------------------------------------------------------
    def test_login_success_telemetry(self):
        """login_success captures all 9 required fields."""
        custom_ua = "PentestLabBrowser/1.0 (Training Client)"
        resp = self.client.post(
            "/login",
            data={"username": self.admin_username, "password": self.admin_password},
            headers={"User-Agent": custom_ua},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        self.assertEqual(resp.status_code, 302)

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["event"], "login_success")
        self.assertEqual(log["username"], self.admin_username)
        self.assertEqual(log["remote_addr"], "127.0.0.1")
        self.assertEqual(log["http_method"], "POST")
        self.assertEqual(log["path"], "/login")
        self.assertEqual(log["status_code"], 302)
        self.assertIn("PentestLabBrowser", log["user_agent"])
        self.assertIsNotNone(log["created_at"])

    def test_login_failure_telemetry(self):
        """login_failure captures attempted username, path, method, and 200 status."""
        resp = self.client.post(
            "/login",
            data={"username": "test_user04", "password": "wrong_password_attempt"},
            headers={"User-Agent": "Hydra-Mock/9.1"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        self.assertEqual(resp.status_code, 200)

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["event"], "login_failure")
        self.assertEqual(log["username"], "test_user04")
        self.assertEqual(log["remote_addr"], "127.0.0.1")
        self.assertEqual(log["http_method"], "POST")
        self.assertEqual(log["path"], "/login")
        self.assertEqual(log["status_code"], 200)
        self.assertEqual(log["detail"], "Invalid username or password")
        self.assertEqual(log["user_agent"], "Hydra-Mock/9.1")

    def test_logout_telemetry(self):
        """logout captures event, username, and 302 redirect."""
        self.client.post("/login", data={"username": self.user_username, "password": self.user_password})
        resp = self.client.get("/logout")
        self.assertEqual(resp.status_code, 302)

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["event"], "logout")
        self.assertEqual(log["username"], self.user_username)
        self.assertEqual(log["http_method"], "GET")
        self.assertEqual(log["path"], "/logout")
        self.assertEqual(log["status_code"], 302)

    def test_unauthorized_admin_access_unauthenticated(self):
        """Unauthenticated request to /admin captures unauthorized_admin_access."""
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["event"], "unauthorized_admin_access")
        self.assertIsNone(log["username"])
        self.assertEqual(log["path"], "/admin")
        self.assertEqual(log["status_code"], 302)

    def test_unauthorized_admin_access_authenticated_non_admin(self):
        """Non-admin authenticated user requesting /admin triggers 403 and is logged."""
        self.client.post("/login", data={"username": self.user_username, "password": self.user_password})

        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 403)

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["event"], "unauthorized_admin_access")
        self.assertEqual(log["username"], self.user_username)
        self.assertEqual(log["path"], "/admin")
        self.assertEqual(log["status_code"], 403)
        self.assertIn("requires admin role", log["detail"])

    def test_not_found_telemetry(self):
        """404 events capture probe path, method, status code 404, and user agent."""
        resp = self.client.get(
            "/wp-admin/sensitive_config.php",
            headers={"User-Agent": "Feroxbuster/2.10.0"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        self.assertEqual(resp.status_code, 404)

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["event"], "not_found")
        self.assertEqual(log["path"], "/wp-admin/sensitive_config.php")
        self.assertEqual(log["http_method"], "GET")
        self.assertEqual(log["status_code"], 404)
        self.assertEqual(log["user_agent"], "Feroxbuster/2.10.0")

    # -------------------------------------------------------------
    # 3. Security Boundary: Header Spoofing Resistance
    # -------------------------------------------------------------
    def test_untrusted_client_ip_headers_ignored(self):
        """Ensure X-Forwarded-For, X-Real-IP, and Client-IP headers are NEVER trusted."""
        spoofed_headers = {
            "X-Forwarded-For": "203.0.113.195, 10.0.0.1",
            "X-Real-IP": "198.51.100.22",
            "Client-IP": "172.16.0.5",
            "User-Agent": "SpoofTest/1.0",
        }
        self.client.post(
            "/login",
            data={"username": self.admin_username, "password": "WrongPassword"},
            headers=spoofed_headers,
            environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )

        log = self._get_latest_audit_log()
        self.assertIsNotNone(log)
        self.assertEqual(log["remote_addr"], "127.0.0.1")
        self.assertNotIn("203.0.113.195", log["remote_addr"])
        self.assertNotIn("198.51.100.22", log["remote_addr"])

    # -------------------------------------------------------------
    # 4. Admin UI Visibility & Dedicated SOC Telemetry Page
    # -------------------------------------------------------------
    def test_admin_audit_log_source_ip_visibility(self):
        """Admin dashboard displays Source IP column and IP values."""
        self.client.post("/login", data={"username": self.admin_username, "password": self.admin_password})
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Source IP", resp.data)
        self.assertIn(b"Open SOC Telemetry", resp.data)
        self.assertIn(b"127.0.0.1", resp.data)

    def test_soc_telemetry_page_access_and_rendering(self):
        """Dedicated SOC telemetry page is accessible only to admin and renders full telemetry."""
        resp = self.client.get("/soc/telemetry")
        self.assertEqual(resp.status_code, 302)

        self.client.post("/login", data={"username": self.user_username, "password": self.user_password})
        resp = self.client.get("/soc/telemetry")
        self.assertEqual(resp.status_code, 403)
        self.client.get("/logout")

        self.client.post("/login", data={"username": self.admin_username, "password": self.admin_password})
        resp = self.client.get("/soc/telemetry")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Telemetry", resp.data)
        self.assertIn(b"TOTAL EVENTS", resp.data)
        self.assertIn(b"UNIQUE IPS", resp.data)
        self.assertIn(b"FAILED LOGINS", resp.data)
        self.assertIn(b"ADMIN PROBES", resp.data)
        self.assertIn(b"404 SCANS", resp.data)

        resp_filtered = self.client.get("/soc/telemetry?event=login_failure")
        self.assertEqual(resp_filtered.status_code, 200)


if __name__ == "__main__":
    unittest.main()
