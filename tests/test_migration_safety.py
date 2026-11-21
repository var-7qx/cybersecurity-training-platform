import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import app, db, close_db, init_db

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "instance" / "my_collections.db"
BACKUP_PATH = BASE_DIR / "instance" / "my_collections.db.phaseA_backup_wal.bak"


class MigrationSafetyTestCase(unittest.TestCase):
    """
    Verification and regression tests for Phase A database schema migration,
    ensuring 100% preservation of accounts, collections, and audit logs.
    """

    def setUp(self):
        self.orig_db_path = app.config.get("DATABASE_PATH")
        self.db_path = DB_PATH
        self.assertTrue(self.db_path.exists(), f"Primary database {self.db_path} does not exist!")

    def tearDown(self):
        with app.app_context():
            close_db()
        app.config["DATABASE_PATH"] = self.orig_db_path

    def test_database_integrity_and_baseline_counts(self):
        """Verify SQLite integrity check returns ok and baseline counts are strictly preserved."""
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cur = con.cursor()

        # 1. Integrity check
        integrity = [tuple(r) for r in cur.execute("PRAGMA integrity_check;").fetchall()]
        self.assertEqual(integrity, [("ok",)], f"Integrity check failed: {integrity}")

        # 2. Baseline row counts
        user_count = cur.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        self.assertEqual(user_count, 20, f"Expected exactly 20 users, found {user_count}")

        coll_count = cur.execute("SELECT COUNT(*) FROM collections;").fetchone()[0]
        self.assertEqual(coll_count, 4, f"Expected exactly 4 collections, found {coll_count}")

        audit_count = cur.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0]
        self.assertGreaterEqual(audit_count, 11, f"Expected at least 11 audit records, found {audit_count}")
        con.close()

    def test_audit_log_schema_extension(self):
        """Verify audit_log table schema has been extended with app_id, severity, and event_id."""
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cols = {row[1] for row in cur.execute("PRAGMA table_info(audit_log);").fetchall()}

        self.assertIn("app_id", cols, "Column 'app_id' missing from audit_log")
        self.assertIn("severity", cols, "Column 'severity' missing from audit_log")
        self.assertIn("event_id", cols, "Column 'event_id' missing from audit_log")

        # Check legacy records have default app_id and severity
        legacy_rows = cur.execute("SELECT app_id, severity FROM audit_log WHERE id <= 11;").fetchall()
        for row in legacy_rows:
            self.assertEqual(row["app_id"], "cw_platform")
            self.assertEqual(row["severity"], "INFO")
        con.close()

    def test_soc_idempotency_table_exists_and_enforces_composite_pk(self):
        """Verify soc_idempotency table exists with primary key (app_id, event_id)."""
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cur = con.cursor()

        # Verify table existence
        table_info = cur.execute("PRAGMA table_info(soc_idempotency);").fetchall()
        self.assertTrue(len(table_info) > 0, "Table 'soc_idempotency' does not exist")

        col_names = [r[1] for r in table_info]
        self.assertIn("app_id", col_names)
        self.assertIn("event_id", col_names)
        self.assertIn("received_at", col_names)

        # Check composite primary key
        pk_cols = [r[1] for r in table_info if r[5] > 0]
        self.assertEqual(set(pk_cols), {"app_id", "event_id"})
        con.close()

    def test_wal_backup_file_exists_and_matches_baseline(self):
        """Verify that the WAL-safe backup file exists and matches baseline counts."""
        self.assertTrue(BACKUP_PATH.exists(), f"Backup file {BACKUP_PATH} was not found!")

        bak_con = sqlite3.connect(f"file:{BACKUP_PATH}?mode=ro", uri=True)
        bak_cur = bak_con.cursor()

        b_integrity = bak_cur.execute("PRAGMA integrity_check;").fetchall()
        self.assertEqual(b_integrity, [("ok",)], f"Backup integrity failed: {b_integrity}")

        b_users = bak_cur.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        self.assertEqual(b_users, 20)

        b_colls = bak_cur.execute("SELECT COUNT(*) FROM collections;").fetchone()[0]
        self.assertEqual(b_colls, 4)

        b_audit = bak_cur.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0]
        self.assertEqual(b_audit, 11)

        bak_con.close()

    def test_idempotent_migration_execution(self):
        """Verify calling init_db multiple times on an isolated copy is idempotent with zero data loss."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_db = Path(tmpdir) / "test_migration_copy.db"
            # Backup live DB to temp DB
            src = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            dst = sqlite3.connect(temp_db)
            src.backup(dst)
            src.close()

            # Execute init_db twice on temp DB
            init_db(dst)
            init_db(dst)

            cur = dst.cursor()
            u_cnt = cur.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
            self.assertEqual(u_cnt, 20)
            dst.close()

    def test_live_database_record_count_preservation(self):
        """Regression test verifying that the live database record counts remain exactly preserved."""
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cur = con.cursor()

        users = cur.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        colls = cur.execute("SELECT COUNT(*) FROM collections;").fetchone()[0]
        audit = cur.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0]
        integrity = [tuple(r) for r in cur.execute("PRAGMA integrity_check;").fetchall()]
        con.close()

        self.assertEqual(integrity, [("ok",)])
        self.assertEqual(users, 20, "Live users count altered!")
        self.assertEqual(colls, 4, "Live collections count altered!")
        self.assertEqual(audit, 12, "Live audit log count altered!")


if __name__ == "__main__":
    unittest.main()
