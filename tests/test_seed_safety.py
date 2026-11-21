import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from seed import seed_database, generate_synthetic_password, ACCOUNT_DEFS


class SeedSecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_db = Path(self.temp_dir) / "test_lab.db"
        self.test_creds = Path(self.temp_dir) / "test_creds.txt"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fresh_database_initialization(self):
        """Fresh database initialization succeeds and seeds 20 accounts and 4 collections."""
        result = seed_database(target_db=self.test_db, credentials_path=self.test_creds)
        self.assertTrue(result)
        self.assertTrue(self.test_db.exists())
        self.assertTrue(self.test_creds.exists())

        con = sqlite3.connect(self.test_db)
        user_count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        coll_count = con.execute("SELECT COUNT(*) FROM collections").fetchone()[0]
        con.close()

        self.assertEqual(user_count, len(ACCOUNT_DEFS))
        self.assertEqual(coll_count, 4)

    def test_seed_safety_guard_on_existing_database(self):
        """Seeding on an already initialized database aborts without modifying records."""
        # First seed
        self.assertTrue(seed_database(target_db=self.test_db, credentials_path=self.test_creds))

        con = sqlite3.connect(self.test_db)
        orig_hashes = dict(con.execute("SELECT username, password_hash FROM users").fetchall())
        con.close()

        # Second seed attempt must abort
        second_result = seed_database(target_db=self.test_db, credentials_path=self.test_creds)
        self.assertFalse(second_result)

        # Verify password hashes were NOT overwritten
        con = sqlite3.connect(self.test_db)
        current_hashes = dict(con.execute("SELECT username, password_hash FROM users").fetchall())
        con.close()

        self.assertEqual(orig_hashes, current_hashes)

    def test_duplicate_username_fails_safely_without_overwriting(self):
        """Direct duplicate username insertion fails on UNIQUE constraint."""
        self.assertTrue(seed_database(target_db=self.test_db, credentials_path=self.test_creds))

        con = sqlite3.connect(self.test_db)
        admin_hash_before = con.execute("SELECT password_hash FROM users WHERE username = 'admin'").fetchone()[0]

        # Duplicate insert without ON CONFLICT DO UPDATE
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute(
                "INSERT INTO users(username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
                ("admin", "new_attacker_hash", "Admin", "admin")
            )

        admin_hash_after = con.execute("SELECT password_hash FROM users WHERE username = 'admin'").fetchone()[0]
        con.close()

        self.assertEqual(admin_hash_before, admin_hash_after)

    def test_fail_closed_on_database_verification_error(self):
        """If SQLite raises an error during inspection, seeding fails closed and aborts."""
        # Create a corrupt file
        self.test_db.write_text("This is not a valid SQLite database header!")

        result = seed_database(target_db=self.test_db, credentials_path=self.test_creds)
        self.assertFalse(result)

    def test_strong_passwords_generated_for_all_accounts(self):
        """Verify generated passwords have high entropy (at least 20 chars)."""
        for _ in range(30):
            pw = generate_synthetic_password()
            self.assertGreaterEqual(len(pw), 20)


if __name__ == "__main__":
    unittest.main()

