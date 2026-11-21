import json
import shutil
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from app import app, db, close_db, init_db
from core.telemetry_client import (
    CW_BANKING,
    CW_ECOMMERCE,
    CW_PLATFORM,
    CW_SOCIAL,
    TelemetryClient,
    compute_signature,
    generate_event_id,
    verify_signature,
)

BASE_DIR = Path(__file__).resolve().parent.parent
LIVE_DB_PATH = BASE_DIR / "instance" / "my_collections.db"

TEST_ECOM_SECRET = "test_ecommerce_secret_key_32_bytes_len!!"
TEST_BANK_SECRET = "test_banking_secret_key_32_bytes_length!"
TEST_PLATFORM_SECRET = "test_platform_secret_key_32_bytes_len!!"


class SocIngestionTestCase(unittest.TestCase):
    """
    Unit and integration tests for Central SOC Telemetry Ingestion API,
    HMAC authentication, timestamp freshness, schema validation, payload hardening,
    and strict database isolation.
    """

    def setUp(self):
        # 1. Isolate test database: save original DB path and create dedicated temporary DB
        self.orig_db_path = app.config.get("DATABASE_PATH")
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_soc_ingest.db"
        app.config["DATABASE_PATH"] = self.test_db_path

        # Initialize schema on isolated test database
        with app.app_context():
            conn = sqlite3.connect(self.test_db_path)
            init_db(conn)
            conn.close()

        app.config["TESTING"] = True
        app.config["SOC_SECRETS"] = {
            CW_ECOMMERCE: TEST_ECOM_SECRET,
            CW_BANKING: TEST_BANK_SECRET,
            CW_PLATFORM: TEST_PLATFORM_SECRET,
            # CW_SOCIAL intentionally omitted to test fail-closed behavior
        }
        self.client = app.test_client()

    def tearDown(self):
        with app.app_context():
            close_db()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        # Restore original database configuration
        app.config["DATABASE_PATH"] = self.orig_db_path

    def _make_ingest_request(
        self,
        app_id=CW_ECOMMERCE,
        secret=TEST_ECOM_SECRET,
        payload=None,
        timestamp_header=None,
        event_id_header=None,
        signature_header=None,
        headers_override=None,
        content_type="application/json",
        raw_body_override=None,
    ):
        """Helper to construct signed telemetry POST requests."""
        event_id = event_id_header or generate_event_id()
        ts = timestamp_header if timestamp_header is not None else str(int(time.time()))

        if raw_body_override is not None:
            raw_body = raw_body_override
        elif payload is not None:
            raw_body = json.dumps(payload, separators=(",", ":"))
        else:
            payload = {
                "event_id": event_id,
                "timestamp": "2026-11-21T10:30:00Z",
                "app_id": app_id,
                "event_type": "checkout_failure",
                "username": "shopper_42",
                "source_ip": "198.51.100.22",
                "http_method": "POST",
                "path": "/checkout",
                "status_code": 402,
                "user_agent": "Mozilla/5.0 TestBrowser",
                "severity": "MEDIUM",
                "details": {"cart_id": "cart_999", "error": "insufficient_funds"},
            }
            raw_body = json.dumps(payload, separators=(",", ":"))

        sig = signature_header or (compute_signature(secret, ts, app_id, event_id, raw_body) if secret else "v1=none")

        headers = {
            "Content-Type": content_type,
            "X-CW-App-ID": app_id,
            "X-CW-Timestamp": ts,
            "X-CW-Event-ID": event_id,
            "X-CW-Signature": sig,
        }

        if headers_override:
            for k, v in headers_override.items():
                if v is None:
                    headers.pop(k, None)
                else:
                    headers[k] = v

        return self.client.post("/api/v1/soc/ingest", data=raw_body, headers=headers)

    def test_valid_soc_ingest_success(self):
        """Verify successful event ingestion creates record in isolated test database."""
        evt_id = f"test_evt_{uuid.uuid4().hex[:12]}"
        resp = self._make_ingest_request(event_id_header=evt_id)
        self.assertEqual(resp.status_code, 201)

        data = resp.get_json()
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["event_id"], evt_id)

        with app.app_context():
            row = db().execute(
                "SELECT * FROM audit_log WHERE event_id = ?",
                (evt_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["app_id"], CW_ECOMMERCE)
            self.assertEqual(row["severity"], "MEDIUM")
            self.assertEqual(row["event"], "checkout_failure")
            self.assertEqual(row["username"], "shopper_42")
            self.assertEqual(row["remote_addr"], "198.51.100.22")

            # Check idempotency table
            idem = db().execute(
                "SELECT * FROM soc_idempotency WHERE app_id = ? AND event_id = ?",
                (CW_ECOMMERCE, evt_id),
            ).fetchone()
            self.assertIsNotNone(idem)

    def test_missing_required_headers(self):
        """Ensure missing any required authentication header returns 400 Bad Request."""
        for header in ["X-CW-App-ID", "X-CW-Timestamp", "X-CW-Event-ID", "X-CW-Signature"]:
            resp = self._make_ingest_request(headers_override={header: None})
            self.assertEqual(resp.status_code, 400, f"Expected 400 when missing header {header}")
            self.assertIn("Missing required authentication headers", resp.get_json()["error"])

    def test_invalid_app_id_header(self):
        """Ensure unregistered application ID returns 400 Bad Request."""
        resp = self._make_ingest_request(app_id="unregistered_spoke_app")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid application identifier", resp.get_json()["error"])

    def test_timestamp_freshness_validation(self):
        """Ensure timestamps outside 300s skew window or malformed timestamps are rejected."""
        # 301 seconds in the past
        past_ts = str(int(time.time()) - 305)
        resp = self._make_ingest_request(timestamp_header=past_ts)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Timestamp outside acceptable skew window", resp.get_json()["error"])

        # 301 seconds in the future
        future_ts = str(int(time.time()) + 305)
        resp = self._make_ingest_request(timestamp_header=future_ts)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Timestamp outside acceptable skew window", resp.get_json()["error"])

        # Non-numeric timestamp
        resp = self._make_ingest_request(timestamp_header="not_a_timestamp")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid timestamp format", resp.get_json()["error"])

    def test_header_payload_identity_matching(self):
        """Ensure mismatch between headers and payload fields is strictly rejected."""
        evt_id = generate_event_id()

        # 1. App ID mismatch
        mismatched_app_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_BANKING,  # Mismatch with CW_ECOMMERCE header
            "event_type": "funds_transfer",
            "severity": "HIGH",
        }
        resp = self._make_ingest_request(
            app_id=CW_ECOMMERCE,
            event_id_header=evt_id,
            payload=mismatched_app_payload,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Header X-CW-App-ID does not match payload app_id", resp.get_json()["error"])

        # 2. Event ID mismatch
        mismatched_evt_payload = {
            "event_id": "payload_evt_different",
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "checkout_failure",
            "severity": "LOW",
        }
        resp = self._make_ingest_request(
            app_id=CW_ECOMMERCE,
            event_id_header=evt_id,
            payload=mismatched_evt_payload,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Header X-CW-Event-ID does not match payload event_id", resp.get_json()["error"])

    def test_schema_validation(self):
        """Verify missing event_type or invalid severity is rejected."""
        evt_id = generate_event_id()

        # Missing event_type
        payload_no_event = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(payload=payload_no_event, event_id_header=evt_id)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'event_type' must be a non-empty string", resp.get_json()["error"])

        # Invalid severity
        payload_bad_sev = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "test_event",
            "severity": "SUPER_CRITICAL",
        }
        resp = self._make_ingest_request(payload=payload_bad_sev, event_id_header=evt_id)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid severity level", resp.get_json()["error"])

    def test_fail_closed_when_secret_unconfigured(self):
        """Ensure applications without configured secrets fail closed with 401 Unauthorized."""
        # CW_SOCIAL secret is intentionally not in SOC_SECRETS
        resp = self._make_ingest_request(app_id=CW_SOCIAL, secret="some_dummy_secret")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("secret not configured", resp.get_json()["error"])

    def test_invalid_hmac_signature(self):
        """Ensure tampered or incorrect HMAC signatures return 401 Unauthorized."""
        evt_id = generate_event_id()
        resp = self._make_ingest_request(
            event_id_header=evt_id,
            signature_header="v1=0000000000000000000000000000000000000000000000000000000000000000",
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid HMAC signature", resp.get_json()["error"])

    def test_idempotency_duplicate_event_rejection(self):
        """Verify submitting identical (app_id, event_id) twice returns 409 Conflict."""
        duplicate_evt_id = f"dup_test_{uuid.uuid4().hex[:10]}"

        # First ingestion -> 201 Created
        resp1 = self._make_ingest_request(event_id_header=duplicate_evt_id)
        self.assertEqual(resp1.status_code, 201)

        # Immediate second ingestion with same (app_id, event_id) -> 409 Conflict
        resp2 = self._make_ingest_request(event_id_header=duplicate_evt_id)
        self.assertEqual(resp2.status_code, 409)
        self.assertIn("Duplicate event detected", resp2.get_json()["error"])

    def test_idempotency_scoped_to_app_id(self):
        """Verify the same event_id is permissible across different app_ids."""
        shared_evt_id = f"shared_id_{uuid.uuid4().hex[:10]}"

        # Ingest under E-Commerce
        resp_ecom = self._make_ingest_request(
            app_id=CW_ECOMMERCE,
            secret=TEST_ECOM_SECRET,
            event_id_header=shared_evt_id,
        )
        self.assertEqual(resp_ecom.status_code, 201)

        # Ingest under Banking with same event_id -> Should succeed because uniqueness is (app_id, event_id)
        resp_bank = self._make_ingest_request(
            app_id=CW_BANKING,
            secret=TEST_BANK_SECRET,
            event_id_header=shared_evt_id,
        )
        self.assertEqual(resp_bank.status_code, 201)

    def test_telemetry_client_helper_methods(self):
        """Verify TelemetryClient helper constructs and validates signatures correctly."""
        client = TelemetryClient(CW_ECOMMERCE, TEST_ECOM_SECRET)
        payload = client.build_payload(
            event_type="test_probe",
            username="analyst_test",
            severity="HIGH",
            details={"ip_check": "passed"},
        )
        self.assertEqual(payload["app_id"], CW_ECOMMERCE)
        self.assertEqual(payload["severity"], "HIGH")

        raw = json.dumps(payload, separators=(",", ":"))
        ts = str(int(time.time()))
        sig = compute_signature(TEST_ECOM_SECRET, ts, CW_ECOMMERCE, payload["event_id"], raw)

        # Verify correct signature
        self.assertTrue(verify_signature(TEST_ECOM_SECRET, ts, CW_ECOMMERCE, payload["event_id"], raw, sig))
        # Verify incorrect secret fails
        self.assertFalse(verify_signature("wrong_secret", ts, CW_ECOMMERCE, payload["event_id"], raw, sig))

    # =========================================================================
    # Phase A Remediation Tests: Ingestion Hardening & Isolation
    # =========================================================================

    def test_unsupported_content_type_rejection(self):
        """Ensure endpoint rejects non-JSON Content-Type with HTTP 415."""
        resp = self._make_ingest_request(
            content_type="text/plain",
            headers_override={"Content-Type": "text/plain"},
        )
        self.assertEqual(resp.status_code, 415)
        self.assertIn("Content-Type must be application/json", resp.get_json()["error"])

    def test_oversized_payload_rejection(self):
        """Ensure payloads exceeding MAX_CONTENT_LENGTH (1 MB) are rejected with HTTP 413."""
        evt_id = generate_event_id()
        # Create a payload larger than 1 MB
        oversized_blob = "A" * (1024 * 1024 + 100)
        oversized_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "large_dump",
            "severity": "INFO",
            "details": {"blob": oversized_blob},
        }
        resp = self._make_ingest_request(
            event_id_header=evt_id,
            payload=oversized_payload,
        )
        self.assertEqual(resp.status_code, 413)

    def test_text_field_length_limits(self):
        """Ensure text fields exceeding configured maximum lengths are rejected with HTTP 400."""
        evt_id = generate_event_id()

        # 1. username > 100 chars
        bad_user_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "username": "U" * 101,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_user_payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'username' exceeds maximum length", resp.get_json()["error"])

        # 2. event_type > 100 chars
        bad_evt_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "E" * 101,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_evt_payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'event_type' exceeds maximum length", resp.get_json()["error"])

        # 3. path > 250 chars
        bad_path_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "path": "/" + "P" * 250,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_path_payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'path' exceeds maximum length", resp.get_json()["error"])

        # 4. source_ip > 45 chars
        bad_ip_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "source_ip": "1" * 46,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_ip_payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'source_ip' exceeds maximum length", resp.get_json()["error"])

        # 5. user_agent > 250 chars
        bad_ua_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "user_agent": "A" * 251,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_ua_payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'user_agent' exceeds maximum length", resp.get_json()["error"])

        # 6. details > 250 chars
        bad_details_payload = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "details": {"msg": "D" * 250},
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_details_payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'details' exceeds maximum length", resp.get_json()["error"])

    def test_invalid_field_types(self):
        """Ensure non-conforming field types are rejected with HTTP 400."""
        evt_id = generate_event_id()

        # Non-string username
        bad_type_user = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "username": 12345,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_type_user)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'username' must be a string or null", resp.get_json()["error"])

        # Non-integer status_code
        bad_type_status = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "status_code": "200_OK",
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_type_status)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'status_code' must be an integer", resp.get_json()["error"])

        # Boolean status_code (should be rejected as non-integer status code)
        bad_bool_status = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "status_code": True,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_bool_status)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'status_code' must be an integer", resp.get_json()["error"])

        # Out-of-bounds status_code (< 100 or > 599)
        bad_range_status = {
            "event_id": evt_id,
            "timestamp": "2026-11-21T10:30:00Z",
            "app_id": CW_ECOMMERCE,
            "event_type": "valid_event",
            "status_code": 999,
            "severity": "INFO",
        }
        resp = self._make_ingest_request(event_id_header=evt_id, payload=bad_range_status)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Field 'status_code' must be an integer between 100 and 599", resp.get_json()["error"])

    def test_test_database_isolation(self):
        """Verify test ingestion writes only to isolated temporary DB, not live DB."""
        evt_id = f"iso_test_{uuid.uuid4().hex[:10]}"
        resp = self._make_ingest_request(event_id_header=evt_id)
        self.assertEqual(resp.status_code, 201)

        # 1. Assert record exists in the test DB
        test_con = sqlite3.connect(self.test_db_path)
        test_row = test_con.execute("SELECT * FROM audit_log WHERE event_id = ?", (evt_id,)).fetchone()
        test_con.close()
        self.assertIsNotNone(test_row, "Record should exist in temporary test database")

        # 2. Assert record DOES NOT exist in the live database
        live_con = sqlite3.connect(f"file:{LIVE_DB_PATH}?mode=ro", uri=True)
        live_row = live_con.execute("SELECT * FROM audit_log WHERE event_id = ?", (evt_id,)).fetchone()
        live_con.close()
        self.assertIsNone(live_row, "Test event MUST NOT be written to the live production database!")


if __name__ == "__main__":
    unittest.main()
