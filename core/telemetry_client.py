"""
CYBER_WRAITH: Telemetry Client Helper (Phase A)
Standardized cryptographic client for signing and dispatching telemetry events
from spoke applications to the Central CYBER_WRAITH SOC ingestion API.
"""

import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import urllib.request
import urllib.error

# Standardized Application Identifiers
CW_PLATFORM = "cw_platform"
CW_ECOMMERCE = "cw_ecommerce"
CW_BOOKING = "cw_booking"
CW_BANKING = "cw_banking"
CW_SOCIAL = "cw_social"

VALID_APP_IDS = {
    CW_PLATFORM,
    CW_ECOMMERCE,
    CW_BOOKING,
    CW_BANKING,
    CW_SOCIAL,
}

VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def generate_event_id() -> str:
    """Generates a cryptographically random UUIDv4 event identifier."""
    return str(uuid.uuid4())


def get_current_iso_timestamp() -> str:
    """Returns the current UTC timestamp formatted as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def build_canonical_string(timestamp: str, app_id: str, event_id: str, raw_body: str) -> str:
    """
    Constructs the canonical string representation for HMAC-SHA256 signature calculation.
    Format: {timestamp}.{app_id}.{event_id}.{raw_body}
    """
    return f"{timestamp}.{app_id}.{event_id}.{raw_body}"


def compute_signature(secret: str, timestamp: str, app_id: str, event_id: str, raw_body: str) -> str:
    """
    Computes an HMAC-SHA256 signature over the canonical telemetry string.
    Returns: 'v1=<hex_signature>'
    """
    canonical = build_canonical_string(timestamp, app_id, event_id, raw_body)
    sig_hex = hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"v1={sig_hex}"


def verify_signature(
    secret: str,
    timestamp: str,
    app_id: str,
    event_id: str,
    raw_body: str,
    presented_signature: str,
) -> bool:
    """
    Verifies an HMAC-SHA256 signature using constant-time comparison.
    """
    if not secret or not presented_signature:
        return False
    expected_sig = compute_signature(secret, timestamp, app_id, event_id, raw_body)
    return hmac.compare_digest(expected_sig, presented_signature)


class TelemetryClient:
    """
    Client for transmitting signed security telemetry events to Central SOC.
    """

    def __init__(self, app_id: str, secret: str, endpoint_url: str = "http://127.0.0.1:5000/api/v1/soc/ingest"):
        if app_id not in VALID_APP_IDS:
            raise ValueError(f"Invalid app_id '{app_id}'. Must be one of: {sorted(VALID_APP_IDS)}")
        if not secret:
            raise ValueError("Secret key must not be empty.")
        self.app_id = app_id
        self._secret = secret
        self.endpoint_url = endpoint_url

    def build_payload(
        self,
        event_type: str,
        username: Optional[str] = None,
        source_ip: str = "127.0.0.1",
        http_method: str = "POST",
        path: str = "/",
        status_code: Optional[int] = 200,
        user_agent: str = "",
        severity: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        iso_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Constructs a validated telemetry payload dictionary."""
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}")

        evt_id = event_id or generate_event_id()
        ts = iso_timestamp or get_current_iso_timestamp()

        return {
            "event_id": evt_id,
            "timestamp": ts,
            "app_id": self.app_id,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "http_method": http_method,
            "path": path,
            "status_code": status_code,
            "user_agent": user_agent,
            "severity": severity,
            "details": details or {},
        }

    def send_event(
        self,
        event_type: str,
        username: Optional[str] = None,
        source_ip: str = "127.0.0.1",
        http_method: str = "POST",
        path: str = "/",
        status_code: Optional[int] = 200,
        user_agent: str = "",
        severity: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Signs and dispatches a telemetry event via HTTP POST.
        """
        payload = self.build_payload(
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            http_method=http_method,
            path=path,
            status_code=status_code,
            user_agent=user_agent,
            severity=severity,
            details=details,
            event_id=event_id,
        )

        raw_body = json.dumps(payload, separators=(",", ":"))
        timestamp_header = str(int(time.time()))
        event_id_header = payload["event_id"]
        signature_header = compute_signature(
            secret=self._secret,
            timestamp=timestamp_header,
            app_id=self.app_id,
            event_id=event_id_header,
            raw_body=raw_body,
        )

        headers = {
            "Content-Type": "application/json",
            "X-CW-App-ID": self.app_id,
            "X-CW-Timestamp": timestamp_header,
            "X-CW-Event-ID": event_id_header,
            "X-CW-Signature": signature_header,
        }

        req = urllib.request.Request(
            self.endpoint_url,
            data=raw_body.encode("utf-8"),
            headers=headers,
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            resp_body = response.read().decode("utf-8")
            return json.loads(resp_body)

