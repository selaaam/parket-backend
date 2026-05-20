"""
telebirr.py — TeleBirr payment integration (Ethio Telecom).

Setup checklist:
  1. Register at https://developerapi.ethiotelecom.et
  2. Create an app and note: App ID, App Key, Short Code
  3. Fill in .env:
       TELEBIRR_APP_ID=<your app id>
       TELEBIRR_APP_KEY=<your app key>
       TELEBIRR_SHORT_CODE=<your short code>
       TELEBIRR_NOTIFY_URL=https://<your domain>/api/payments/webhook
       TELEBIRR_SANDBOX_MODE=false
  4. Ensure the server is publicly reachable (TeleBirr POSTs to notify_url)

Payment flow:
  1. App → POST /api/payments/telebirr/initiate
       → backend calls TeleBirr checkOut
       → TeleBirr sends USSD push to user's phone
       → returns {order_id}
  2. App polls GET /api/payments/telebirr/status/<order_id>
  3. User approves USSD on phone
  4. TeleBirr POSTs to POST /api/payments/webhook
       → backend marks order paid + creates plate session
  5. App gets status='paid' from polling → creates SessionModel → navigates to /active
"""

import hashlib
import os
import time
import uuid

import requests as _rq

SANDBOX     = os.environ.get("TELEBIRR_SANDBOX_MODE", "true").lower() == "true"
APP_ID      = os.environ.get("TELEBIRR_APP_ID",      "").strip()
APP_KEY     = os.environ.get("TELEBIRR_APP_KEY",     "").strip()
SHORT_CODE  = os.environ.get("TELEBIRR_SHORT_CODE",  "").strip()
NOTIFY_URL  = os.environ.get("TELEBIRR_NOTIFY_URL",  "").strip()

# Ethio Telecom API base — update if they change the endpoint
_API_BASE = (
    "https://api.ethiotelecom.et/api"
    if SANDBOX
    else "https://api.trade.ethiotelecom.et/api"
)


def _sign(out_trade_no: str, timestamp: str, nonce: str) -> str:
    """SHA-256 signature over key fields (TeleBirr Developer API spec)."""
    raw = APP_ID + out_trade_no + timestamp + nonce + APP_KEY
    return hashlib.sha256(raw.encode()).hexdigest().upper()


def _normalize_msisdn(phone: str) -> str:
    """Convert any Ethiopian phone format to 251XXXXXXXXX."""
    digits = "".join(c for c in phone if c.isdigit())
    if digits.startswith("251") and len(digits) == 12:
        return digits
    if digits.startswith("0") and len(digits) == 10:
        return "251" + digits[1:]
    if len(digits) == 9:
        return "251" + digits
    return digits  # pass through; TeleBirr will validate


def is_configured() -> bool:
    return bool(APP_ID and APP_KEY and SHORT_CODE)


def initiate(phone: str, amount: int, order_id: str,
             subject: str = "ParkET Parking Fee") -> dict:
    """
    Initiate a TeleBirr payment.

    Returns dict with keys: order_id, out_trade_no, payment_url (may be empty).
    Raises RuntimeError on configuration or API errors.
    """
    if not is_configured():
        raise RuntimeError(
            "TeleBirr credentials not configured. "
            "Set TELEBIRR_APP_ID, TELEBIRR_APP_KEY, TELEBIRR_SHORT_CODE in .env"
        )
    if not NOTIFY_URL:
        raise RuntimeError(
            "TELEBIRR_NOTIFY_URL not set — TeleBirr cannot post payment confirmations. "
            "Set it to your public server URL, e.g. https://api.parket.et/api/payments/webhook"
        )

    timestamp    = str(int(time.time()))
    nonce        = uuid.uuid4().hex[:16]
    out_trade_no = f"PKT-{order_id}-{timestamp}"
    sign         = _sign(out_trade_no, timestamp, nonce)

    payload = {
        "appId":       APP_ID,
        "appKey":      APP_KEY,
        "nonce":       nonce,
        "timestamp":   timestamp,
        "sign":        sign,
        "msisdn":      _normalize_msisdn(phone),
        "amount":      str(amount),
        "orderId":     order_id,
        "outTradeNo":  out_trade_no,
        "subject":     subject,
        "shortCode":   SHORT_CODE,
        "notifyUrl":   NOTIFY_URL,
        "returnUrl":   "parket://payment/complete",
        "receiveName": "ParkET",
        "timeout":     300,
    }

    try:
        resp = _rq.post(f"{_API_BASE}/checkOut", json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except _rq.Timeout:
        raise RuntimeError("TeleBirr API request timed out")
    except _rq.RequestException as e:
        raise RuntimeError(f"TeleBirr API unreachable: {e}")

    code = str(data.get("code", ""))
    if code not in ("200", "0", "00000"):
        msg = data.get("message") or data.get("msg") or data.get("result") or "Unknown error"
        raise RuntimeError(f"TeleBirr error {code}: {msg}")

    result = data.get("result", data)
    return {
        "order_id":     order_id,
        "out_trade_no": out_trade_no,
        "payment_url":  result.get("toPayUrl", ""),
    }


def verify_webhook_sign(payload: dict) -> bool:
    """
    Verify the signature on an incoming webhook notification.
    Returns True if valid (or if APP_KEY is not set — dev/sandbox mode).
    """
    if not APP_KEY:
        return True
    trade_no  = str(payload.get("outTradeNo") or payload.get("tradeNo", ""))
    timestamp = str(payload.get("timestamp", ""))
    provided  = str(payload.get("sign", "")).upper()
    expected  = hashlib.sha256((trade_no + timestamp + APP_KEY).encode()).hexdigest().upper()
    return provided == expected
