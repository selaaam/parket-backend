"""
notifications.py — Firebase Cloud Messaging helper.

Import-safe: all functions are no-ops when USE_FCM=false.
init_fcm() is called from app.py during startup.
"""
from __future__ import annotations

_messaging = None  # set by init_fcm() when USE_FCM=true


def init_fcm(firebase_app) -> None:
    global _messaging
    try:
        from firebase_admin import messaging
        _messaging = messaging
        print("[OK] FCM initialized")
    except Exception as e:
        print(f"[WARN] FCM init failed: {e}")


def send_fcm(token: str, title: str, body: str, data: dict | None = None) -> bool:
    """Send a single push notification. Returns True on success, False if disabled or error."""
    if not _messaging or not token:
        return False
    try:
        msg = _messaging.Message(
            notification=_messaging.Notification(title=title, body=body),
            data={str(k): str(v) for k, v in (data or {}).items()},
            token=token,
        )
        _messaging.send(msg)
        return True
    except Exception as e:
        print(f"[FCM] send error: {e}")
        return False


def notify_expiry_warning(token: str, plate: str, minutes: int) -> None:
    send_fcm(
        token,
        title=f"⏰ Parking expires in {minutes} min",
        body=f"Your session for {plate} ends soon. Extend or leave to avoid a fine.",
        data={"type": "expiry_warning", "plate": plate, "minutes": str(minutes)},
    )


def notify_payment_confirmed(token: str, plate: str, amount: int, reference: str) -> None:
    send_fcm(
        token,
        title="✅ Payment confirmed",
        body=f"Your parking for {plate} is active. Amount: {amount} ብር",
        data={"type": "payment_confirmed", "plate": plate, "reference": reference},
    )


def notify_violation_issued(token: str, plate: str, zone: str, amount: float) -> None:
    send_fcm(
        token,
        title="⚠️ Parking violation issued",
        body=f"A {amount:.0f} ብር fine was issued for {plate} at {zone}.",
        data={"type": "violation", "plate": plate, "zone": zone},
    )
