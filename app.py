from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import datetime, timedelta
from dotenv import load_dotenv
import bcrypt
import jwt
import os

load_dotenv()

from db_adapter import get_db, IntegrityError
from database import init_db
from plate_utils import normalize_plate, validate_plate, classify_plate
import json
import threading
import time

app = Flask(__name__)

# ─── Config ──────────────────────────────────────────────────────────────────

import secrets as _secrets
JWT_SECRET = os.environ.get("JWT_SECRET") or _secrets.token_hex(32)
JWT_EXPIRY_HOURS = 24

CORS(app,
     origins="*",
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)

# ─── Firebase Admin SDK (USE_FIREBASE_AUTH and/or USE_FCM) ───────────────────

USE_FIREBASE_AUTH = os.environ.get("USE_FIREBASE_AUTH", "false").lower() == "true"
USE_FCM           = os.environ.get("USE_FCM",           "false").lower() == "true"

_firebase_auth = None

if USE_FIREBASE_AUTH or USE_FCM:
    try:
        import firebase_admin
        from firebase_admin import credentials
        sa_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT", "").strip()
        if sa_path and os.path.exists(sa_path):
            _cred = credentials.Certificate(sa_path)
            firebase_admin.initialize_app(_cred)
            if USE_FIREBASE_AUTH:
                from firebase_admin import auth as _fb_auth
                _firebase_auth = _fb_auth
                print("[OK] Firebase Auth initialized")
            if USE_FCM:
                from notifications import init_fcm
                init_fcm(firebase_admin.get_app())
        else:
            print("[WARN] Firebase enabled but FIREBASE_SERVICE_ACCOUNT path is missing or invalid")
    except Exception as _e:
        print(f"[WARN] Firebase Admin init failed: {_e}")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def row_to_dict(row):
    return dict(row) if row else None

def rows_to_list(rows):
    return [dict(r) for r in rows]

def make_token(user):
    payload = {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token manquant"}), 401
        token = auth_header.split(" ")[1]

        # Try Firebase ID token first when Firebase is enabled
        if _firebase_auth:
            try:
                decoded = _firebase_auth.verify_id_token(token)
                request.user = {
                    "id":           decoded.get("uid"),
                    "email":        decoded.get("email", ""),
                    "role":         decoded.get("role", "user"),
                    "zone_id":      decoded.get("zone_id"),
                    "firebase_uid": decoded.get("uid"),
                }
                return f(*args, **kwargs)
            except Exception:
                pass  # Fall through to JWT

        # JWT fallback (always active)
        try:
            request.user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expiré"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token invalide"}), 403
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @require_auth
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.user.get("role") not in roles:
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

require_admin        = require_role("admin")
require_warden_admin = require_role("warden", "admin")


# ─── FCM expiry checker ───────────────────────────────────────────────────────

def _check_expiring_sessions():
    """Runs every 60 s. Sends 15-min and 5-min expiry warnings via FCM."""
    if not USE_FCM:
        return
    from notifications import notify_expiry_warning
    db = get_db()
    try:
        rows = db.execute("""
            SELECT p.id, p.plate_number, p.entry_time, p.duration_minutes,
                   p.expiry_notified_15, p.expiry_notified_5, f.token
            FROM plates p
            JOIN fcm_tokens f ON f.plate_id = p.id
            WHERE p.exit_time IS NULL
              AND p.duration_minutes IS NOT NULL
              AND (p.expiry_notified_15 = 0 OR p.expiry_notified_5 = 0)
        """).fetchall()

        now = datetime.now()
        for s in rows:
            try:
                entry = datetime.fromisoformat(str(s["entry_time"])[:19])
            except Exception:
                continue
            expiry = entry + timedelta(minutes=s["duration_minutes"])
            mins_left = (expiry - now).total_seconds() / 60

            if 13 <= mins_left <= 17 and not s["expiry_notified_15"]:
                notify_expiry_warning(s["token"], s["plate_number"], 15)
                db.execute("UPDATE plates SET expiry_notified_15=1 WHERE id=?", (s["id"],))
                db.commit()

            if 3 <= mins_left <= 7 and not s["expiry_notified_5"]:
                notify_expiry_warning(s["token"], s["plate_number"], 5)
                db.execute("UPDATE plates SET expiry_notified_5=1 WHERE id=?", (s["id"],))
                db.commit()
    finally:
        db.close()


def _expiry_checker_loop():
    while True:
        try:
            _check_expiring_sessions()
        except Exception as _e:
            print(f"[WARN] Expiry check error: {_e}")
        time.sleep(60)


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return jsonify({"service": "ParkET API", "version": "2.0", "status": "running",
                    "docs": "/api/health"})

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
@limiter.limit("5 per 15 minutes")
def login():
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email et mot de passe requis"}), 400

    db = get_db()
    user = row_to_dict(db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone())
    db.close()

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Identifiants incorrects"}), 401

    token = make_token(user)
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "role": user["role"]}
    })

@app.post("/api/auth/logout")
def logout():
    return jsonify({"message": "Déconnecté"})


@app.post("/api/auth/firebase/link")
@require_auth
def firebase_link():
    """Link a Firebase UID to the calling user's account (admin or warden)."""
    data = request.json or {}
    firebase_uid = (data.get("firebase_uid") or "").strip()
    if not firebase_uid:
        return jsonify({"error": "firebase_uid required"}), 400

    user = request.user
    role = user.get("role")
    db = get_db()
    try:
        if role == "warden":
            db.execute("UPDATE wardens SET firebase_uid=? WHERE id=?",
                       (firebase_uid, user["id"]))
        else:
            db.execute("UPDATE users SET firebase_uid=? WHERE id=?",
                       (firebase_uid, user["id"]))
        db.commit()
    finally:
        db.close()
    return jsonify({"message": "Firebase UID linked"})


@app.post("/api/admin/claims")
@require_admin
def set_firebase_claims():
    """Set custom claims (role, zone_id) on a Firebase user — admin only."""
    if not _firebase_auth:
        return jsonify({"error": "Firebase Auth is not enabled on this server"}), 501

    data = request.json or {}
    uid   = (data.get("uid") or "").strip()
    role  = (data.get("role") or "user").strip()
    zone_id = data.get("zone_id")

    if not uid:
        return jsonify({"error": "uid required"}), 400
    if role not in ("admin", "warden", "user"):
        return jsonify({"error": "role must be admin, warden, or user"}), 400

    try:
        claims = {"role": role}
        if zone_id is not None:
            claims["zone_id"] = zone_id
        _firebase_auth.set_custom_user_claims(uid, claims)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "Claims set", "uid": uid, "claims": claims})

@app.post("/api/auth/warden/login")
@limiter.limit("5 per 15 minutes")
def warden_login():
    data = request.json or {}
    badge = (data.get("badge_number") or "").strip().upper()
    password = data.get("password", "")
    if not badge or not password:
        return jsonify({"error": "Badge number and password required"}), 400

    db = get_db()
    warden = row_to_dict(db.execute("""
        SELECT w.*, z.name zone_name FROM wardens w
        LEFT JOIN zones z ON w.zone_id = z.id
        WHERE w.badge_number = ? AND w.active = 1
    """, (badge,)).fetchone())
    db.close()

    if not warden:
        return jsonify({"error": "Invalid credentials"}), 401
    if not warden.get("password_hash"):
        return jsonify({"error": "Account not set up — contact your supervisor to set your PIN"}), 401
    if not bcrypt.checkpw(password.encode(), warden["password_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "id":           warden["id"],
        "badge_number": warden["badge_number"],
        "name":         warden["name"],
        "role":         "warden",
        "zone_id":      warden["zone_id"],
        "exp":          datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({
        "token": token,
        "warden": {
            "id":           warden["id"],
            "name":         warden["name"],
            "badge_number": warden["badge_number"],
            "zone_id":      warden["zone_id"],
            "zone_name":    warden["zone_name"],
        },
    })


# ─── Dashboard ───────────────────────────────────────────────────────────────

@app.get("/api/dashboard")
@require_admin
def dashboard():
    db = get_db()
    today = datetime.now().strftime("%Y-%m-%d")

    def q(sql, *params):
        return db.execute(sql, params).fetchone()

    def qa(sql, *params):
        return rows_to_list(db.execute(sql, params).fetchall())

    result = {
        "activeZones":      q("SELECT COUNT(*) c FROM zones WHERE active=1")["c"],
        "activeWardens":    q("SELECT COUNT(*) c FROM wardens WHERE active=1")["c"],
        "ticketsToday":     q("SELECT COUNT(*) c FROM tickets WHERE DATE(issued_at)=?", today)["c"],
        "revenueToday":     q("SELECT COALESCE(SUM(amount),0) t FROM payments WHERE DATE(paid_at)=?", today)["t"],
        "unpaidTickets":    row_to_dict(q("SELECT COUNT(*) count, COALESCE(SUM(amount),0) total FROM tickets WHERE status='unpaid'")),
        "contestedTickets": q("SELECT COUNT(*) c FROM tickets WHERE status='contested'")["c"],
        "currentlyParked":  q("SELECT COUNT(*) c FROM plates WHERE exit_time IS NULL")["c"],
        "ticketsLast7Days": qa("""
            SELECT DATE(issued_at) day, COUNT(*) count, SUM(amount) amount
            FROM tickets WHERE issued_at >= DATE('now','-7 days')
            GROUP BY DATE(issued_at) ORDER BY day
        """),
        "recentTickets": qa("""
            SELECT t.*, w.name warden_name, z.name zone_name
            FROM tickets t
            LEFT JOIN wardens w ON t.warden_id=w.id
            LEFT JOIN zones z ON t.zone_id=z.id
            ORDER BY t.issued_at DESC LIMIT 5
        """),
        "topWardens": qa("""
            SELECT w.name, w.badge_number, COUNT(t.id) ticket_count
            FROM wardens w
            LEFT JOIN tickets t ON t.warden_id=w.id
            WHERE DATE(t.issued_at) >= DATE('now','-30 days')
            GROUP BY w.id ORDER BY ticket_count DESC LIMIT 5
        """),
    }
    db.close()
    return jsonify(result)


# ─── Zones ───────────────────────────────────────────────────────────────────

@app.get("/api/zones")
@require_admin
def get_zones():
    db = get_db()
    zones = rows_to_list(db.execute("""
        SELECT z.*,
          (SELECT COUNT(*) FROM plates p WHERE p.zone_id=z.id AND p.exit_time IS NULL) present_count
        FROM zones z ORDER BY z.active DESC, z.name
    """).fetchall())
    db.close()
    return jsonify(zones)

@app.get("/api/zones/<int:zone_id>")
@require_admin
def get_zone(zone_id):
    db = get_db()
    zone = row_to_dict(db.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone())
    db.close()
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    return jsonify(zone)

@app.post("/api/zones")
@require_admin
def create_zone():
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Zone name required"}), 400
    db = get_db()
    c = db.execute(
        "INSERT INTO zones (name, address, capacity, hourly_rate) VALUES (?,?,?,?)",
        (name, data.get("address", ""), data.get("capacity", 0), data.get("hourly_rate", 100))
    )
    zone = row_to_dict(db.execute("SELECT * FROM zones WHERE id=?", (c.lastrowid,)).fetchone())
    db.commit(); db.close()
    return jsonify(zone), 201

@app.put("/api/zones/<int:zone_id>")
@require_admin
def update_zone(zone_id):
    db = get_db()
    z = row_to_dict(db.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone())
    if not z:
        db.close(); return jsonify({"error": "Zone not found"}), 404
    data = request.json or {}
    db.execute(
        "UPDATE zones SET name=?,address=?,capacity=?,hourly_rate=?,active=? WHERE id=?",
        (data.get("name", z["name"]), data.get("address", z["address"]),
         data.get("capacity", z["capacity"]), data.get("hourly_rate", z["hourly_rate"]),
         data.get("active", z["active"]), zone_id)
    )
    zone = row_to_dict(db.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone())
    db.commit(); db.close()
    return jsonify(zone)

@app.delete("/api/zones/<int:zone_id>")
@require_admin
def delete_zone(zone_id):
    db = get_db()
    db.execute("UPDATE zones SET active=0 WHERE id=?", (zone_id,))
    db.commit(); db.close()
    return jsonify({"message": "Zone removed"})


# ─── Wardens ─────────────────────────────────────────────────────────────────

@app.get("/api/wardens")
@require_admin
def get_wardens():
    db = get_db()
    wardens = rows_to_list(db.execute("""
        SELECT w.*, z.name zone_name,
          (SELECT COUNT(*) FROM tickets t WHERE t.warden_id=w.id) total_tickets
        FROM wardens w LEFT JOIN zones z ON w.zone_id=z.id ORDER BY w.name
    """).fetchall())
    db.close()
    return jsonify(wardens)

@app.get("/api/wardens/<int:warden_id>")
@require_admin
def get_warden(warden_id):
    db = get_db()
    w = row_to_dict(db.execute("""
        SELECT w.*, z.name zone_name FROM wardens w
        LEFT JOIN zones z ON w.zone_id=z.id WHERE w.id=?
    """, (warden_id,)).fetchone())
    if not w:
        db.close(); return jsonify({"error": "Agent non trouvé"}), 404
    tickets = rows_to_list(db.execute("""
        SELECT t.*, z.name zone_name FROM tickets t
        LEFT JOIN zones z ON t.zone_id=z.id
        WHERE t.warden_id=? ORDER BY t.issued_at DESC LIMIT 50
    """, (warden_id,)).fetchall())
    db.close()
    return jsonify({**w, "tickets": tickets})

@app.post("/api/wardens")
@require_admin
def create_warden():
    data = request.json or {}
    if not data.get("name") or not data.get("badge_number"):
        return jsonify({"error": "Nom et badge requis"}), 400
    db = get_db()
    try:
        c = db.execute("INSERT INTO wardens (name,email,phone,badge_number,zone_id) VALUES (?,?,?,?,?)",
                       (data["name"], data.get("email"), data.get("phone"),
                        data["badge_number"], data.get("zone_id")))
        w = row_to_dict(db.execute("SELECT * FROM wardens WHERE id=?", (c.lastrowid,)).fetchone())
        db.commit(); db.close()
        return jsonify(w), 201
    except IntegrityError:
        db.close()
        return jsonify({"error": "Badge ou email déjà utilisé"}), 409

@app.put("/api/wardens/<int:warden_id>")
@require_admin
def update_warden(warden_id):
    db = get_db()
    w = row_to_dict(db.execute("SELECT * FROM wardens WHERE id=?", (warden_id,)).fetchone())
    if not w:
        db.close(); return jsonify({"error": "Agent non trouvé"}), 404
    data = request.json or {}
    db.execute("UPDATE wardens SET name=?,email=?,phone=?,badge_number=?,zone_id=?,active=? WHERE id=?",
               (data.get("name",w["name"]), data.get("email",w["email"]), data.get("phone",w["phone"]),
                data.get("badge_number",w["badge_number"]), data.get("zone_id",w["zone_id"]),
                data.get("active",w["active"]), warden_id))
    result = row_to_dict(db.execute("SELECT * FROM wardens WHERE id=?", (warden_id,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)

@app.delete("/api/wardens/<int:warden_id>")
@require_admin
def delete_warden(warden_id):
    db = get_db()
    db.execute("UPDATE wardens SET active=0 WHERE id=?", (warden_id,))
    db.commit(); db.close()
    return jsonify({"message": "Agent désactivé"})


# ─── Plates ──────────────────────────────────────────────────────────────────

@app.get("/api/plates")
@require_admin
def get_plates():
    db = get_db()
    q = "SELECT p.*, z.name zone_name FROM plates p LEFT JOIN zones z ON p.zone_id=z.id WHERE 1=1"
    params = []
    if request.args.get("zone_id"):
        q += " AND p.zone_id=?"; params.append(request.args["zone_id"])
    if request.args.get("date"):
        q += " AND DATE(p.entry_time)=?"; params.append(request.args["date"])
    if request.args.get("active") == "true":
        q += " AND p.exit_time IS NULL"
    q += " ORDER BY p.entry_time DESC LIMIT 200"
    plates = rows_to_list(db.execute(q, params).fetchall())
    db.close()
    return jsonify(plates)

@app.post("/api/plates")
@require_admin
def create_plate():
    data = request.json or {}
    if not data.get("plate_number"):
        return jsonify({"error": "Numéro de plaque requis"}), 400
    plate_number = data["plate_number"].strip().upper()
    normalized = normalize_plate(plate_number)
    db = get_db()
    c = db.execute("INSERT INTO plates (plate_number, normalized, zone_id, entry_time) VALUES (?,?,?,CURRENT_TIMESTAMP)",
                   (plate_number, normalized, data.get("zone_id")))
    p = row_to_dict(db.execute("SELECT * FROM plates WHERE id=?", (c.lastrowid,)).fetchone())
    db.commit(); db.close()
    return jsonify(p), 201

@app.put("/api/plates/<int:plate_id>/exit")
@require_admin
def plate_exit(plate_id):
    db = get_db()
    p = row_to_dict(db.execute("SELECT * FROM plates WHERE id=?", (plate_id,)).fetchone())
    if not p:
        db.close(); return jsonify({"error": "Entrée non trouvée"}), 404
    if p["exit_time"]:
        db.close(); return jsonify({"error": "Sortie déjà enregistrée"}), 400
    db.execute("UPDATE plates SET exit_time=CURRENT_TIMESTAMP WHERE id=?", (plate_id,))
    result = row_to_dict(db.execute("SELECT * FROM plates WHERE id=?", (plate_id,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)


@app.delete("/api/plates/all")
@require_admin
def clear_all_plates():
    db = get_db()
    count = db.execute("SELECT COUNT(*) c FROM plates").fetchone()["c"]
    db.execute("DELETE FROM plates")
    db.execute("DELETE FROM fcm_tokens")
    db.commit(); db.close()
    return jsonify({"cleared": count, "message": f"Cleared {count} plate entries"})


# ─── Tickets ─────────────────────────────────────────────────────────────────

VALID_STATUSES = ['unpaid', 'paid', 'contested', 'cancelled']

@app.get("/api/tickets")
@require_admin
def get_tickets():
    db = get_db()
    q = """
        SELECT t.*, w.name warden_name, w.badge_number, z.name zone_name
        FROM tickets t
        LEFT JOIN wardens w ON t.warden_id=w.id
        LEFT JOIN zones z ON t.zone_id=z.id WHERE 1=1
    """
    params = []
    if request.args.get("status"):
        q += " AND t.status=?"; params.append(request.args["status"])
    if request.args.get("warden_id"):
        q += " AND t.warden_id=?"; params.append(request.args["warden_id"])
    if request.args.get("zone_id"):
        q += " AND t.zone_id=?"; params.append(request.args["zone_id"])
    if request.args.get("date_from"):
        q += " AND DATE(t.issued_at)>=?"; params.append(request.args["date_from"])
    if request.args.get("date_to"):
        q += " AND DATE(t.issued_at)<=?"; params.append(request.args["date_to"])
    if request.args.get("plate"):
        q += " AND t.plate_number LIKE ?"; params.append(f"%{normalize_plate(request.args['plate'])}%")
    q += " ORDER BY t.issued_at DESC LIMIT 500"
    tickets = rows_to_list(db.execute(q, params).fetchall())
    db.close()
    return jsonify(tickets)

@app.get("/api/tickets/<int:ticket_id>")
@require_admin
def get_ticket(ticket_id):
    db = get_db()
    t = row_to_dict(db.execute("""
        SELECT t.*, w.name warden_name, w.badge_number, z.name zone_name,
          p.amount payment_amount, p.method payment_method, p.paid_at, p.reference
        FROM tickets t
        LEFT JOIN wardens w ON t.warden_id=w.id
        LEFT JOIN zones z ON t.zone_id=z.id
        LEFT JOIN payments p ON p.ticket_id=t.id
        WHERE t.id=?
    """, (ticket_id,)).fetchone())
    db.close()
    if not t:
        return jsonify({"error": "Ticket non trouvé"}), 404
    return jsonify(t)

@app.post("/api/tickets")
@require_admin
def create_ticket():
    data = request.json or {}
    if not data.get("plate_number") or not data.get("amount"):
        return jsonify({"error": "Plaque et montant requis"}), 400
    db = get_db()
    c = db.execute("""
        INSERT INTO tickets (plate_id, warden_id, zone_id, plate_number, reason, amount)
        VALUES (?,?,?,?,?,?)
    """, (data.get("plate_id"), data.get("warden_id"), data.get("zone_id"),
          normalize_plate(data["plate_number"]), data.get("reason"), data["amount"]))
    t = row_to_dict(db.execute("SELECT * FROM tickets WHERE id=?", (c.lastrowid,)).fetchone())
    db.commit(); db.close()
    return jsonify(t), 201

@app.put("/api/tickets/<int:ticket_id>")
@require_admin
def update_ticket(ticket_id):
    data = request.json or {}
    if "status" in data and data["status"] not in VALID_STATUSES:
        return jsonify({"error": f"Statut invalide. Valeurs: {', '.join(VALID_STATUSES)}"}), 400
    db = get_db()
    t = row_to_dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())
    if not t:
        db.close(); return jsonify({"error": "Ticket non trouvé"}), 404
    # Recalculate total amount if fine_amount or parking_fee changed
    new_fine    = float(data["fine_amount"])    if "fine_amount"  in data else (t.get("fine_amount")  or t["amount"])
    new_parking = float(data["parking_fee"])    if "parking_fee"  in data else (t.get("parking_fee")  or 0)
    new_amount  = new_fine + new_parking
    db.execute("""
        UPDATE tickets SET
          status=?, reason=?, amount=?,
          fine_amount=?, parking_fee=?,
          user_phone=?, notes=?,
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
    """, (
        data.get("status",     t["status"]),
        data.get("reason",     t["reason"]),
        new_amount,
        new_fine,
        new_parking,
        data.get("user_phone", t.get("user_phone")),
        data.get("notes",      t.get("notes")),
        ticket_id,
    ))
    result = row_to_dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)


@app.post("/api/tickets/<int:ticket_id>/send-notice")
@require_admin
def send_notice(ticket_id):
    db = get_db()
    t = row_to_dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())
    if not t:
        db.close(); return jsonify({"error": "Ticket not found"}), 404
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    db.execute("UPDATE tickets SET notice_sent_at=?, updated_at=? WHERE id=?",
               (now, now, ticket_id))
    db.commit(); db.close()
    return jsonify({"ok": True, "notice_sent_at": now})


@app.post("/api/tickets/<int:ticket_id>/issue-warrant")
@require_admin
def issue_warrant(ticket_id):
    db = get_db()
    t = row_to_dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())
    if not t:
        db.close(); return jsonify({"error": "Ticket not found"}), 404
    if t.get("warrant_number"):
        db.close(); return jsonify({"ok": True, "warrant_number": t["warrant_number"],
                                    "warrant_issued_at": t["warrant_issued_at"]})
    # Generate warrant number: PW-YYYY-NNNNN
    year = datetime.now().year
    count = db.execute("SELECT COUNT(*) c FROM tickets WHERE warrant_number IS NOT NULL").fetchone()["c"]
    warrant_number = f"PW-{year}-{str(count + 1).zfill(5)}"
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    db.execute("UPDATE tickets SET warrant_number=?, warrant_issued_at=?, updated_at=? WHERE id=?",
               (warrant_number, now, now, ticket_id))
    db.commit(); db.close()
    return jsonify({"ok": True, "warrant_number": warrant_number, "warrant_issued_at": now})


# ─── Payments ────────────────────────────────────────────────────────────────

@app.get("/api/payments")
@require_admin
def get_payments():
    db = get_db()
    q = """
        SELECT p.*, t.plate_number, t.reason, t.amount ticket_amount, z.name zone_name
        FROM payments p JOIN tickets t ON p.ticket_id=t.id
        LEFT JOIN zones z ON t.zone_id=z.id WHERE 1=1
    """
    params = []
    if request.args.get("date_from"):
        q += " AND DATE(p.paid_at)>=?"; params.append(request.args["date_from"])
    if request.args.get("date_to"):
        q += " AND DATE(p.paid_at)<=?"; params.append(request.args["date_to"])
    if request.args.get("method"):
        q += " AND p.method=?"; params.append(request.args["method"])
    q += " ORDER BY p.paid_at DESC LIMIT 500"
    payments = rows_to_list(db.execute(q, params).fetchall())
    db.close()
    return jsonify(payments)

@app.get("/api/payments/summary")
@require_admin
def payments_summary():
    db = get_db()

    def q(sql, *params):
        return row_to_dict(db.execute(sql, params).fetchone())

    result = {
        "today":   q("SELECT COALESCE(SUM(amount),0) total, COUNT(*) count FROM payments WHERE DATE(paid_at)=DATE('now')"),
        "week":    q("SELECT COALESCE(SUM(amount),0) total, COUNT(*) count FROM payments WHERE paid_at>=DATE('now','-7 days')"),
        "month":   q("SELECT COALESCE(SUM(amount),0) total, COUNT(*) count FROM payments WHERE strftime('%Y-%m',paid_at)=strftime('%Y-%m','now')"),
        "byDay":   rows_to_list(db.execute("SELECT DATE(paid_at) day, SUM(amount) total, COUNT(*) count FROM payments WHERE paid_at>=DATE('now','-30 days') GROUP BY DATE(paid_at) ORDER BY day").fetchall()),
        "byMethod":rows_to_list(db.execute("SELECT method, SUM(amount) total, COUNT(*) count FROM payments GROUP BY method").fetchall()),
        "unpaidCount": q("SELECT COUNT(*) count, COALESCE(SUM(amount),0) total FROM tickets WHERE status='unpaid'"),
    }
    db.close()
    return jsonify(result)

@app.post("/api/payments")
@require_admin
def create_payment():
    data = request.json or {}
    if not data.get("ticket_id") or not data.get("amount"):
        return jsonify({"error": "ticket_id et montant requis"}), 400
    VALID_METHODS = ['cash', 'card', 'online']
    method = data.get("method", "cash")
    if method not in VALID_METHODS:
        return jsonify({"error": f"Méthode invalide: {', '.join(VALID_METHODS)}"}), 400

    db = get_db()
    t = db.execute("SELECT * FROM tickets WHERE id=?", (data["ticket_id"],)).fetchone()
    if not t:
        db.close(); return jsonify({"error": "Ticket non trouvé"}), 404

    c = db.execute("INSERT INTO payments (ticket_id, amount, method, reference) VALUES (?,?,?,?)",
                   (data["ticket_id"], data["amount"], method, data.get("reference")))
    db.execute("UPDATE tickets SET status='paid',updated_at=CURRENT_TIMESTAMP WHERE id=?", (data["ticket_id"],))
    p = row_to_dict(db.execute("SELECT * FROM payments WHERE id=?", (c.lastrowid,)).fetchone())
    db.commit(); db.close()
    return jsonify(p), 201


# ─── Violations ──────────────────────────────────────────────────────────────

@app.post("/api/violations")
@require_warden_admin
def create_violation():
    data = request.json or {}
    raw_plate = (data.get("plate_number") or "").strip()
    plate_info = classify_plate(raw_plate)
    plate = plate_info['normalized'] if plate_info['valid'] else normalize_plate(raw_plate)
    if not plate or not data.get("amount"):
        return jsonify({"error": "plate_number and amount required"}), 400
    if not plate_info['valid']:
        return jsonify({"error": "Invalid plate format. Supported: 2 AA 12345, 01 AA A12345, UN 12345, AU 54321, TT 99999"}), 400

    warden_id = data.get("warden_id") or request.user.get("id")
    evidence_raw = data.get("evidence")
    evidence_json = json.dumps(evidence_raw) if evidence_raw is not None else None
    fine_amount = float(data["amount"])
    parking_fee = float(data.get("parking_fee", 0) or 0)
    total_amount = fine_amount + parking_fee

    db = get_db()
    cur = db.execute("""
        INSERT INTO tickets
          (plate_number, warden_id, zone_id, reason, amount, violation_type,
           gps_lat, gps_lng, evidence,
           parking_fee, fine_amount, user_phone, notes, entry_time, duration_minutes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        normalize_plate(plate),
        warden_id,
        data.get("zone_id"),
        data.get("reason"),
        total_amount,
        data.get("violation_type"),
        data.get("gps_lat"),
        data.get("gps_lng"),
        evidence_json,
        parking_fee,
        fine_amount,
        (data.get("user_phone") or "").strip() or None,
        data.get("notes"),
        data.get("entry_time"),
        data.get("duration_minutes"),
    ))
    ticket = row_to_dict(db.execute("""
        SELECT t.*, w.name warden_name, z.name zone_name
        FROM tickets t
        LEFT JOIN wardens w ON t.warden_id=w.id
        LEFT JOIN zones z ON t.zone_id=z.id
        WHERE t.id=?
    """, (cur.lastrowid,)).fetchone())
    db.commit()

    # Notify the plate owner if they have an active session with an FCM token
    if USE_FCM:
        try:
            norm = normalize_plate(plate)
            row = db.execute("""
                SELECT f.token FROM fcm_tokens f
                JOIN plates p ON p.id = f.plate_id
                WHERE p.normalized = ? AND p.exit_time IS NULL
                LIMIT 1
            """, (norm,)).fetchone()
            if row:
                from notifications import notify_violation_issued
                notify_violation_issued(row["token"], plate,
                                        ticket.get("zone_name", ""), data["amount"])
        except Exception:
            pass

    db.close()
    return jsonify(ticket), 201

@app.get("/api/violations")
@require_warden_admin
def get_violations():
    db = get_db()
    q = """
        SELECT t.*, w.name warden_name, w.badge_number, z.name zone_name
        FROM tickets t
        LEFT JOIN wardens w ON t.warden_id=w.id
        LEFT JOIN zones z ON t.zone_id=z.id WHERE 1=1
    """
    params = []
    # Wardens can only see their own violations
    if request.user.get("role") == "warden":
        q += " AND t.warden_id=?"; params.append(request.user["id"])
    if request.args.get("plate"):
        q += " AND t.plate_number LIKE ?"; params.append(f"%{normalize_plate(request.args['plate'])}%")
    if request.args.get("status"):
        q += " AND t.status=?"; params.append(request.args["status"])
    if request.args.get("zone_id"):
        q += " AND t.zone_id=?"; params.append(request.args["zone_id"])
    if request.args.get("warden_id") and request.user.get("role") == "admin":
        q += " AND t.warden_id=?"; params.append(request.args["warden_id"])
    if request.args.get("date_from"):
        q += " AND DATE(t.issued_at)>=?"; params.append(request.args["date_from"])
    q += " ORDER BY t.issued_at DESC LIMIT 200"
    violations = rows_to_list(db.execute(q, params).fetchall())
    db.close()
    return jsonify(violations)

# ─── Warden: request admin to issue warrant ──────────────────────────────────
@app.post("/api/tickets/<int:ticket_id>/request-warrant")
@require_warden_admin
def ticket_request_warrant(ticket_id):
    """Warden flags a ticket as needing a warrant. Admin sees it and escalates."""
    db = get_db()
    row = db.execute("SELECT id, status FROM tickets WHERE id=?", (ticket_id,)).fetchone()
    if not row:
        db.close(); return jsonify({"error": "Ticket not found"}), 404
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    db.execute(
        "UPDATE tickets SET status='warrant_requested', updated_at=? WHERE id=?",
        (now, ticket_id))
    db.commit(); db.close()
    return jsonify({"ok": True, "status": "warrant_requested"})


# ─── Request TeleBirr payment for a violation ticket ─────────────────────────
@app.post("/api/tickets/<int:ticket_id>/request-payment")
@require_warden_admin
def ticket_request_payment(ticket_id):
    """
    Initiate a TeleBirr USSD payment push for an unpaid violation ticket.
    Body: { "phone": "09XXXXXXXX" }
    Returns: { "order_id": "...", "sandbox": true/false }
    """
    from telebirr import initiate as tb_initiate, is_configured
    data  = request.json or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone required"}), 400

    db = get_db()
    row = db.execute("""
        SELECT t.*, z.name zone_name FROM tickets t
        LEFT JOIN zones z ON z.id=t.zone_id WHERE t.id=?
    """, (ticket_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "Ticket not found"}), 404
    ticket = dict(row)
    if ticket["status"] == "paid":
        db.close()
        return jsonify({"error": "Ticket already paid"}), 400

    amount   = int(float(ticket["amount"] or 0))
    plate_no = ticket["plate_number"]
    order_id = f"VIO-{ticket_id}-{int(datetime.utcnow().timestamp() * 1000)}"

    if not is_configured():
        # Dev / sandbox mode — store order but skip real TeleBirr call
        db.execute(
            "INSERT OR IGNORE INTO telebirr_orders"
            " (order_id, out_trade_no, plate_number, phone, amount, ticket_id, status)"
            " VALUES (?,?,?,?,?,?,'pending')",
            (order_id, order_id, plate_no, phone, amount, ticket_id))
        db.execute("UPDATE tickets SET telebirr_order_id=?, user_phone=? WHERE id=?",
                   (order_id, phone, ticket_id))
        db.commit(); db.close()
        return jsonify({"order_id": order_id, "sandbox": True})

    try:
        result = tb_initiate(
            phone=phone, amount=amount, order_id=order_id,
            subject=f"ParkET Fine – {plate_no}")
    except RuntimeError as e:
        db.close()
        return jsonify({"error": str(e)}), 502

    db.execute(
        "INSERT OR IGNORE INTO telebirr_orders"
        " (order_id, out_trade_no, plate_number, phone, amount, ticket_id, status)"
        " VALUES (?,?,?,?,?,?,'pending')",
        (order_id, result["out_trade_no"], plate_no, phone, amount, ticket_id))
    db.execute("UPDATE tickets SET telebirr_order_id=?, user_phone=? WHERE id=?",
               (order_id, phone, ticket_id))
    db.commit(); db.close()
    return jsonify({"order_id": order_id, "sandbox": False})


# ─── Warrants list ───────────────────────────────────────────────────────────
@app.get("/api/tickets/warrants")
@require_admin
def get_warrants():
    """Return all tickets with an issued warrant, newest first."""
    db = get_db()
    rows = db.execute("""
        SELECT t.id, t.plate_number, t.warrant_number, t.warrant_issued_at,
               t.reason, t.amount, t.status, t.user_phone,
               w.name warden_name, z.name zone_name, t.issued_at, t.notes
        FROM tickets t
        LEFT JOIN wardens w ON t.warden_id=w.id
        LEFT JOIN zones z ON t.zone_id=z.id
        WHERE t.warrant_number IS NOT NULL
        ORDER BY t.warrant_issued_at DESC
    """).fetchall()
    db.close()
    return jsonify(rows_to_list(rows))


# ─── Mobile: check violations for a plate (no auth — public lookup) ───────────
@app.get("/api/mobile/violations/<plate>")
def mobile_violations(plate):
    plate = plate.strip().upper()
    if not plate:
        return jsonify({"error": "plate required"}), 400
    db = get_db()
    try:
        rows = db.execute("""
            SELECT t.id, t.plate_number, t.violation_type, t.reason,
                   t.amount, t.parking_fee, t.fine_amount, t.status,
                   t.issued_at, t.entry_time, t.duration_minutes,
                   t.notice_sent_at, t.warrant_number, t.warrant_issued_at,
                   z.name AS zone_name
            FROM tickets t
            LEFT JOIN zones z ON z.id = t.zone_id
            WHERE UPPER(REPLACE(t.plate_number, ' ', '')) = UPPER(REPLACE(?, ' ', ''))
            ORDER BY t.issued_at DESC
            LIMIT 50
        """, (plate,)).fetchall()
        return jsonify(rows_to_list(rows))
    finally:
        db.close()

# ─── Warden: active sessions (all currently parked vehicles) ─────────────────
@app.get("/api/warden/active-sessions")
@require_warden_admin
def warden_active_sessions():
    db = get_db()
    sessions = rows_to_list(db.execute("""
        SELECT p.id, p.plate_number, p.normalized, p.entry_time,
               p.duration_minutes, p.session_cost, p.payment_phone,
               z.name zone_name, z.id zone_id
        FROM plates p
        LEFT JOIN zones z ON z.id = p.zone_id
        WHERE p.exit_time IS NULL
        ORDER BY p.entry_time DESC
    """).fetchall())
    db.close()
    return jsonify(sessions)

# ─── Warden: check plate status before issuing violation ─────────────────────
@app.get("/api/warden/check-plate/<plate>")
@require_warden_admin
def warden_check_plate(plate):
    plate = plate.strip().upper()
    norm  = normalize_plate(plate)
    db    = get_db()
    try:
        row = db.execute("""
            SELECT p.id, p.plate_number, p.entry_time, p.duration_minutes,
                   p.exit_time, z.name AS zone_name
            FROM plates p
            LEFT JOIN zones z ON z.id = p.zone_id
            WHERE UPPER(REPLACE(p.plate_number, ' ', '')) = UPPER(REPLACE(?, ' ', ''))
              AND p.exit_time IS NULL
            ORDER BY p.entry_time DESC
            LIMIT 1
        """, (plate,)).fetchone()

        if not row:
            return jsonify({"status": "no_session", "plate": plate})

        r = dict(row)
        entry_str = str(r["entry_time"])[:19]
        try:
            entry = datetime.fromisoformat(entry_str)
        except ValueError:
            return jsonify({"status": "no_session", "plate": plate})

        if r["duration_minutes"]:
            expiry    = entry + timedelta(minutes=int(r["duration_minutes"]))
            now       = datetime.now()
            if now > expiry:
                expired_mins = int((now - expiry).total_seconds() / 60)
                return jsonify({
                    "status":              "expired",
                    "plate":               plate,
                    "zone_name":           r["zone_name"] or "",
                    "entry_time":          entry_str,
                    "expiry_time":         expiry.strftime("%Y-%m-%dT%H:%M:%S"),
                    "expired_minutes_ago": expired_mins,
                })
            else:
                mins_left = int((expiry - now).total_seconds() / 60)
                return jsonify({
                    "status":       "active",
                    "plate":        plate,
                    "zone_name":    r["zone_name"] or "",
                    "entry_time":   entry_str,
                    "expiry_time":  expiry.strftime("%Y-%m-%dT%H:%M:%S"),
                    "minutes_left": mins_left,
                })
        else:
            return jsonify({
                "status":      "active",
                "plate":       plate,
                "zone_name":   r["zone_name"] or "",
                "entry_time":  entry_str,
                "expiry_time": None,
                "minutes_left": None,
            })
    finally:
        db.close()

@app.post("/api/wardens/<int:warden_id>/set-password")
@require_admin
def set_warden_password(warden_id):
    data = request.json or {}
    password = (data.get("password") or "").strip()
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    db.execute("UPDATE wardens SET password_hash=? WHERE id=?", (pw_hash, warden_id))
    db.commit(); db.close()
    return jsonify({"message": "Password updated"})


# ─── FCM Token Registration ──────────────────────────────────────────────────

@app.post("/api/mobile/fcm-token")
def register_mobile_fcm_token():
    """Link an FCM token to an active parking session (no auth required)."""
    data = request.json or {}
    plate_id = data.get("plate_id")
    token    = (data.get("token") or "").strip()
    if not plate_id or not token:
        return jsonify({"error": "plate_id and token required"}), 400
    db = get_db()
    db.execute("""
        INSERT OR IGNORE INTO fcm_tokens (plate_id, token) VALUES (?,?)
    """, (plate_id, token))
    db.execute("""
        UPDATE fcm_tokens SET token=? WHERE plate_id=?
    """, (token, plate_id))
    db.commit(); db.close()
    return jsonify({"message": "Token registered"})


@app.post("/api/warden/fcm-token")
@require_auth
def register_warden_fcm_token():
    """Link an FCM token to the authenticated warden account."""
    data = request.json or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "token required"}), 400
    warden_id = request.user.get("id")
    db = get_db()
    db.execute("INSERT OR IGNORE INTO fcm_tokens (warden_id, token) VALUES (?,?)",
               (warden_id, token))
    db.execute("UPDATE fcm_tokens SET token=? WHERE warden_id=?", (token, warden_id))
    db.commit(); db.close()
    return jsonify({"message": "Token registered"})


# ─── Public / Mobile ─────────────────────────────────────────────────────────

@app.get("/api/public/zones")
def public_zones():
    db = get_db()
    zones = rows_to_list(db.execute(
        "SELECT id, name, address, capacity, hourly_rate FROM zones WHERE active=1 ORDER BY name"
    ).fetchall())
    db.close()
    return jsonify(zones)

@app.post("/api/mobile/sessions")
def mobile_start_session():
    data = request.json or {}
    raw = (data.get("plate_number") or "").strip()
    info = classify_plate(raw)
    plate_number = info['normalized'] if info['valid'] else normalize_plate(raw)
    if not plate_number:
        return jsonify({"error": "plate_number required or invalid format"}), 400
    normalized = plate_number
    # Prefer explicitly-passed vehicle_category, fall back to auto-detected
    vehicle_category = data.get("vehicle_category") or info.get('vehicle_category')
    db = get_db()
    c = db.execute(
        """INSERT INTO plates
           (plate_number, normalized, zone_id, entry_time, session_cost, payment_ref,
            payment_phone, duration_minutes,
            vehicle_category, region, is_diplomatic,
            diplomatic_code, diplomatic_country, mission_type, organization_type)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (plate_number, normalized,
         data.get("zone_id"),
         data.get("start_time", datetime.now().isoformat()),
         data.get("cost", 0),
         data.get("reference"),
         data.get("phone"),
         data.get("duration_minutes"),
         vehicle_category,
         info.get('region'),
         1 if info.get('is_diplomatic') else 0,
         info.get('diplomatic_code'),
         info.get('diplomatic_country'),
         info.get('mission_type'),
         info.get('organization_type'))
    )
    plate_id = c.lastrowid
    p = row_to_dict(db.execute("SELECT * FROM plates WHERE id=?", (plate_id,)).fetchone())
    db.commit(); db.close()
    return jsonify({"plate_id": plate_id, "plate": p}), 201

@app.put("/api/mobile/sessions/<int:plate_id>/end")
def mobile_end_session(plate_id):
    db = get_db()
    p = row_to_dict(db.execute("SELECT * FROM plates WHERE id=?", (plate_id,)).fetchone())
    if not p:
        db.close(); return jsonify({"error": "Session not found"}), 404
    db.execute("UPDATE plates SET exit_time=CURRENT_TIMESTAMP WHERE id=?", (plate_id,))
    result = row_to_dict(db.execute("SELECT * FROM plates WHERE id=?", (plate_id,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)

@app.get("/api/mobile/sessions")
def mobile_get_sessions():
    plate = request.args.get("plate", "").strip().upper()
    if not plate:
        return jsonify({"error": "plate parameter required"}), 400
    normalized = normalize_plate(plate)
    db = get_db()
    sessions = rows_to_list(db.execute(
        """SELECT p.*, z.name zone_name, z.hourly_rate
           FROM plates p LEFT JOIN zones z ON p.zone_id=z.id
           WHERE p.normalized LIKE ? ORDER BY p.entry_time DESC LIMIT 50""",
        (f"%{normalized}%",)
    ).fetchall())
    db.close()
    return jsonify(sessions)


# ─── TeleBirr ────────────────────────────────────────────────────────────────

@app.post("/api/payments/telebirr/initiate")
def telebirr_initiate():
    """
    Initiate a TeleBirr payment for a parking session.
    Body: {phone, amount, plate_number, zone_id, duration_minutes}
    Returns: {order_id, payment_url}
    """
    from telebirr import initiate as tb_initiate, is_configured
    data = request.json or {}
    phone    = (data.get("phone") or "").strip()
    amount   = data.get("amount")
    plate_no = normalize_plate((data.get("plate_number") or "").strip())
    if not phone or not amount or not plate_no:
        return jsonify({"error": "phone, amount, plate_number required"}), 400
    if not is_configured():
        return jsonify({"error": "TeleBirr not configured on server. Check TELEBIRR_* in .env"}), 503

    order_id = f"ORD-{int(datetime.utcnow().timestamp() * 1000)}"
    try:
        result = tb_initiate(phone, int(amount), order_id)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 502

    db = get_db()
    db.execute("""
        INSERT OR IGNORE INTO telebirr_orders
          (order_id, out_trade_no, plate_number, zone_id, phone, amount, duration_minutes)
        VALUES (?,?,?,?,?,?,?)
    """, (order_id, result["out_trade_no"], normalize_plate(plate_no),
          data.get("zone_id"), phone, int(amount), data.get("duration_minutes")))
    db.commit(); db.close()
    return jsonify({"order_id": order_id, "payment_url": result.get("payment_url", "")})


@app.post("/api/payments/webhook")
def telebirr_webhook():
    """Receive payment notification from TeleBirr."""
    from telebirr import verify_webhook_sign
    from plate_utils import normalize_plate as _np
    payload = request.json or {}

    if not verify_webhook_sign(payload):
        return jsonify({"error": "Invalid signature"}), 403

    out_trade_no = str(payload.get("outTradeNo") or payload.get("tradeNo", ""))
    trade_status = str(payload.get("tradeStatus") or payload.get("status", "")).upper()
    paid = trade_status in ("TRADE_SUCCESS", "SUCCESS", "PAID", "1", "00000")

    db = get_db()
    order = db.execute(
        "SELECT * FROM telebirr_orders WHERE out_trade_no=?", (out_trade_no,)
    ).fetchone()

    if not order:
        db.close()
        return jsonify({"error": "Order not found"}), 404

    if paid and order["status"] == "pending":
        plate_no = order["plate_number"]
        plate_id = order["plate_id"]

        if order["ticket_id"]:
            # ── Violation payment ──────────────────────────────────────────
            db.execute(
                "UPDATE tickets SET status='paid', updated_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), order["ticket_id"]))
            db.execute(
                "INSERT INTO payments (ticket_id, amount, method, reference)"
                " VALUES (?,?,?,?)",
                (order["ticket_id"], order["amount"], "telebirr", out_trade_no))
        else:
            # ── Session (parking fee) payment ──────────────────────────────
            c = db.execute("""
                INSERT INTO plates
                  (plate_number, normalized, zone_id, entry_time,
                   session_cost, payment_ref, payment_phone, duration_minutes)
                VALUES (?,?,?,?,?,?,?,?)
            """, (plate_no, normalize_plate(plate_no), order["zone_id"],
                  datetime.utcnow().isoformat(),
                  order["amount"], order["order_id"], order["phone"],
                  order["duration_minutes"]))
            plate_id = c.lastrowid

        db.execute(
            "UPDATE telebirr_orders SET status='paid', plate_id=?, webhook_data=?, updated_at=? WHERE out_trade_no=?",
            (plate_id, json.dumps(payload), datetime.utcnow().isoformat(), out_trade_no)
        )
        db.commit()

        # FCM payment confirmation
        if USE_FCM:
            try:
                fcm_row = db.execute("SELECT token FROM fcm_tokens WHERE plate_id=?", (plate_id,)).fetchone()
                if fcm_row:
                    from notifications import notify_payment_confirmed
                    notify_payment_confirmed(fcm_row["token"], plate_no, order["amount"], order["order_id"])
            except Exception:
                pass
    else:
        new_status = "paid" if paid else "failed"
        db.execute(
            "UPDATE telebirr_orders SET status=?, webhook_data=?, updated_at=? WHERE out_trade_no=?",
            (new_status, json.dumps(payload), datetime.utcnow().isoformat(), out_trade_no)
        )
        db.commit()

    db.close()
    return jsonify({"message": "OK"})


@app.get("/api/payments/telebirr/status/<order_id>")
def telebirr_status(order_id):
    """Poll payment status. Returns {status, plate_id}."""
    db = get_db()
    order = db.execute(
        "SELECT status, plate_id FROM telebirr_orders WHERE order_id=?", (order_id,)
    ).fetchone()
    db.close()
    if not order:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({
        "status":    order["status"],
        "plate_id":  order["plate_id"],
        "ticket_id": order["ticket_id"],
    })


# ─── Vehicle Config ──────────────────────────────────────────────────────────

@app.get("/api/config")
def get_config():
    """Return all configuration tables in one call (public — no auth required)."""
    db = get_db()
    try:
        return jsonify({
            "vehicle_categories": rows_to_list(db.execute(
                "SELECT * FROM vehicle_categories WHERE active=1 ORDER BY sort_order, code"
            ).fetchall()),
            "regions": rows_to_list(db.execute(
                "SELECT * FROM regions WHERE active=1 ORDER BY sort_order, code"
            ).fetchall()),
            "diplomatic_codes": rows_to_list(db.execute(
                "SELECT * FROM diplomatic_codes WHERE active=1 ORDER BY CAST(code AS INTEGER), code"
            ).fetchall()),
        })
    finally:
        db.close()


@app.get("/api/config/vehicle-categories")
def get_vehicle_categories():
    db = get_db()
    rows = rows_to_list(db.execute(
        "SELECT * FROM vehicle_categories ORDER BY sort_order, code"
    ).fetchall())
    db.close()
    return jsonify(rows)

@app.post("/api/config/vehicle-categories")
@require_admin
def create_vehicle_category():
    data = request.json or {}
    code = (data.get("code") or "").strip()
    name = (data.get("name") or "").strip()
    if not code or not name:
        return jsonify({"error": "code and name required"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO vehicle_categories (code, name, name_am, sort_order) VALUES (?,?,?,?)",
            (code, name, data.get("name_am"), data.get("sort_order", 0))
        )
        row = row_to_dict(db.execute(
            "SELECT * FROM vehicle_categories WHERE code=?", (code,)).fetchone())
        db.commit(); db.close()
        return jsonify(row), 201
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 409

@app.put("/api/config/vehicle-categories/<code>")
@require_admin
def update_vehicle_category(code):
    data = request.json or {}
    db = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM vehicle_categories WHERE code=?", (code,)).fetchone())
    if not row:
        db.close(); return jsonify({"error": "Not found"}), 404
    db.execute(
        "UPDATE vehicle_categories SET name=?, name_am=?, active=?, sort_order=? WHERE code=?",
        (data.get("name", row["name"]), data.get("name_am", row["name_am"]),
         data.get("active", row["active"]), data.get("sort_order", row["sort_order"]), code)
    )
    result = row_to_dict(db.execute(
        "SELECT * FROM vehicle_categories WHERE code=?", (code,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)

@app.delete("/api/config/vehicle-categories/<code>")
@require_admin
def delete_vehicle_category(code):
    db = get_db()
    db.execute("UPDATE vehicle_categories SET active=0 WHERE code=?", (code,))
    db.commit(); db.close()
    return jsonify({"message": "Deactivated"})


@app.get("/api/config/regions")
def get_regions():
    db = get_db()
    rows = rows_to_list(db.execute(
        "SELECT * FROM regions ORDER BY sort_order, code"
    ).fetchall())
    db.close()
    return jsonify(rows)

@app.post("/api/config/regions")
@require_admin
def create_region():
    data = request.json or {}
    code = (data.get("code") or "").strip().upper()
    name = (data.get("name") or "").strip()
    if not code or not name:
        return jsonify({"error": "code and name required"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO regions (code, name, name_am, sort_order) VALUES (?,?,?,?)",
            (code, name, data.get("name_am"), data.get("sort_order", 0))
        )
        row = row_to_dict(db.execute("SELECT * FROM regions WHERE code=?", (code,)).fetchone())
        db.commit(); db.close()
        return jsonify(row), 201
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 409

@app.put("/api/config/regions/<code>")
@require_admin
def update_region(code):
    data = request.json or {}
    db = get_db()
    row = row_to_dict(db.execute("SELECT * FROM regions WHERE code=?", (code,)).fetchone())
    if not row:
        db.close(); return jsonify({"error": "Not found"}), 404
    db.execute(
        "UPDATE regions SET name=?, name_am=?, active=?, sort_order=? WHERE code=?",
        (data.get("name", row["name"]), data.get("name_am", row["name_am"]),
         data.get("active", row["active"]), data.get("sort_order", row["sort_order"]), code)
    )
    result = row_to_dict(db.execute("SELECT * FROM regions WHERE code=?", (code,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)


@app.get("/api/config/diplomatic-codes")
def get_diplomatic_codes():
    db = get_db()
    rows = rows_to_list(db.execute(
        "SELECT * FROM diplomatic_codes ORDER BY CAST(code AS INTEGER), code"
    ).fetchall())
    db.close()
    return jsonify(rows)

@app.post("/api/config/diplomatic-codes")
@require_admin
def create_diplomatic_code():
    data = request.json or {}
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"error": "code required"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO diplomatic_codes (code, country, organization_type, is_reserved) VALUES (?,?,?,?)",
            (code, data.get("country"), data.get("organization_type", "Diplomatic Mission"),
             1 if data.get("is_reserved") else 0)
        )
        row = row_to_dict(db.execute("SELECT * FROM diplomatic_codes WHERE code=?", (code,)).fetchone())
        db.commit(); db.close()
        return jsonify(row), 201
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 409

@app.put("/api/config/diplomatic-codes/<code>")
@require_admin
def update_diplomatic_code(code):
    data = request.json or {}
    db = get_db()
    row = row_to_dict(db.execute("SELECT * FROM diplomatic_codes WHERE code=?", (code,)).fetchone())
    if not row:
        db.close(); return jsonify({"error": "Not found"}), 404
    db.execute(
        "UPDATE diplomatic_codes SET country=?, organization_type=?, active=?, is_reserved=? WHERE code=?",
        (data.get("country", row["country"]),
         data.get("organization_type", row["organization_type"]),
         data.get("active", row["active"]),
         data.get("is_reserved", row["is_reserved"]), code)
    )
    result = row_to_dict(db.execute("SELECT * FROM diplomatic_codes WHERE code=?", (code,)).fetchone())
    db.commit(); db.close()
    return jsonify(result)


# ─── Plates (enhanced with vehicle/diplomatic filters) ────────────────────────

@app.get("/api/plates/search")
@require_admin
def search_plates():
    """
    Advanced plate search with vehicle/diplomatic filters.
    Query params: plate, region, vehicle_category, is_diplomatic,
                  diplomatic_code, organization_type, zone_id, active
    """
    db = get_db()
    q = "SELECT p.*, z.name zone_name FROM plates p LEFT JOIN zones z ON p.zone_id=z.id WHERE 1=1"
    params = []

    if request.args.get("plate"):
        norm = normalize_plate(request.args["plate"])
        search_term = norm if norm else request.args["plate"].upper()
        q += " AND (p.normalized LIKE ? OR p.plate_number LIKE ?)"; params += [f"%{search_term}%", f"%{search_term}%"]
    if request.args.get("region"):
        q += " AND p.region=?"; params.append(request.args["region"].upper())
    if request.args.get("vehicle_category"):
        q += " AND p.vehicle_category=?"; params.append(request.args["vehicle_category"])
    if request.args.get("is_diplomatic") == "true":
        q += " AND p.is_diplomatic=1"
    elif request.args.get("is_diplomatic") == "false":
        q += " AND (p.is_diplomatic IS NULL OR p.is_diplomatic=0)"
    if request.args.get("diplomatic_code"):
        q += " AND p.diplomatic_code=?"; params.append(request.args["diplomatic_code"])
    if request.args.get("organization_type"):
        q += " AND p.organization_type=?"; params.append(request.args["organization_type"])
    if request.args.get("zone_id"):
        q += " AND p.zone_id=?"; params.append(request.args["zone_id"])
    if request.args.get("active") == "true":
        q += " AND p.exit_time IS NULL"

    q += " ORDER BY p.entry_time DESC LIMIT 500"
    plates = rows_to_list(db.execute(q, params).fetchall())
    db.close()
    return jsonify(plates)


@app.get("/api/analytics/vehicles")
@require_admin
def vehicle_analytics():
    """Analytics breakdown by vehicle category and region."""
    db = get_db()
    try:
        return jsonify({
            "by_category": rows_to_list(db.execute("""
                SELECT p.vehicle_category, vc.name category_name,
                       COUNT(*) total,
                       SUM(CASE WHEN p.exit_time IS NULL THEN 1 ELSE 0 END) active
                FROM plates p
                LEFT JOIN vehicle_categories vc ON vc.code = p.vehicle_category
                GROUP BY p.vehicle_category ORDER BY total DESC
            """).fetchall()),
            "by_region": rows_to_list(db.execute("""
                SELECT p.region, r.name region_name,
                       COUNT(*) total,
                       SUM(CASE WHEN p.exit_time IS NULL THEN 1 ELSE 0 END) active
                FROM plates p
                LEFT JOIN regions r ON r.code = p.region
                WHERE p.region IS NOT NULL
                GROUP BY p.region ORDER BY total DESC
            """).fetchall()),
            "diplomatic": rows_to_list(db.execute("""
                SELECT p.diplomatic_code, p.diplomatic_country,
                       p.mission_type, p.organization_type,
                       COUNT(*) total,
                       SUM(CASE WHEN p.exit_time IS NULL THEN 1 ELSE 0 END) active
                FROM plates p
                WHERE p.is_diplomatic=1
                GROUP BY p.diplomatic_code, p.organization_type
                ORDER BY total DESC
            """).fetchall()),
            "totals": row_to_dict(db.execute("""
                SELECT
                    COUNT(*) total,
                    SUM(CASE WHEN is_diplomatic=1 THEN 1 ELSE 0 END) diplomatic_count,
                    SUM(CASE WHEN vehicle_category='UN' THEN 1 ELSE 0 END) un_count,
                    SUM(CASE WHEN vehicle_category='AU' THEN 1 ELSE 0 END) au_count,
                    SUM(CASE WHEN vehicle_category='ተላላፊ' THEN 1 ELSE 0 END) temporary_count,
                    SUM(CASE WHEN vehicle_category='4' THEN 1 ELSE 0 END) government_count
                FROM plates
            """).fetchone()),
        })
    finally:
        db.close()


# ─── Run ─────────────────────────────────────────────────────────────────────

# ─── Startup (runs for both gunicorn and direct python execution) ─────────────
try:
    init_db()
except Exception as _e:
    print(f"[WARN] init_db failed: {_e}")
threading.Thread(target=_expiry_checker_loop, daemon=True, name="expiry-checker").start()
print("[OK] FCM expiry checker started (60 s interval)")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    print(f"\nParking Admin API running on http://localhost:{port}")
    print("Routes: POST /api/auth/login  |  GET /api/dashboard")
    print("        GET /api/zones | /api/wardens | /api/plates | /api/tickets | /api/payments\n")
    app.run(host="0.0.0.0", port=port, debug=False)
