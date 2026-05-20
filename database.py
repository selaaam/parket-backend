import bcrypt
import os
from db_adapter import get_db, BACKEND

# ── Schema DDL ────────────────────────────────────────────────────────────────

_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS vehicle_categories (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    name_am TEXT,
    active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS regions (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    name_am TEXT,
    active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS diplomatic_codes (
    code TEXT PRIMARY KEY,
    country TEXT,
    organization_type TEXT DEFAULT 'Diplomatic Mission',
    active INTEGER DEFAULT 1,
    is_reserved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT,
    capacity INTEGER DEFAULT 0,
    hourly_rate INTEGER DEFAULT 100,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wardens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    badge_number TEXT UNIQUE,
    zone_id INTEGER REFERENCES zones(id),
    active INTEGER DEFAULT 1,
    password_hash TEXT,
    firebase_uid TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate_number TEXT NOT NULL,
    normalized TEXT NOT NULL,
    zone_id INTEGER REFERENCES zones(id),
    entry_time TEXT DEFAULT CURRENT_TIMESTAMP,
    exit_time TEXT,
    session_cost REAL DEFAULT 0,
    payment_ref TEXT,
    payment_phone TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate_id INTEGER REFERENCES plates(id),
    warden_id INTEGER REFERENCES wardens(id),
    zone_id INTEGER REFERENCES zones(id),
    plate_number TEXT NOT NULL,
    reason TEXT,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'unpaid',
    violation_type TEXT,
    gps_lat REAL,
    gps_lng REAL,
    evidence TEXT,
    issued_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER REFERENCES tickets(id),
    amount REAL NOT NULL,
    method TEXT DEFAULT 'cash',
    paid_at TEXT DEFAULT CURRENT_TIMESTAMP,
    reference TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    firebase_uid TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fcm_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate_id INTEGER UNIQUE REFERENCES plates(id) ON DELETE CASCADE,
    warden_id INTEGER UNIQUE REFERENCES wardens(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS telebirr_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT UNIQUE NOT NULL,
    out_trade_no TEXT,
    plate_number TEXT NOT NULL,
    zone_id INTEGER,
    phone TEXT,
    amount INTEGER NOT NULL,
    duration_minutes INTEGER,
    plate_id INTEGER REFERENCES plates(id),
    status TEXT DEFAULT 'pending',
    webhook_data TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

# Individual statements (PostgreSQL doesn't support executescript)
_PG_DDL = [
    """CREATE TABLE IF NOT EXISTS vehicle_categories (
        code TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        name_am TEXT,
        active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS regions (
        code TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        name_am TEXT,
        active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS diplomatic_codes (
        code TEXT PRIMARY KEY,
        country TEXT,
        organization_type TEXT DEFAULT 'Diplomatic Mission',
        active INTEGER DEFAULT 1,
        is_reserved INTEGER DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS zones (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        address TEXT,
        capacity INTEGER DEFAULT 0,
        hourly_rate INTEGER DEFAULT 100,
        active INTEGER DEFAULT 1,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS wardens (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        phone TEXT,
        badge_number TEXT UNIQUE,
        zone_id INTEGER REFERENCES zones(id),
        active INTEGER DEFAULT 1,
        password_hash TEXT,
        firebase_uid TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS plates (
        id SERIAL PRIMARY KEY,
        plate_number TEXT NOT NULL,
        normalized TEXT NOT NULL,
        zone_id INTEGER REFERENCES zones(id),
        entry_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        exit_time TIMESTAMPTZ,
        session_cost REAL DEFAULT 0,
        payment_ref TEXT,
        payment_phone TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS tickets (
        id SERIAL PRIMARY KEY,
        plate_id INTEGER REFERENCES plates(id),
        warden_id INTEGER REFERENCES wardens(id),
        zone_id INTEGER REFERENCES zones(id),
        plate_number TEXT NOT NULL,
        reason TEXT,
        amount REAL NOT NULL,
        status TEXT DEFAULT 'unpaid',
        violation_type TEXT,
        gps_lat REAL,
        gps_lng REAL,
        evidence TEXT,
        issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        ticket_id INTEGER REFERENCES tickets(id),
        amount REAL NOT NULL,
        method TEXT DEFAULT 'cash',
        paid_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        reference TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        firebase_uid TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS fcm_tokens (
        id SERIAL PRIMARY KEY,
        plate_id INTEGER UNIQUE REFERENCES plates(id) ON DELETE CASCADE,
        warden_id INTEGER UNIQUE REFERENCES wardens(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS telebirr_orders (
        id SERIAL PRIMARY KEY,
        order_id TEXT UNIQUE NOT NULL,
        out_trade_no TEXT,
        plate_number TEXT NOT NULL,
        zone_id INTEGER,
        phone TEXT,
        amount INTEGER NOT NULL,
        duration_minutes INTEGER,
        plate_id INTEGER REFERENCES plates(id),
        status TEXT DEFAULT 'pending',
        webhook_data TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )""",
]

# SQLite: try/except because ADD COLUMN fails if column already exists
_SQLITE_MIGRATIONS = [
    "ALTER TABLE plates ADD COLUMN duration_minutes INTEGER",
    "ALTER TABLE plates ADD COLUMN expiry_notified_15 INTEGER DEFAULT 0",
    "ALTER TABLE plates ADD COLUMN expiry_notified_5 INTEGER DEFAULT 0",
    "ALTER TABLE zones ADD COLUMN hourly_rate INTEGER DEFAULT 100",
    "ALTER TABLE plates ADD COLUMN session_cost REAL DEFAULT 0",
    "ALTER TABLE plates ADD COLUMN payment_ref TEXT",
    "ALTER TABLE plates ADD COLUMN payment_phone TEXT",
    "ALTER TABLE wardens ADD COLUMN password_hash TEXT",
    "ALTER TABLE tickets ADD COLUMN violation_type TEXT",
    "ALTER TABLE tickets ADD COLUMN gps_lat REAL",
    "ALTER TABLE tickets ADD COLUMN gps_lng REAL",
    "ALTER TABLE tickets ADD COLUMN evidence TEXT",
    "ALTER TABLE users ADD COLUMN firebase_uid TEXT",
    "ALTER TABLE wardens ADD COLUMN firebase_uid TEXT",
    "ALTER TABLE tickets ADD COLUMN parking_fee REAL DEFAULT 0",
    "ALTER TABLE tickets ADD COLUMN fine_amount REAL",
    "ALTER TABLE tickets ADD COLUMN user_phone TEXT",
    "ALTER TABLE tickets ADD COLUMN notes TEXT",
    "ALTER TABLE tickets ADD COLUMN entry_time TEXT",
    "ALTER TABLE tickets ADD COLUMN duration_minutes INTEGER",
    "ALTER TABLE tickets ADD COLUMN notice_sent_at TEXT",
    "ALTER TABLE tickets ADD COLUMN warrant_number TEXT",
    "ALTER TABLE tickets ADD COLUMN warrant_issued_at TEXT",
    "ALTER TABLE tickets ADD COLUMN telebirr_order_id TEXT",
    "ALTER TABLE telebirr_orders ADD COLUMN ticket_id INTEGER",
    # Vehicle / diplomatic metadata on plates
    "ALTER TABLE plates ADD COLUMN vehicle_category TEXT",
    "ALTER TABLE plates ADD COLUMN region TEXT",
    "ALTER TABLE plates ADD COLUMN is_diplomatic INTEGER DEFAULT 0",
    "ALTER TABLE plates ADD COLUMN diplomatic_code TEXT",
    "ALTER TABLE plates ADD COLUMN diplomatic_country TEXT",
    "ALTER TABLE plates ADD COLUMN mission_type TEXT",
    "ALTER TABLE plates ADD COLUMN organization_type TEXT",
]

# PostgreSQL 9.6+: IF NOT EXISTS is idempotent
_PG_MIGRATIONS = [
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS duration_minutes INTEGER",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS expiry_notified_15 INTEGER DEFAULT 0",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS expiry_notified_5 INTEGER DEFAULT 0",
    "ALTER TABLE zones ADD COLUMN IF NOT EXISTS hourly_rate INTEGER DEFAULT 100",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS session_cost REAL DEFAULT 0",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS payment_ref TEXT",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS payment_phone TEXT",
    "ALTER TABLE wardens ADD COLUMN IF NOT EXISTS password_hash TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS violation_type TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS gps_lat REAL",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS gps_lng REAL",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS evidence TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS firebase_uid TEXT",
    "ALTER TABLE wardens ADD COLUMN IF NOT EXISTS firebase_uid TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS parking_fee REAL DEFAULT 0",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS fine_amount REAL",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS user_phone TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS notes TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS entry_time TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS duration_minutes INTEGER",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS notice_sent_at TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS warrant_number TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS warrant_issued_at TEXT",
    "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS telebirr_order_id TEXT",
    "ALTER TABLE telebirr_orders ADD COLUMN IF NOT EXISTS ticket_id INTEGER",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS vehicle_category TEXT",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS region TEXT",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS is_diplomatic INTEGER DEFAULT 0",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS diplomatic_code TEXT",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS diplomatic_country TEXT",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS mission_type TEXT",
    "ALTER TABLE plates ADD COLUMN IF NOT EXISTS organization_type TEXT",
]


def _seed_config(conn):
    """Populate vehicle_categories, regions, and diplomatic_codes if empty."""
    from plate_utils import (
        DEFAULT_VEHICLE_CATEGORIES, DEFAULT_REGIONS, DEFAULT_DIPLOMATIC_CODES,
        RESERVED_DIPLOMATIC_CODES,
    )

    if conn.execute("SELECT COUNT(*) c FROM vehicle_categories").fetchone()["c"] == 0:
        for code, info in DEFAULT_VEHICLE_CATEGORIES.items():
            conn.execute(
                "INSERT OR IGNORE INTO vehicle_categories (code, name, name_am, sort_order) VALUES (?,?,?,?)",
                (code, info['name'], info.get('name_am'), info.get('sort_order', 0))
            )
        conn.commit()
        print("[OK] vehicle_categories seeded")

    if conn.execute("SELECT COUNT(*) c FROM regions").fetchone()["c"] == 0:
        for i, (code, name) in enumerate(DEFAULT_REGIONS.items()):
            conn.execute(
                "INSERT OR IGNORE INTO regions (code, name, sort_order) VALUES (?,?,?)",
                (code, name, i)
            )
        conn.commit()
        print("[OK] regions seeded")

    if conn.execute("SELECT COUNT(*) c FROM diplomatic_codes").fetchone()["c"] == 0:
        for code, country in DEFAULT_DIPLOMATIC_CODES.items():
            conn.execute(
                "INSERT OR IGNORE INTO diplomatic_codes (code, country, is_reserved) VALUES (?,?,?)",
                (code, country, 1 if code in RESERVED_DIPLOMATIC_CODES else 0)
            )
        conn.commit()
        print("[OK] diplomatic_codes seeded ({} entries)".format(len(DEFAULT_DIPLOMATIC_CODES)))


def init_db():
    conn = get_db()

    if BACKEND == "sqlite":
        conn.executescript(_SQLITE_DDL)
        for m in _SQLITE_MIGRATIONS:
            try:
                conn.execute(m)
                conn.commit()
            except Exception:
                pass
    else:
        for stmt in _PG_DDL:
            conn.execute(stmt)
        conn.commit()
        for m in _PG_MIGRATIONS:
            try:
                conn.execute(m)
                conn.commit()
            except Exception:
                pass

    # Set default warden PIN for wardens that have no password yet
    default_pin = os.environ.get("WARDEN_DEFAULT_PIN", "").strip()
    if default_pin:
        rows = conn.execute(
            "SELECT id FROM wardens WHERE password_hash IS NULL AND active=1"
        ).fetchall()
        if rows:
            pin_hash = bcrypt.hashpw(default_pin.encode(), bcrypt.gensalt()).decode()
            for row in rows:
                conn.execute(
                    "UPDATE wardens SET password_hash=? WHERE id=?",
                    (pin_hash, row["id"])
                )
            conn.commit()
            print(f"[OK] Default PIN set for {len(rows)} warden(s)")

    # Seed zones + wardens only on a completely empty database
    zone_count = conn.execute("SELECT COUNT(*) c FROM zones").fetchone()["c"]
    if zone_count == 0:
        bole_id    = conn.execute(
            "INSERT INTO zones (name, address, capacity, hourly_rate) VALUES (?,?,?,?)",
            ('Bole Zone', 'Bole, Addis Ababa', 50, 100)
        ).lastrowid
        piazza_id  = conn.execute(
            "INSERT INTO zones (name, address, capacity, hourly_rate) VALUES (?,?,?,?)",
            ('Piazza Zone', 'Arada, Addis Ababa', 30, 100)
        ).lastrowid
        merkato_id = conn.execute(
            "INSERT INTO zones (name, address, capacity, hourly_rate) VALUES (?,?,?,?)",
            ('Merkato Zone', 'Addis Ketema', 80, 100)
        ).lastrowid
        conn.execute(
            "INSERT INTO zones (name, address, capacity, hourly_rate) VALUES (?,?,?,?)",
            ('Kazanchis Zone', 'Kirkos, Addis Ababa', 40, 100)
        )

        warden_pin_hash = None
        if default_pin:
            warden_pin_hash = bcrypt.hashpw(default_pin.encode(), bcrypt.gensalt()).decode()

        conn.execute(
            "INSERT INTO wardens (name,email,phone,badge_number,zone_id,password_hash) VALUES (?,?,?,?,?,?)",
            ('Abebe Girma', 'abebe@parket.et', '0911234567', 'W-001', bole_id, warden_pin_hash)
        )
        conn.execute(
            "INSERT INTO wardens (name,email,phone,badge_number,zone_id,password_hash) VALUES (?,?,?,?,?,?)",
            ('Tigist Haile', 'tigist@parket.et', '0922345678', 'W-002', piazza_id, warden_pin_hash)
        )
        conn.execute(
            "INSERT INTO wardens (name,email,phone,badge_number,zone_id,password_hash) VALUES (?,?,?,?,?,?)",
            ('Dawit Bekele', 'dawit@parket.et', '0933456789', 'W-003', merkato_id, warden_pin_hash)
        )
        conn.commit()
        print("[OK] Zones and wardens seeded")

    # Create initial admin from environment variables (first-run only)
    admin_email    = os.environ.get("ADMIN_EMAIL", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    user_count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]

    if admin_email and admin_password:
        pw_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT OR IGNORE INTO users (email, password_hash, role) VALUES (?,?,?)",
            (admin_email, pw_hash, 'admin')
        )
        conn.commit()
        print(f"[OK] Admin account ready: {admin_email}")
    elif user_count == 0:
        print("\n[WARN] No admin account exists and ADMIN_EMAIL/ADMIN_PASSWORD are not set.")
        print("   Set them in .env and restart once to create the initial admin account.\n")

    _seed_config(conn)
    conn.close()
    print(f"[OK] Database initialised ({BACKEND})")
