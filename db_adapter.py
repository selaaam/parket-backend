"""
db_adapter.py — Unified SQLite / PostgreSQL database adapter.

Backend selection:
  DATABASE_URL not set (or empty) → SQLite  (local dev, default)
  DATABASE_URL=postgresql://...   → PostgreSQL with connection pool (production)

All SQL may be written in SQLite dialect:
  • ? parameter placeholders
  • DATE('now'), DATE('now','-N days')
  • strftime('%Y-%m', col)
  • DATE(col)  (cast to date)
  • INSERT OR IGNORE INTO
They are translated transparently to PostgreSQL syntax when running on Postgres.

Public API:
  get_db()        → connection wrapper (execute / commit / close)
  IntegrityError  → sqlite3.IntegrityError  or  psycopg2.IntegrityError
  BACKEND         → "sqlite" | "postgresql"
"""

import os
import re

DATABASE_URL: str = os.environ.get("DATABASE_URL", "").strip()
BACKEND: str = "postgresql" if DATABASE_URL else "sqlite"

# ── SQL translation (SQLite → PostgreSQL) ─────────────────────────────────────

_PG_SUBS = [
    # DATE('now','-N days')  →  (CURRENT_DATE - INTERVAL 'N days')
    (re.compile(r"DATE\s*\(\s*'now'\s*,\s*'-(\d+)\s+days'\s*\)", re.I),
     r"(CURRENT_DATE - INTERVAL '\1 days')"),
    # DATE('now')  →  CURRENT_DATE
    (re.compile(r"DATE\s*\(\s*'now'\s*\)", re.I),
     "CURRENT_DATE"),
    # strftime('%Y-%m','now')  →  TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM')
    (re.compile(r"strftime\s*\(\s*'%Y-%m'\s*,\s*'now'\s*\)", re.I),
     "TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM')"),
    # strftime('%Y-%m',col)  →  TO_CHAR(col,'YYYY-MM')
    (re.compile(r"strftime\s*\(\s*'%Y-%m'\s*,\s*(\w+)\s*\)", re.I),
     r"TO_CHAR(\1,'YYYY-MM')"),
    # DATE(col)  →  col::date  (identifier cast, not string literal)
    (re.compile(r"\bDATE\s*\(\s*([a-zA-Z_]\w*)\s*\)"),
     r"\1::date"),
    # INSERT OR IGNORE INTO  →  INSERT INTO  (ON CONFLICT added in execute())
    (re.compile(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", re.I),
     "INSERT INTO"),
    # ? → %s
    (re.compile(r"\?"),
     r"%s"),
]


def _adapt(sql: str) -> str:
    """Translate SQLite dialect to PostgreSQL."""
    for pattern, repl in _PG_SUBS:
        sql = pattern.sub(repl, sql)
    return sql


def _is_insert(sql: str) -> bool:
    return bool(re.match(r"\s*INSERT\b", sql, re.I))


def _had_or_ignore(sql: str) -> bool:
    return bool(re.search(r"\bINSERT\s+OR\s+IGNORE\b", sql, re.I))


# ── Cursor wrappers ───────────────────────────────────────────────────────────

class _SqliteCursor:
    def __init__(self, raw):
        self._raw = raw

    def fetchone(self):
        row = self._raw.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(r) for r in self._raw.fetchall()]

    @property
    def lastrowid(self):
        return self._raw.lastrowid

    @property
    def rowcount(self):
        return self._raw.rowcount


class _PgCursor:
    def __init__(self, raw, lastrowid=None):
        self._raw = raw
        self._lastrowid = lastrowid

    def fetchone(self):
        return self._raw.fetchone()

    def fetchall(self):
        return self._raw.fetchall()

    @property
    def lastrowid(self):
        return self._lastrowid

    @property
    def rowcount(self):
        return self._raw.rowcount


# ── Connection wrappers ───────────────────────────────────────────────────────

class _SqliteConn:
    def __init__(self):
        import sqlite3
        db_path = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "parking.db"))
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")

    def execute(self, sql: str, params=()):
        return _SqliteCursor(self._conn.execute(sql, params))

    def executescript(self, script: str):
        self._conn.executescript(script)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


_pg_pool = None


def _get_pool():
    global _pg_pool
    if _pg_pool is None:
        import psycopg2.pool
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=int(os.environ.get("DB_POOL_SIZE", "10")),
            dsn=DATABASE_URL,
        )
    return _pg_pool


class _PgConn:
    def __init__(self):
        self._pool = _get_pool()
        self._conn = self._pool.getconn()

    def execute(self, sql: str, params=()):
        import psycopg2.extras

        ignore = _had_or_ignore(sql)
        adapted = _adapt(sql)

        # Auto-append RETURNING id for INSERT so .lastrowid works
        needs_returning = _is_insert(sql) and "RETURNING" not in sql.upper()

        if needs_returning:
            conflict = " ON CONFLICT DO NOTHING" if ignore else ""
            adapted = adapted.rstrip("; ") + conflict + " RETURNING id"
        elif ignore:
            adapted = adapted.rstrip("; ") + " ON CONFLICT DO NOTHING"

        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(adapted, params or ())

        lid = None
        if needs_returning:
            row = cur.fetchone()
            lid = row["id"] if row else None

        return _PgCursor(cur, lid)

    def executescript(self, script: str):
        """Run multi-statement DDL (used only during init_db on SQLite path)."""
        cur = self._conn.cursor()
        cur.execute(script)

    def commit(self):
        self._conn.commit()

    def close(self):
        """Return the connection to the pool."""
        _get_pool().putconn(self._conn)


# ── Public API ────────────────────────────────────────────────────────────────

def get_db():
    """Return a database connection for the configured backend."""
    if BACKEND == "postgresql":
        return _PgConn()
    return _SqliteConn()


# Unified IntegrityError alias
if BACKEND == "postgresql":
    try:
        import psycopg2
        IntegrityError = psycopg2.IntegrityError
    except ImportError:
        raise RuntimeError(
            "DATABASE_URL is set but psycopg2 is not installed.\n"
            "Run: pip install psycopg2-binary"
        )
else:
    import sqlite3 as _sq3
    IntegrityError = _sq3.IntegrityError
