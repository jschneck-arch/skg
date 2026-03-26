"""
tests/fixtures/create_webapp_db.py
====================================
Creates a realistic web application SQLite database for testing
the skg data pipeline adapter.

The database mimics a typical Flask/Django web app backend with:
  - users table    — has NULL in required field, stale records
  - orders table   — has duplicate primary keys, out-of-bounds amounts
  - sessions table — all expired (staleness violation)
  - products table — clean, reference table

These intentional violations let us validate that DP-* wickets fire
correctly:
  DP-03 blocked  — NULL in required users.email field
  DP-08 blocked  — duplicate order_id in orders
  DP-09 blocked  — sessions.last_seen all > 24h ago
  DP-04 blocked  — orders.amount has negative value (out of declared bounds)
  DP-10 realized — SQLite source is reachable
  DP-15 realized — records conform to current schema

Run:
  python tests/fixtures/create_webapp_db.py
  skg data profile --url sqlite:///tests/fixtures/webapp.db --table users
  skg data profile --url sqlite:///tests/fixtures/webapp.db --table orders
"""
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent / "webapp.db"


def create():
    if DB_PATH.exists():
        DB_PATH.unlink()

    con = sqlite3.connect(str(DB_PATH))
    cur = con.cursor()

    # ── users ─────────────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE users (
        user_id   INTEGER PRIMARY KEY,
        username  TEXT NOT NULL,
        email     TEXT,              -- intentionally nullable (violation)
        role      TEXT DEFAULT 'user',
        created_at TEXT NOT NULL,
        last_login TEXT
    )
    """)

    now  = datetime.now(timezone.utc)
    old  = now - timedelta(days=400)
    users = [
        (1,  "alice",   "alice@example.com",  "admin",  now.isoformat(),  now.isoformat()),
        (2,  "bob",     None,                 "user",   now.isoformat(),  now.isoformat()),   # NULL email — DP-03 violation
        (3,  "carol",   "carol@example.com",  "user",   now.isoformat(),  None),
        (4,  "dave",    "dave@example.com",   "user",   old.isoformat(),  old.isoformat()),  # stale
        (5,  "eve",     None,                 "user",   now.isoformat(),  now.isoformat()),   # NULL email
        (6,  "frank",   "frank@example.com",  "mod",    now.isoformat(),  now.isoformat()),
        (7,  "grace",   "grace@example.com",  "user",   now.isoformat(),  now.isoformat()),
        (8,  "heidi",   "heidi@example.com",  "user",   now.isoformat(),  now.isoformat()),
        (9,  "ivan",    "ivan@example.com",   "user",   now.isoformat(),  now.isoformat()),
        (10, "judy",    "judy@example.com",   "user",   now.isoformat(),  now.isoformat()),
    ]
    cur.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", users)

    # ── orders ────────────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE orders (
        order_id    INTEGER,          -- NOT declared PRIMARY KEY to allow dupes
        user_id     INTEGER,
        product_id  INTEGER,
        amount      REAL NOT NULL,
        status      TEXT DEFAULT 'pending',
        created_at  TEXT NOT NULL
    )
    """)

    stale_order = now - timedelta(hours=48)
    orders = [
        (1001, 1, 10, 49.99,   "complete",   now.isoformat()),
        (1002, 2, 11, 199.00,  "pending",    now.isoformat()),
        (1003, 3, 10, -15.00,  "refund",     now.isoformat()),   # negative amount — DP-04 violation
        (1004, 1, 12, 5.00,    "complete",   now.isoformat()),
        (1002, 2, 11, 199.00,  "pending",    now.isoformat()),   # duplicate order_id 1002 — DP-08 violation
        (1005, 4, 13, 299.99,  "cancelled",  stale_order.isoformat()),
        (1006, 5, 10, 99.99,   "complete",   now.isoformat()),
        (1007, 6, 14, 1500.00, "pending",    now.isoformat()),   # over declared max — DP-04 violation
        (1008, 7, 10, 25.00,   "complete",   now.isoformat()),
        (1009, 8, 11, 75.50,   "pending",    now.isoformat()),
    ]
    cur.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?)", orders)

    # ── sessions ─────────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE sessions (
        session_id  TEXT PRIMARY KEY,
        user_id     INTEGER NOT NULL,
        token       TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        ip_address  TEXT
    )
    """)

    expired = now - timedelta(hours=36)  # all sessions expired > 24h TTL — DP-09 violation
    sessions = [
        ("sess_aaa", 1, "tok_abc123", expired.isoformat(), "10.0.0.1"),
        ("sess_bbb", 2, "tok_def456", expired.isoformat(), "10.0.0.2"),
        ("sess_ccc", 3, "tok_ghi789", expired.isoformat(), "192.168.1.50"),
        ("sess_ddd", 4, "tok_jkl012", expired.isoformat(), "10.0.0.3"),
    ]
    cur.executemany("INSERT INTO sessions VALUES (?,?,?,?,?)", sessions)

    # ── products ─────────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE products (
        product_id  INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        price       REAL NOT NULL,
        category    TEXT,
        stock       INTEGER DEFAULT 0
    )
    """)

    products = [
        (10, "Widget A",    49.99, "widgets",   100),
        (11, "Widget B",   199.00, "widgets",    50),
        (12, "Gadget X",     5.00, "gadgets",   500),
        (13, "Gadget Y",   299.99, "gadgets",    20),
        (14, "Premium Z", 1500.00, "premium",     5),
    ]
    cur.executemany("INSERT INTO products VALUES (?,?,?,?,?)", products)

    con.commit()
    con.close()
    print(f"Created: {DB_PATH}")
    print(f"  users:    {len(users)} rows (2 NULL emails, intentional)")
    print(f"  orders:   {len(orders)} rows (1 dup, 1 negative, 1 over-bound, intentional)")
    print(f"  sessions: {len(sessions)} rows (all stale >24h, intentional)")
    print(f"  products: {len(products)} rows (clean reference table)")
    print()
    print("Test with:")
    print(f"  skg data profile --url sqlite:///{DB_PATH} --table users \\")
    print(f"       --contract tests/fixtures/users_contract.json")
    print(f"  skg data profile --url sqlite:///{DB_PATH} --table orders \\")
    print(f"       --contract tests/fixtures/orders_contract.json")
    print(f"  skg data profile --url sqlite:///{DB_PATH} --table sessions \\")
    print(f"       --contract tests/fixtures/sessions_contract.json")


if __name__ == "__main__":
    create()
