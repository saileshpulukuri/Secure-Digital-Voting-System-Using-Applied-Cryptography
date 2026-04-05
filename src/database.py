"""SQLite persistence, schema v2 (multi-election), optional v1 migration."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS voters (
  voter_id TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  public_key_pem TEXT NOT NULL,
  has_voted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS admins (
  username TEXT PRIMARY KEY COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS elections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('class','department','campus')),
  public_key_pem TEXT NOT NULL,
  private_key_pem TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  closed INTEGER NOT NULL DEFAULT 0,
  results_announced INTEGER NOT NULL DEFAULT 0,
  results_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contestants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  image_path TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS election_registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  voter_id TEXT NOT NULL REFERENCES voters(voter_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL,
  UNIQUE(election_id, voter_id)
);

CREATE TABLE IF NOT EXISTS election_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  voter_id TEXT NOT NULL REFERENCES voters(voter_id) ON DELETE CASCADE,
  encrypted_vote TEXT NOT NULL,
  signature TEXT NOT NULL,
  integrity_hash TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  voter_public_key_pem TEXT,
  UNIQUE(election_id, voter_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL
);
"""


@contextmanager
def get_connection(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate_admin_meta_to_table(conn)
    _migrate_legacy_v1(conn)
    _migrate_election_votes_voter_pubkey(conn)


def _migrate_admin_meta_to_table(conn: sqlite3.Connection) -> None:
    if not conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='admins'"
    ).fetchone():
        return
    n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
    if n > 0:
        return
    h = get_meta(conn, "admin_password_hash")
    if not h:
        return
    conn.execute(
        "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
        ("admin", h, _utc_now_iso()),
    )
    conn.commit()
    conn.execute("DELETE FROM meta WHERE key = ?", ("admin_password_hash",))
    conn.commit()
    audit_log(conn, "admin_migrated", "Legacy admin_password_hash -> admins.admin")


def _migrate_legacy_v1(conn: sqlite3.Connection) -> None:
    if get_meta(conn, "legacy_v1_migrated"):
        return
    legacy = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='election'"
    ).fetchone()
    if not legacy:
        set_meta(conn, "legacy_v1_migrated", "1")
        return
    row = conn.execute("SELECT * FROM election WHERE id = 1").fetchone()
    if not row:
        set_meta(conn, "legacy_v1_migrated", "1")
        return
    n = conn.execute("SELECT COUNT(*) AS c FROM elections").fetchone()["c"]
    if n > 0:
        set_meta(conn, "legacy_v1_migrated", "1")
        return
    cur = conn.execute(
        """INSERT INTO elections (title, category, public_key_pem, private_key_pem, starts_at, ends_at,
           closed, results_announced, results_json, created_at)
           VALUES (?, 'campus', ?, ?, ?, ?, ?, 0, NULL, ?)""",
        (
            "Imported election (v1)",
            row["public_key_pem"],
            row["private_key_pem"],
            row["starts_at"],
            row["ends_at"],
            int(row["closed"]),
            _utc_now_iso(),
        ),
    )
    eid = cur.lastrowid
    votes_old = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='votes'"
    ).fetchone()
    if votes_old:
        for v in conn.execute("SELECT * FROM votes"):
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO election_votes
                       (election_id, voter_id, encrypted_vote, signature, integrity_hash, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        eid,
                        v["voter_id"],
                        v["encrypted_vote"],
                        v["signature"],
                        v["integrity_hash"],
                        v["timestamp"],
                    ),
                )
            except sqlite3.IntegrityError:
                pass
    conn.commit()
    set_meta(conn, "legacy_v1_migrated", "1")
    audit_log(conn, "schema_migrated", f"v1 election -> elections.id={eid}")


def _migrate_election_votes_voter_pubkey(conn: sqlite3.Connection) -> None:
    """Store voter public key per ballot so signatures still verify after key rotation."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(election_votes)").fetchall()}
    if "voter_public_key_pem" not in cols:
        conn.execute("ALTER TABLE election_votes ADD COLUMN voter_public_key_pem TEXT")
        conn.commit()
    conn.execute(
        """
        UPDATE election_votes
        SET voter_public_key_pem = (
            SELECT v.public_key_pem FROM voters v WHERE v.voter_id = election_votes.voter_id
        )
        WHERE voter_public_key_pem IS NULL OR voter_public_key_pem = ''
        """
    )
    conn.commit()


def audit_log(conn: sqlite3.Connection, event_type: str, detail: str | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log (event_type, detail, created_at) VALUES (?, ?, ?)",
        (event_type, detail, _utc_now_iso()),
    )
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def get_election_row(conn: sqlite3.Connection, election_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
