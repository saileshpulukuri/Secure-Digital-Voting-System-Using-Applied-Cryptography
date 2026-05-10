"""Bootstrap default admin account when none exist (after schema + migrations)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.config import settings
from src.crypto_service import hash_password
from src.database import audit_log, get_connection, init_schema

logger = logging.getLogger("voting")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _prune_voters_not_on_allowlist(conn) -> None:
    """Remove voter rows whose email is not in ``STUDENT_EMAIL_ALLOWLIST`` (CASCADE cleans OTPs/registrations/votes)."""
    allowed = settings.allowed_student_emails()
    if not allowed:
        logger.warning("STUDENT_EMAIL_ALLOWLIST is empty — not pruning voters (misconfiguration risk).")
        return
    rows = conn.execute("SELECT voter_id FROM voters").fetchall()
    removed = 0
    for r in rows:
        raw = str(r["voter_id"])
        vid = raw.strip().lower()
        if vid not in allowed:
            conn.execute("DELETE FROM voters WHERE voter_id = ?", (raw,))
            removed += 1
    if removed:
        conn.commit()
        audit_log(conn, "voters_pruned_allowlist", f"removed {removed} voter(s) not on STUDENT_EMAIL_ALLOWLIST")
        logger.info("Removed %s voter row(s) not on the current allowlist", removed)


def ensure_bootstrap(db_path, admin_plain_password: str, _starts_at: str | None, _ends_at: str | None) -> None:
    with get_connection(db_path) as conn:
        init_schema(conn)
        _prune_voters_not_on_allowlist(conn)
        un = settings.admin_username.strip() or "admin"
        n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
        ph = hash_password(admin_plain_password)
        row = conn.execute("SELECT username FROM admins WHERE username = ?", (un,)).fetchone()

        if settings.sync_admin_from_env:
            if row:
                conn.execute("UPDATE admins SET password_hash = ? WHERE username = ?", (ph, un))
                conn.commit()
                audit_log(conn, "admin_password_synced", un)
                return
            if n == 0:
                conn.execute(
                    "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
                    (un, ph, _utc_iso()),
                )
                conn.commit()
                audit_log(conn, "admin_bootstrap", f"Seeded administrator {un!r} from .env")
                return
            # Other admins exist but not ADMIN_USERNAME — still create/sync the .env account so login works.
            conn.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
                (un, ph, _utc_iso()),
            )
            conn.commit()
            audit_log(conn, "admin_bootstrap", f"Added administrator {un!r} from .env (SYNC_ADMIN_FROM_ENV)")
            return

        if n > 0:
            return
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
            (un, ph, _utc_iso()),
        )
        conn.commit()
        audit_log(conn, "admin_bootstrap", f"Seeded administrator {un!r} (configure ADMIN_USERNAME / ADMIN_PASSWORD in .env)")
