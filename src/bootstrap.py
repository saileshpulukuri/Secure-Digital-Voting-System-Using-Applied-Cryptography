"""Bootstrap default admin account when none exist (after schema + migrations)."""

from __future__ import annotations

from datetime import datetime, timezone

from src.config import settings
from src.crypto_service import hash_password
from src.database import audit_log, get_connection, init_schema


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_bootstrap(db_path, admin_plain_password: str, _starts_at: str | None, _ends_at: str | None) -> None:
    with get_connection(db_path) as conn:
        init_schema(conn)
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
