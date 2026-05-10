"""JSON API for web UI and clients."""

from __future__ import annotations

import json
import hashlib
import logging
import re
import secrets
import smtplib
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Annotated


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

import sqlite3
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from src.auth_tokens import create_access_token, safe_decode
from src.config import settings
from src.crypto_service import (
    decrypt_vote_ciphertext,
    generate_rsa_keypair,
    hash_password,
    integrity_hash_for_encrypted_vote,
    parse_iso8601,
    verify_password,
    verify_submission_signature,
)
from src.database import audit_log, get_connection, get_election_row

logger = logging.getLogger("voting")

router = APIRouter()
_db_path = settings.db_file()
_UPLOADS = settings.data_dir / "uploads"
_ALLOWED_CT = {"image/jpeg", "image/png", "image/webp"}
_MAX_UPLOAD = 2 * 1024 * 1024


class RegisterPrecheckBody(BaseModel):
    """Email-only check: same allowlist as register, but does not create an account or require a password."""

    voter_id: str = Field(min_length=1, max_length=128)


class RegisterBody(BaseModel):
    voter_id: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8)


class LoginBody(BaseModel):
    voter_id: str
    password: str
    otp: str | None = None


class AdminLoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class AdminRegisterBody(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8)


class AdminDeleteVoterBody(BaseModel):
    voter_id: str = Field(min_length=1, max_length=128)


class VoteBody(BaseModel):
    voter_id: str
    encrypted_vote: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    timestamp: str


class VoterPasswordBody(BaseModel):
    password: str = Field(min_length=1)


def _normalize_voter_email(voter_id: str) -> str:
    return voter_id.strip().lower()


# Shown on register/login when email is not in STUDENT_EMAIL_ALLOWLIST, and when JWT sub is not allowlisted.
ALLOWLIST_REJECTION_DETAIL = (
    "This email is not in the college authorized database for SecureVote. Only the approved addresses on the server list may register."
)


def _validate_allowed_student_email(voter_id: str) -> str:
    email = _normalize_voter_email(voter_id)
    if not re.match(r"^[a-z0-9._%+-]+@umsystem\.edu$", email):
        raise HTTPException(status_code=400, detail="Use your college email ending with @umsystem.edu")
    if email not in settings.allowed_student_emails():
        raise HTTPException(status_code=403, detail=ALLOWLIST_REJECTION_DETAIL)
    return email


def _assert_jwt_voter_sub_allowlisted(raw_sub: str) -> str:
    """Re-check allowlist on every voter-authenticated request (JWT sub must match configured list)."""
    email = _normalize_voter_email(raw_sub)
    if email not in settings.allowed_student_emails():
        raise HTTPException(status_code=403, detail=ALLOWLIST_REJECTION_DETAIL)
    return email


def _otp_hash(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def _send_login_otp_email(recipient: str, code: str, expires_s: int) -> None:
    mode = (settings.otp_delivery_mode or "demo").strip().lower()
    if mode != "smtp":
        logger.info("OTP for %s is %s (demo mode)", recipient, code)
        return

    host = settings.smtp_host.strip()
    user = settings.smtp_username.strip()
    pwd = settings.smtp_password
    from_email = settings.smtp_from_email.strip() or user
    if not host or not user or not pwd or not from_email:
        raise HTTPException(status_code=500, detail="OTP email service is not configured on server")

    msg = EmailMessage()
    msg["Subject"] = "SecureVote login OTP"
    msg["From"] = from_email
    msg["To"] = recipient
    msg.set_content(
        "Your SecureVote OTP is: "
        f"{code}\n\nThis code expires in {expires_s} seconds."
        "\n\nIf you did not request this, ignore this email."
    )
    try:
        with smtplib.SMTP(host, int(settings.smtp_port), timeout=20) as server:
            if settings.smtp_use_starttls:
                server.starttls()
            server.login(user, pwd)
            server.send_message(msg)
    except Exception as exc:
        logger.exception("Failed to send OTP email to %s", recipient)
        raise HTTPException(status_code=502, detail=f"Failed to send OTP email: {exc}") from exc


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def require_voter(token: str = Depends(bearer_token)) -> str:
    payload = safe_decode(token)
    if not payload or payload.get("role") != "voter" or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    return _assert_jwt_voter_sub_allowlisted(str(payload["sub"]))


def admin_bearer(token: str = Depends(bearer_token)) -> None:
    payload = safe_decode(token)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required")


def optional_voter(authorization: str | None = Header(default=None)) -> str | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    tok = authorization.split(" ", 1)[1].strip()
    if not tok:
        return None
    p = safe_decode(tok)
    if p is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    if p.get("role") == "voter" and p.get("sub"):
        return _assert_jwt_voter_sub_allowlisted(str(p["sub"]))
    return None


@router.get("/voter/session")
def voter_session(voter_sub: str = Depends(require_voter)):
    """Lightweight check used on app load so the UI does not trust localStorage alone."""
    return {"voter_id": voter_sub}


# --- Models via dict / inline ---


@router.post("/register/precheck")
def api_register_precheck(body: RegisterPrecheckBody):
    """Fail fast on the sign-up page: reject emails that are not in ``STUDENT_EMAIL_ALLOWLIST`` before any account exists."""
    voter_id = _validate_allowed_student_email(body.voter_id)
    return {"ok": True, "voter_id": voter_id}


@router.post("/register", status_code=201)
def api_register(body: RegisterBody):
    voter_id = _validate_allowed_student_email(body.voter_id)
    password = body.password
    if not voter_id:
        raise HTTPException(status_code=400, detail="Invalid input format")
    priv_pem, pub_pem = generate_rsa_keypair()
    ph = hash_password(password)
    with get_connection(_db_path) as conn:
        try:
            conn.execute(
                "INSERT INTO voters (voter_id, password_hash, public_key_pem, has_voted) VALUES (?, ?, ?, 0)",
                (voter_id, ph, pub_pem.decode("utf-8")),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="This email is already registered. Use Sign in (not Register) with the same address and password — a one-time code will be sent next.",
            )
        audit_log(conn, "voter_registered", voter_id)
    return {
        "voter_id": voter_id,
        "voter_private_key_pem": priv_pem.decode("utf-8"),
        "message": "Store voter_private_key_pem in this browser only; the server does not retain it.",
    }


@router.post("/login")
def api_login(body: LoginBody):
    voter_id = _validate_allowed_student_email(body.voter_id)
    password = body.password
    otp = (body.otp or "").strip()
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT * FROM voters WHERE voter_id = ?", (voter_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Voter not found")
        if not verify_password(password, row["password_hash"]):
            raise HTTPException(
                status_code=401,
                detail="Incorrect password for this account. The one-time code is only sent after your password is accepted. Use the same password you chose at registration.",
            )
        if not otp:
            code = f"{secrets.randbelow(1_000_000):06d}"
            expires = datetime.now(timezone.utc).timestamp() + int(settings.otp_expire_seconds)
            expires_at = datetime.fromtimestamp(expires, timezone.utc).isoformat().replace("+00:00", "Z")
            _send_login_otp_email(voter_id, code, int(settings.otp_expire_seconds))
            conn.execute(
                "UPDATE voter_login_otps SET consumed = 1 WHERE voter_id = ? AND consumed = 0",
                (voter_id,),
            )
            conn.execute(
                """INSERT INTO voter_login_otps (voter_id, otp_hash, expires_at, consumed, created_at)
                   VALUES (?, ?, ?, 0, ?)""",
                (voter_id, _otp_hash(code), expires_at, _utc_iso()),
            )
            conn.commit()
            payload = {
                "otp_required": True,
                "message": "OTP sent to your college email. Enter it to finish sign in.",
                "expires_in_seconds": int(settings.otp_expire_seconds),
            }
            if settings.expose_otp_in_response and (settings.otp_delivery_mode or "demo").lower() != "smtp":
                payload["dev_otp"] = code
            audit_log(conn, "voter_login_otp_issued", voter_id)
            return payload

        rec = conn.execute(
            """SELECT * FROM voter_login_otps
               WHERE voter_id = ? AND consumed = 0
               ORDER BY id DESC LIMIT 1""",
            (voter_id,),
        ).fetchone()
        if not rec:
            raise HTTPException(status_code=401, detail="No active OTP. Request a new OTP.")
        try:
            if parse_iso8601(rec["expires_at"]) < datetime.now(timezone.utc):
                conn.execute("UPDATE voter_login_otps SET consumed = 1 WHERE id = ?", (rec["id"],))
                conn.commit()
                raise HTTPException(status_code=401, detail="OTP expired. Request a new OTP.")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid OTP state")
        if _otp_hash(otp) != rec["otp_hash"]:
            raise HTTPException(status_code=401, detail="Invalid OTP")
        conn.execute("UPDATE voter_login_otps SET consumed = 1 WHERE id = ?", (rec["id"],))
        conn.commit()
        audit_log(conn, "voter_login", voter_id)
    return {"access_token": create_access_token(voter_id, "voter"), "token_type": "bearer"}


@router.post("/voter/restore-signing-key")
def restore_voter_signing_key(body: VoterPasswordBody, voter_sub: str = Depends(require_voter)):
    """Issue a new RSA key pair after password check.

    Past ballots remain verifiable because each row in ``election_votes`` stores the voter public key
    that was used when the ballot was cast; tally uses that snapshot, not only the live ``voters`` row.
    """
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT * FROM voters WHERE voter_id = ?", (voter_sub,)).fetchone()
        if not row or not verify_password(body.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid password")
        priv_pem, pub_pem = generate_rsa_keypair()
        conn.execute(
            "UPDATE voters SET public_key_pem = ? WHERE voter_id = ?",
            (pub_pem.decode("utf-8"), voter_sub),
        )
        conn.commit()
        audit_log(conn, "voter_signing_key_restored", voter_sub)
    return {"voter_private_key_pem": priv_pem.decode("utf-8")}


@router.get("/admin/election-stats")
def admin_election_stats(_: None = Depends(admin_bearer)):
    """Per-election ballot counts (encrypted votes submitted — not decrypted choices)."""
    with get_connection(_db_path) as conn:
        rows = conn.execute(
            """SELECT e.id, e.title, e.category, e.closed, e.results_announced,
                      (SELECT COUNT(*) FROM election_votes v WHERE v.election_id = e.id) AS ballots_cast,
                      (SELECT COUNT(*) FROM contestants c WHERE c.election_id = e.id) AS contestant_count
               FROM elections e ORDER BY e.id DESC"""
        ).fetchall()
    return {"elections": [dict(r) for r in rows]}


@router.get("/admin/setup-status")
def admin_setup_status():
    with get_connection(_db_path) as conn:
        n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
    return {"needs_first_admin": n == 0}


@router.post("/admin/register-first", status_code=201)
def admin_register_first(body: AdminRegisterBody):
    un = body.username.strip()
    if len(un) < 3 or not re.match(r"^[a-zA-Z0-9_-]+$", un):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3–64 characters (letters, numbers, _ or - only)",
        )
    with get_connection(_db_path) as conn:
        n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
        if n > 0:
            raise HTTPException(
                status_code=403,
                detail="An administrator already exists. Use Admin sign in.",
            )
        try:
            conn.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
                (un, hash_password(body.password), _utc_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Username already taken")
        audit_log(conn, "admin_register_first", un)
    return {"ok": True, "username": un}


@router.post("/admin/login")
def api_admin_login(body: AdminLoginBody):
    un = body.username.strip()
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT * FROM admins WHERE username = ?", (un,)).fetchone()
        if not row or not verify_password(body.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        audit_log(conn, "admin_login", row["username"])
    return {"access_token": create_access_token(row["username"], "admin"), "token_type": "bearer"}


@router.post("/admin/voters/delete")
def admin_delete_voter(body: AdminDeleteVoterBody, _: None = Depends(admin_bearer)):
    """Support / dev: remove a voter so they can register again with a new password. Cascades OTPs and related rows."""
    vid = _normalize_voter_email(body.voter_id)
    with get_connection(_db_path) as conn:
        cur = conn.execute("DELETE FROM voters WHERE voter_id = ?", (vid,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Voter not found")
        conn.commit()
        audit_log(conn, "admin_voter_deleted", vid)
    return {"ok": True, "voter_id": vid}


@router.get("/admin/dashboard-summary")
def admin_dashboard_summary(_: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM election_registrations WHERE status = 'pending'"
        ).fetchone()["c"]
        total_el = conn.execute("SELECT COUNT(*) AS c FROM elections").fetchone()["c"]
        open_el = conn.execute("SELECT COUNT(*) AS c FROM elections WHERE closed = 0").fetchone()["c"]
        published = conn.execute(
            "SELECT COUNT(*) AS c FROM elections WHERE results_announced = 1"
        ).fetchone()["c"]
        votes = conn.execute("SELECT COUNT(*) AS c FROM election_votes").fetchone()["c"]
    return {
        "pending_approvals": pending,
        "elections_total": total_el,
        "elections_open": open_el,
        "results_published": published,
        "votes_recorded": votes,
    }


@router.get("/elections")
def list_elections(voter_id: Annotated[str | None, Depends(optional_voter)]):
    with get_connection(_db_path) as conn:
        rows = conn.execute(
            """SELECT e.id, e.title, e.category, e.starts_at, e.ends_at, e.closed, e.results_announced,
                      e.created_at,
                      (SELECT COUNT(*) FROM contestants c WHERE c.election_id = e.id) AS contestant_count
               FROM elections e ORDER BY e.id DESC"""
        ).fetchall()
        out = []
        for r in rows:
            reg = None
            voted = False
            if voter_id:
                reg_row = conn.execute(
                    "SELECT status FROM election_registrations WHERE election_id = ? AND voter_id = ?",
                    (r["id"], voter_id),
                ).fetchone()
                reg = reg_row["status"] if reg_row else None
                v_row = conn.execute(
                    "SELECT 1 FROM election_votes WHERE election_id = ? AND voter_id = ?",
                    (r["id"], voter_id),
                ).fetchone()
                voted = v_row is not None
            out.append(
                {
                    "id": r["id"],
                    "title": r["title"],
                    "category": r["category"],
                    "starts_at": r["starts_at"],
                    "ends_at": r["ends_at"],
                    "closed": bool(r["closed"]),
                    "results_announced": bool(r["results_announced"]),
                    "contestant_count": r["contestant_count"],
                    "my_registration_status": reg,
                    "my_voted": voted,
                }
            )
        return {"elections": out}


@router.get("/elections/{election_id}/detail")
def election_detail(election_id: int, voter_id: Annotated[str | None, Depends(optional_voter)]):
    with get_connection(_db_path) as conn:
        el = get_election_row(conn, election_id)
        if not el:
            raise HTTPException(status_code=404, detail="Election not found")
        cons = conn.execute(
            "SELECT id, name, image_path, sort_order FROM contestants WHERE election_id = ? ORDER BY sort_order, id",
            (election_id,),
        ).fetchall()
        contestants = [
            {
                "id": c["id"],
                "name": c["name"],
                "image_url": f"/uploads/{election_id}/{Path(c['image_path']).name}",
            }
            for c in cons
        ]
        reg = None
        voted = False
        if voter_id:
            rr = conn.execute(
                "SELECT status FROM election_registrations WHERE election_id = ? AND voter_id = ?",
                (election_id, voter_id),
            ).fetchone()
            reg = rr["status"] if rr else None
            vr = conn.execute(
                "SELECT 1 FROM election_votes WHERE election_id = ? AND voter_id = ?",
                (election_id, voter_id),
            ).fetchone()
            voted = vr is not None
        return {
            "id": el["id"],
            "title": el["title"],
            "category": el["category"],
            "starts_at": el["starts_at"],
            "ends_at": el["ends_at"],
            "closed": bool(el["closed"]),
            "results_announced": bool(el["results_announced"]),
            "public_key_pem": el["public_key_pem"] if voter_id else None,
            "contestants": contestants,
            "my_registration_status": reg,
            "my_voted": voted,
        }


@router.post("/elections/{election_id}/register")
def register_for_election(election_id: int, voter_sub: str = Depends(require_voter)):
    with get_connection(_db_path) as conn:
        el = get_election_row(conn, election_id)
        if not el:
            raise HTTPException(status_code=404, detail="Election not found")
        if el["closed"]:
            raise HTTPException(status_code=403, detail="Election is closed")
        try:
            conn.execute(
                """INSERT INTO election_registrations (election_id, voter_id, status, created_at)
                   VALUES (?, ?, 'pending', ?)""",
                (election_id, voter_sub, _utc_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Already registered for this election")
        audit_log(conn, "election_register_request", f"{voter_sub} -> election {election_id}")
    return {"ok": True, "status": "pending"}


@router.get("/admin/registrations")
def admin_list_registrations(
    status_filter: str = "pending",
    _a: None = Depends(admin_bearer),
):
    if status_filter not in ("pending", "approved", "rejected", "all"):
        status_filter = "pending"
    with get_connection(_db_path) as conn:
        q = """SELECT r.id, r.election_id, r.voter_id, r.status, r.created_at, e.title AS election_title
               FROM election_registrations r JOIN elections e ON e.id = r.election_id"""
        args: list = []
        if status_filter != "all":
            q += " WHERE r.status = ?"
            args.append(status_filter)
        q += " ORDER BY r.id DESC"
        rows = conn.execute(q, args).fetchall()
        return {"registrations": [dict(r) for r in rows]}


@router.post("/admin/registrations/{reg_id}/approve")
def admin_approve_registration(reg_id: int, _a: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        conn.execute(
            "UPDATE election_registrations SET status = 'approved' WHERE id = ? AND status = 'pending'",
            (reg_id,),
        )
        if conn.total_changes != 1:
            raise HTTPException(status_code=404, detail="Pending registration not found")
        conn.commit()
        audit_log(conn, "registration_approved", str(reg_id))
    return {"ok": True}


@router.post("/admin/registrations/{reg_id}/reject")
def admin_reject_registration(reg_id: int, _a: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        conn.execute(
            "UPDATE election_registrations SET status = 'rejected' WHERE id = ? AND status = 'pending'",
            (reg_id,),
        )
        if conn.total_changes != 1:
            raise HTTPException(status_code=404, detail="Pending registration not found")
        conn.commit()
        audit_log(conn, "registration_rejected", str(reg_id))
    return {"ok": True}


@router.post("/admin/elections")
async def admin_create_election(
    title: str = Form(...),
    category: str = Form(...),
    starts_at: str = Form(...),
    ends_at: str = Form(...),
    contestant_names: str = Form(...),
    photos: list[UploadFile] = File(...),
    _a: None = Depends(admin_bearer),
):
    if category not in ("class", "department", "campus"):
        raise HTTPException(status_code=400, detail="Invalid category")
    try:
        names = json.loads(contestant_names)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="contestant_names must be a JSON array of strings")
    if not isinstance(names, list) or len(names) < 1:
        raise HTTPException(status_code=400, detail="At least one contestant required")
    if len(names) != len(photos):
        raise HTTPException(status_code=400, detail="Each contestant needs one photo")
    names = [str(n).strip() for n in names]
    if any(len(n) < 1 for n in names):
        raise HTTPException(status_code=400, detail="Contestant names must be non-empty")

    for p in photos:
        if p.content_type not in _ALLOWED_CT:
            raise HTTPException(status_code=400, detail=f"Unsupported image type: {p.content_type}")
        body = await p.read()
        if len(body) > _MAX_UPLOAD:
            raise HTTPException(status_code=400, detail="Image too large (max 2MB)")

    priv, pub = generate_rsa_keypair()
    with get_connection(_db_path) as conn:
        cur = conn.execute(
            """INSERT INTO elections (title, category, public_key_pem, private_key_pem, starts_at, ends_at,
               closed, results_announced, results_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, 0, NULL, ?)""",
            (title.strip(), category, pub.decode("utf-8"), priv.decode("utf-8"), starts_at, ends_at, _utc_iso()),
        )
        eid = cur.lastrowid
        conn.commit()

    _UPLOADS.mkdir(parents=True, exist_ok=True)
    election_dir = _UPLOADS / str(eid)
    election_dir.mkdir(parents=True, exist_ok=True)

    ext_map = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}

    with get_connection(_db_path) as conn:
        for i, (p, name) in enumerate(zip(photos, names, strict=True)):
            await p.seek(0)
            raw = await p.read()
            ext = ext_map.get(p.content_type, ".bin")
            fname = f"{uuid.uuid4().hex}{ext}"
            fp = election_dir / fname
            fp.write_bytes(raw)
            rel = f"{eid}/{fname}"
            conn.execute(
                """INSERT INTO contestants (election_id, name, image_path, sort_order)
                   VALUES (?, ?, ?, ?)""",
                (eid, name, rel, i),
            )
        conn.commit()
        audit_log(conn, "election_created", f"id={eid} title={title!r}")

    return {"ok": True, "election_id": eid}


@router.post("/elections/{election_id}/vote")
def api_vote(election_id: int, body: VoteBody, voter_sub: str = Depends(require_voter)):
    voter_id = body.voter_id
    encrypted_vote = body.encrypted_vote
    sig = body.signature
    ts = body.timestamp
    if voter_id != voter_sub:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        ts_p = parse_iso8601(ts)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid vote format")

    with get_connection(_db_path) as conn:
        el = get_election_row(conn, election_id)
        if not el:
            raise HTTPException(status_code=500, detail="Internal server error")
        if el["closed"]:
            raise HTTPException(status_code=403, detail="Election is closed")
        w_start = parse_iso8601(el["starts_at"])
        w_end = parse_iso8601(el["ends_at"])
        if not (w_start <= ts_p <= w_end):
            raise HTTPException(status_code=422, detail="Vote outside election window")

        reg = conn.execute(
            "SELECT status FROM election_registrations WHERE election_id = ? AND voter_id = ?",
            (election_id, voter_id),
        ).fetchone()
        if not reg or reg["status"] != "approved":
            raise HTTPException(status_code=403, detail="Not approved for this election")

        voter = conn.execute("SELECT * FROM voters WHERE voter_id = ?", (voter_id,)).fetchone()
        if not voter:
            raise HTTPException(status_code=400, detail="Invalid vote format")

        existing = conn.execute(
            "SELECT 1 FROM election_votes WHERE election_id = ? AND voter_id = ?",
            (election_id, voter_id),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=403, detail="Voter has already voted")

        pub_pem = voter["public_key_pem"].encode("utf-8")
        if not verify_submission_signature(encrypted_vote, ts, sig, pub_pem):
            raise HTTPException(status_code=409, detail="Invalid signature")

        try:
            plain = decrypt_vote_ciphertext(encrypted_vote, el["private_key_pem"].encode("utf-8"))
            obj = json.loads(plain.decode("utf-8"))
            cid = int(obj.get("contestant_id", -1))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid vote payload")
        c_ok = conn.execute(
            "SELECT 1 FROM contestants WHERE id = ? AND election_id = ?",
            (cid, election_id),
        ).fetchone()
        if not c_ok:
            raise HTTPException(status_code=400, detail="Invalid contestant")

        try:
            h = integrity_hash_for_encrypted_vote(encrypted_vote)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid vote format")

        voter_pub_snapshot = voter["public_key_pem"]
        try:
            conn.execute(
                """INSERT INTO election_votes (election_id, voter_id, encrypted_vote, signature, integrity_hash, timestamp, voter_public_key_pem)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (election_id, voter_id, encrypted_vote, sig, h, ts, voter_pub_snapshot),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=403, detail="Voter has already voted")
        audit_log(conn, "vote_cast", f"{voter_id} election {election_id}")
    return {"ok": True}


@router.post("/admin/elections/{election_id}/close")
def admin_close_election(election_id: int, _a: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        el = get_election_row(conn, election_id)
        if not el:
            raise HTTPException(status_code=404, detail="Election not found")
        conn.execute("UPDATE elections SET closed = 1 WHERE id = ?", (election_id,))
        conn.commit()
        audit_log(conn, "election_closed", str(election_id))
    return {"ok": True}


def _compute_tally(conn: sqlite3.Connection, election_id: int) -> tuple[dict, dict, int, list[str]]:
    el = get_election_row(conn, election_id)
    if not el:
        raise HTTPException(status_code=404, detail="Election not found")
    rows = conn.execute("SELECT * FROM election_votes WHERE election_id = ?", (election_id,)).fetchall()
    priv_pem = el["private_key_pem"].encode("utf-8")
    by_id: dict[str, int] = {}
    by_name: dict[str, int] = {}
    failures: list[str] = []
    valid = 0
    id_to_name = {
        str(r["id"]): r["name"]
        for r in conn.execute("SELECT id, name FROM contestants WHERE election_id = ?", (election_id,)).fetchall()
    }
    for r in rows:
        ev = r["encrypted_vote"]
        if integrity_hash_for_encrypted_vote(ev) != r["integrity_hash"]:
            failures.append(f"integrity:{r['voter_id']}")
            continue
        snap = r["voter_public_key_pem"] if r["voter_public_key_pem"] else None
        if snap:
            pub_pem = snap.encode("utf-8")
        else:
            pub = conn.execute("SELECT public_key_pem FROM voters WHERE voter_id = ?", (r["voter_id"],)).fetchone()
            pub_pem = pub["public_key_pem"].encode("utf-8") if pub else b""
        if not pub_pem or not verify_submission_signature(ev, r["timestamp"], r["signature"], pub_pem):
            failures.append(f"signature:{r['voter_id']}")
            continue
        try:
            plain = decrypt_vote_ciphertext(ev, priv_pem)
            obj = json.loads(plain.decode("utf-8"))
            cid = str(int(obj.get("contestant_id", -1)))
        except Exception:
            failures.append(f"decrypt:{r['voter_id']}")
            continue
        if cid not in id_to_name:
            failures.append(f"contestant:{r['voter_id']}")
            continue
        name = id_to_name[cid]
        by_id[cid] = by_id.get(cid, 0) + 1
        by_name[name] = by_name.get(name, 0) + 1
        valid += 1
    return by_id, by_name, valid, failures


@router.post("/admin/elections/{election_id}/publish-results")
def admin_publish_results(election_id: int, _a: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        el = get_election_row(conn, election_id)
        if not el:
            raise HTTPException(status_code=404, detail="Election not found")
        if not el["closed"]:
            raise HTTPException(status_code=403, detail="Election not closed")
        by_id, by_name, valid, failures = _compute_tally(conn, election_id)
        payload = {
            "by_contestant_id": by_id,
            "by_name": by_name,
            "total_valid_votes": valid,
            "integrity_failures": failures,
        }
        conn.execute(
            "UPDATE elections SET results_announced = 1, results_json = ? WHERE id = ?",
            (json.dumps(payload), election_id),
        )
        conn.commit()
        audit_log(conn, "results_published", str(election_id))
    return {"ok": True, **payload}


@router.get("/elections/{election_id}/results")
def get_public_results(election_id: int):
    with get_connection(_db_path) as conn:
        el = get_election_row(conn, election_id)
        if not el:
            raise HTTPException(status_code=404, detail="Election not found")
        if not el["results_announced"] or not el["results_json"]:
            raise HTTPException(status_code=403, detail="Results not published yet")
        data = json.loads(el["results_json"])
        cons = conn.execute(
            "SELECT id, name, image_path FROM contestants WHERE election_id = ? ORDER BY sort_order, id",
            (election_id,),
        ).fetchall()
        breakdown = []
        for c in cons:
            cid = str(c["id"])
            breakdown.append(
                {
                    "contestant_id": c["id"],
                    "name": c["name"],
                    "votes": data.get("by_contestant_id", {}).get(cid, 0),
                    "image_url": f"/uploads/{election_id}/{Path(c['image_path']).name}",
                }
            )
        return {
            "election_id": election_id,
            "title": el["title"],
            "category": el["category"],
            "total_valid_votes": data.get("total_valid_votes", 0),
            "by_name": data.get("by_name", {}),
            "contestants": breakdown,
        }


# --- Legacy single-election shims (optional compatibility) ---


@router.get("/legacy/election/info")
def legacy_election_info():
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT * FROM elections ORDER BY id ASC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No elections configured")
        return {
            "public_key_pem": row["public_key_pem"],
            "starts_at": row["starts_at"],
            "ends_at": row["ends_at"],
            "closed": bool(row["closed"]),
            "election_id": row["id"],
        }


@router.post("/legacy/vote")
def legacy_vote(body: dict, voter_sub: str = Depends(require_voter)):
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT id FROM elections ORDER BY id ASC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(status_code=500, detail="No elections configured")
    return api_vote(int(row["id"]), body, voter_sub)


@router.post("/legacy/election/close")
def legacy_close(_a: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT id FROM elections ORDER BY id ASC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No elections")
        conn.execute("UPDATE elections SET closed = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        audit_log(conn, "election_closed", str(row["id"]))
    return {"ok": True, "closed": True}


@router.post("/legacy/tally")
def legacy_tally(_a: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        row = conn.execute("SELECT id FROM elections ORDER BY id ASC LIMIT 1").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No elections")
        eid = int(row["id"])
        el = get_election_row(conn, eid)
        if not el["closed"]:
            raise HTTPException(status_code=403, detail="Election not closed")
        _, by_name, valid, failures = _compute_tally(conn, eid)
    return {
        "closed": True,
        "total_valid_votes": valid,
        "choices": by_name,
        "integrity_failures": failures,
    }
