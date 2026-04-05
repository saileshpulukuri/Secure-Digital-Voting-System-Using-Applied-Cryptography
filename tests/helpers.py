"""Test helpers to build encrypted + signed ballots."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from src.crypto_service import encrypt_vote_plaintext, sign_submission

PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def election_window() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    end = (now + timedelta(days=7)).isoformat().replace("+00:00", "Z")
    return start, end


def build_ballot(choice: str, election_pub_pem: str, voter_priv_pem: str) -> tuple[str, str, str]:
    ts = iso_timestamp()
    plain = json.dumps({"choice": choice}).encode("utf-8")
    enc = encrypt_vote_plaintext(plain, election_pub_pem.encode("utf-8"))
    sig = sign_submission(enc, ts, voter_priv_pem.encode("utf-8"))
    return enc, sig, ts


def build_ballot_contestant(contestant_id: int, election_pub_pem: str, voter_priv_pem: str) -> tuple[str, str, str]:
    ts = iso_timestamp()
    plain = json.dumps({"contestant_id": contestant_id}).encode("utf-8")
    enc = encrypt_vote_plaintext(plain, election_pub_pem.encode("utf-8"))
    sig = sign_submission(enc, ts, voter_priv_pem.encode("utf-8"))
    return enc, sig, ts


def create_test_election(client, admin_token: str) -> int:
    import json as _json

    starts_at, ends_at = election_window()
    files = [
        ("photos", ("a.png", PNG_BYTES, "image/png")),
        ("photos", ("b.png", PNG_BYTES, "image/png")),
    ]
    data = {
        "title": "Test election",
        "category": "class",
        "starts_at": starts_at,
        "ends_at": ends_at,
        "contestant_names": _json.dumps(["Alice", "Bob"]),
    }
    r = client.post(
        "/api/admin/elections",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    return int(r.json()["election_id"])
