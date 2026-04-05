#!/usr/bin/env python3
"""Walk through the demo story (proposal): register → login → vote → close → tally.

Run the API first:
  cd <repo> && .venv/bin/uvicorn src.main:app --reload

Then:
  .venv/bin/python scripts/demo_flow.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto_service import encrypt_vote_plaintext, sign_submission

BASE = "http://127.0.0.1:8000"


def main() -> int:
    with httpx.Client(base_url=BASE, timeout=30.0) as client:
        voter_id = "demo_voter"
        password = "demopass12"

        r = client.post("/register", json={"voter_id": voter_id, "password": password})
        r.raise_for_status()
        reg = r.json()
        priv_pem = reg["voter_private_key_pem"]
        print("Registered; save voter private PEM offline in a real deployment.")

        r = client.post("/login", json={"voter_id": voter_id, "password": password})
        r.raise_for_status()
        token = r.json()["access_token"]

        info = client.get("/election/info").json()
        pub = info["public_key_pem"]
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        plain = json.dumps({"choice": "candidate_a"}).encode("utf-8")
        enc = encrypt_vote_plaintext(plain, pub.encode("utf-8"))
        sig = sign_submission(enc, ts, priv_pem.encode("utf-8"))

        r = client.post(
            "/vote",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "voter_id": voter_id,
                "encrypted_vote": enc,
                "signature": sig,
                "timestamp": ts,
            },
        )
        r.raise_for_status()
        print("Vote submitted (encrypted + signed).")

        admin_user = input("Admin username [admin]: ").strip() or "admin"
        admin_pw = input("Admin password (see .env ADMIN_PASSWORD): ").strip()
        ar = client.post("/api/admin/login", json={"username": admin_user, "password": admin_pw})
        ar.raise_for_status()
        adm = ar.json()["access_token"]

        client.post("/election/close", headers={"Authorization": f"Bearer {adm}"}).raise_for_status()
        print("Election closed.")

        tr = client.post("/tally", headers={"Authorization": f"Bearer {adm}"})
        tr.raise_for_status()
        print("Tally:", json.dumps(tr.json(), indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except httpx.HTTPError as e:
        print("HTTP error:", e, file=sys.stderr)
        raise SystemExit(1)
