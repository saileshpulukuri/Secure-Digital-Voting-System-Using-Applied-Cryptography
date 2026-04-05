"""API tests for multi-election flow and /api routes."""

from tests.helpers import build_ballot_contestant, create_test_election, iso_timestamp


def test_register_login_vote_results_flow(client):
    r = client.post("/api/register", json={"voter_id": "v1", "password": "password12"})
    assert r.status_code == 201
    priv = r.json()["voter_private_key_pem"]

    r = client.post("/api/login", json={"voter_id": "v1", "password": "password12"})
    assert r.status_code == 200
    token = r.json()["access_token"]

    admin = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    )
    assert admin.status_code == 200
    adm = admin.json()["access_token"]

    eid = create_test_election(client, adm)

    assert client.post(f"/api/elections/{eid}/register", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    pending = client.get("/api/admin/registrations?status_filter=pending", headers={"Authorization": f"Bearer {adm}"})
    assert pending.status_code == 200
    reg_id = pending.json()["registrations"][0]["id"]
    assert client.post(
        f"/api/admin/registrations/{reg_id}/approve", headers={"Authorization": f"Bearer {adm}"}
    ).status_code == 200

    detail = client.get(f"/api/elections/{eid}/detail", headers={"Authorization": f"Bearer {token}"})
    assert detail.status_code == 200
    pub = detail.json()["public_key_pem"]
    enc, sig, ts = build_ballot_contestant(1, pub, priv)

    r = client.post(
        f"/api/elections/{eid}/vote",
        headers={"Authorization": f"Bearer {token}"},
        json={"voter_id": "v1", "encrypted_vote": enc, "signature": sig, "timestamp": ts},
    )
    assert r.status_code == 200

    assert client.post(f"/api/admin/elections/{eid}/close", headers={"Authorization": f"Bearer {adm}"}).status_code == 200

    pubres = client.post(f"/api/admin/elections/{eid}/publish-results", headers={"Authorization": f"Bearer {adm}"})
    assert pubres.status_code == 200
    assert pubres.json()["total_valid_votes"] == 1

    res = client.get(f"/api/elections/{eid}/results")
    assert res.status_code == 200
    assert res.json()["total_valid_votes"] == 1
    alice = next(c for c in res.json()["contestants"] if c["name"] == "Alice")
    assert alice["votes"] == 1


def test_double_registration_conflict(client):
    client.post("/api/register", json={"voter_id": "dup", "password": "password12"})
    r = client.post("/api/register", json={"voter_id": "dup", "password": "password12"})
    assert r.status_code == 409


def test_double_vote_blocked(client):
    reg = client.post("/api/register", json={"voter_id": "twice", "password": "password12"}).json()
    priv = reg["voter_private_key_pem"]
    tok = client.post("/api/login", json={"voter_id": "twice", "password": "password12"}).json()["access_token"]
    adm = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    eid = create_test_election(client, adm)
    client.post(f"/api/elections/{eid}/register", headers={"Authorization": f"Bearer {tok}"})
    reg_row = client.get("/api/admin/registrations?status_filter=pending", headers={"Authorization": f"Bearer {adm}"}).json()[
        "registrations"
    ][0]
    client.post(f"/api/admin/registrations/{reg_row['id']}/approve", headers={"Authorization": f"Bearer {adm}"})
    d = client.get(f"/api/elections/{eid}/detail", headers={"Authorization": f"Bearer {tok}"}).json()
    pub = d["public_key_pem"]
    h = {"Authorization": f"Bearer {tok}"}
    enc, sig, ts = build_ballot_contestant(1, pub, priv)
    body = {"voter_id": "twice", "encrypted_vote": enc, "signature": sig, "timestamp": ts}
    assert client.post(f"/api/elections/{eid}/vote", headers=h, json=body).status_code == 200
    enc2, sig2, ts2 = build_ballot_contestant(2, pub, priv)
    body2 = {"voter_id": "twice", "encrypted_vote": enc2, "signature": sig2, "timestamp": ts2}
    assert client.post(f"/api/elections/{eid}/vote", headers=h, json=body2).status_code == 403


def test_invalid_signature_rejected(client):
    reg = client.post("/api/register", json={"voter_id": "sig", "password": "password12"}).json()
    priv = reg["voter_private_key_pem"]
    tok = client.post("/api/login", json={"voter_id": "sig", "password": "password12"}).json()["access_token"]
    adm = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    eid = create_test_election(client, adm)
    client.post(f"/api/elections/{eid}/register", headers={"Authorization": f"Bearer {tok}"})
    rr = client.get("/api/admin/registrations?status_filter=pending", headers={"Authorization": f"Bearer {adm}"}).json()[
        "registrations"
    ][0]
    client.post(f"/api/admin/registrations/{rr['id']}/approve", headers={"Authorization": f"Bearer {adm}"})
    d = client.get(f"/api/elections/{eid}/detail", headers={"Authorization": f"Bearer {tok}"}).json()
    enc, _, ts = build_ballot_contestant(1, d["public_key_pem"], priv)
    r = client.post(
        f"/api/elections/{eid}/vote",
        headers={"Authorization": f"Bearer {tok}"},
        json={"voter_id": "sig", "encrypted_vote": enc, "signature": "YmFk", "timestamp": ts},
    )
    assert r.status_code == 409


def test_vote_requires_auth(client):
    adm = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    eid = create_test_election(client, adm)
    r = client.post(
        f"/api/elections/{eid}/vote",
        json={
            "voter_id": "nobody",
            "encrypted_vote": "eA==",
            "signature": "eA==",
            "timestamp": iso_timestamp(),
        },
    )
    assert r.status_code == 401


def test_publish_forbidden_before_close(client):
    client.post("/api/register", json={"voter_id": "t1", "password": "password12"})
    admin = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    eid = create_test_election(client, admin)
    r = client.post(f"/api/admin/elections/{eid}/publish-results", headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code == 403


def test_home_page_ok(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"SecureVote" in r.content or b"Welcome back" in r.content


def test_admin_setup_status_seeded(client):
    assert client.get("/api/admin/setup-status").json()["needs_first_admin"] is False


def test_admin_register_first_forbidden_after_seed(client):
    r = client.post(
        "/api/admin/register-first",
        json={"username": "other", "password": "password12"},
    )
    assert r.status_code == 403


def test_restore_signing_key_ok_before_any_vote(client):
    client.post("/api/register", json={"voter_id": "rekey1", "password": "password12"})
    tok = client.post("/api/login", json={"voter_id": "rekey1", "password": "password12"}).json()[
        "access_token"
    ]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/api/voter/restore-signing-key", headers=h, json={"password": "password12"})
    assert r.status_code == 200
    assert "BEGIN PRIVATE KEY" in r.json()["voter_private_key_pem"]


def test_restore_signing_key_wrong_password(client):
    client.post("/api/register", json={"voter_id": "rekey2", "password": "password12"})
    tok = client.post("/api/login", json={"voter_id": "rekey2", "password": "password12"}).json()[
        "access_token"
    ]
    r = client.post(
        "/api/voter/restore-signing-key",
        headers={"Authorization": f"Bearer {tok}"},
        json={"password": "wrong-pass-xxx"},
    )
    assert r.status_code == 401


def test_restore_signing_key_after_vote_allows_second_election_and_tally(client):
    """Ballots store voter public key at cast time; rotating keys does not break older tallies."""
    reg = client.post("/api/register", json={"voter_id": "rekey3", "password": "password12"}).json()
    priv1 = reg["voter_private_key_pem"]
    tok = client.post("/api/login", json={"voter_id": "rekey3", "password": "password12"}).json()[
        "access_token"
    ]
    h = {"Authorization": f"Bearer {tok}"}
    adm = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    ah = {"Authorization": f"Bearer {adm}"}

    e1 = create_test_election(client, adm)
    client.post(f"/api/elections/{e1}/register", headers=h)
    rr = client.get("/api/admin/registrations?status_filter=pending", headers=ah).json()["registrations"][0]
    client.post(f"/api/admin/registrations/{rr['id']}/approve", headers=ah)
    d1 = client.get(f"/api/elections/{e1}/detail", headers=h).json()
    cid1 = d1["contestants"][0]["id"]
    enc1, sig1, ts1 = build_ballot_contestant(cid1, d1["public_key_pem"], priv1)
    assert (
        client.post(
            f"/api/elections/{e1}/vote",
            headers=h,
            json={"voter_id": "rekey3", "encrypted_vote": enc1, "signature": sig1, "timestamp": ts1},
        ).status_code
        == 200
    )

    r = client.post("/api/voter/restore-signing-key", headers=h, json={"password": "password12"})
    assert r.status_code == 200
    priv2 = r.json()["voter_private_key_pem"]

    e2 = create_test_election(client, adm)
    client.post(f"/api/elections/{e2}/register", headers=h)
    pending = client.get("/api/admin/registrations?status_filter=pending", headers=ah).json()["registrations"]
    rr2 = next(x for x in pending if x["election_id"] == e2)
    client.post(f"/api/admin/registrations/{rr2['id']}/approve", headers=ah)
    d2 = client.get(f"/api/elections/{e2}/detail", headers=h).json()
    cid2 = d2["contestants"][0]["id"]
    enc2, sig2, ts2 = build_ballot_contestant(cid2, d2["public_key_pem"], priv2)
    assert (
        client.post(
            f"/api/elections/{e2}/vote",
            headers=h,
            json={"voter_id": "rekey3", "encrypted_vote": enc2, "signature": sig2, "timestamp": ts2},
        ).status_code
        == 200
    )

    assert client.post(f"/api/admin/elections/{e1}/close", headers=ah).status_code == 200
    pub1 = client.post(f"/api/admin/elections/{e1}/publish-results", headers=ah)
    assert pub1.status_code == 200
    assert pub1.json()["total_valid_votes"] == 1


def test_admin_election_stats_requires_admin(client):
    assert client.get("/api/admin/election-stats").status_code == 401
    adm = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    r = client.get("/api/admin/election-stats", headers={"Authorization": f"Bearer {adm}"})
    assert r.status_code == 200
    assert "elections" in r.json()
