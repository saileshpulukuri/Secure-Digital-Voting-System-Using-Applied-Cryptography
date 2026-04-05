# Secure Digital Voting System Using Applied Cryptography

Course-scale voting platform with a **web UI** at `/`, a JSON API under `/api`, and cryptography aligned with `docs/` (proposal, CDDR, interface spec, key lifecycle).



The root path `/` must serve the app. This project now serves **`GET /`** as the SecureVote UI. JSON APIs live under **`/api/...`** (for example `/api/login`). Hitting a path that does not exist still returns JSON `Not Found` from FastAPI.

## Security properties

| Property | Mechanism |
|----------|-----------|
| Vote confidentiality | Per-election RSA-2048 OAEP (SHA-256) |
| Integrity of stored ciphertext | SHA-256 over ciphertext |
| Passwords | bcrypt |
| Sessions | JWT (`Bearer`) |
| Ballot origin | RSA-PSS + SHA-256 over UTF-8 `encrypted_vote ‖ \| ‖ timestamp` |

Voter **signing** private keys are returned once at registration and stored in **browser `localStorage`** for the demo UI (not kept on the server). Each election has its own RSA key pair in the database.

## Layout

```
.
├── docs/
├── src/           # main.py, api_routes.py, crypto_service.py, database.py, …
├── static/        # CSS + JS for the UI
├── templates/     # app.html (single-page shell)
├── tests/
├── data/          # runtime DB + uploads (gitignored)
└── requirements.txt
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/.env.example .env   # set JWT_SECRET and ADMIN_PASSWORD
```

## Run

```bash
uvicorn src.main:app --reload --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/** in a browser.

- **Voter tab**: sign in or create an account (signing key saved in this browser).
- **Admin tab**: password is `ADMIN_PASSWORD` from `.env` (hashed once into the DB on first run).
- **Admin**: *Create election* (class / department / campus), add contestant names + photos, set open/close times. *Approvals* for registration requests. *Manage* to **Close** an election, then **Publish results** so voters see counts in **Results**.

### Environment

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | HMAC key for JWTs |
| `ADMIN_PASSWORD` | Used to seed the first admin account if the `admins` table is empty (bcrypt in DB) |
| `ADMIN_USERNAME` | Username for that seeded account (default `admin`) |
| `DATABASE_PATH` | Optional SQLite path (default `./data/voting.db`) |
| `DATA_DIR` | Optional data root for DB default path + `uploads/` |

## API (summary)

All under prefix **`/api`**:

- `POST /api/register`, `POST /api/login`, `GET /api/admin/setup-status`, `POST /api/admin/register-first` (only if no admins), `POST /api/admin/login` (username + password), `GET /api/admin/dashboard-summary`
- `GET /api/elections` (optional `Authorization: Bearer` voter token for per-user status)
- `GET /api/elections/{id}/detail`
- `POST /api/elections/{id}/register` (voter)
- `GET /api/admin/registrations?status_filter=pending`
- `POST /api/admin/registrations/{id}/approve|reject`
- `POST /api/admin/elections` (multipart: title, category, starts_at, ends_at, contestant_names JSON, photos[])
- `POST /api/elections/{id}/vote` — body: `voter_id`, `encrypted_vote` (base64), `signature`, `timestamp`; plaintext JSON is `{"contestant_id": <int>}`
- `POST /api/admin/elections/{id}/close`, `POST /api/admin/elections/{id}/publish-results`
- `GET /api/elections/{id}/results` (after publish)

Legacy shims for the original single-election flow: `/api/legacy/...`.

## Tests

```bash
pytest
```

## License

MIT — see `LICENSE`.
