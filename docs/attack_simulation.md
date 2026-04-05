# Simulated Attack: Signature Replay and Forgery

## Threat

An attacker tries to submit a vote using another voter’s identity by reusing or forging a digital signature, or by replaying a previously captured payload.

## Mechanisms Tested

1. **Forged signature** — Random or incorrectly generated RSA-PSS signature over the submission digest is rejected during `POST /vote` (HTTP 409, invalid signature).
2. **Binding to ciphertext and timestamp** — RSA-PSS + SHA-256 signs the UTF-8 string `encrypted_vote ‖ '|' ‖ timestamp` as a single message. Changing the timestamp after signing invalidates the signature (see unit test `test_reject_signature_on_tampered_timestamp`).
3. **Replay of an old vote** — If an attacker resubmits the same encrypted vote and signature with an old timestamp, validation fails when the timestamp falls outside the configured election window (HTTP 422).

## Mitigation Summary

| Control | Purpose |
|--------|---------|
| RSA-PSS + SHA-256 | Ensures signatures are unforgeable without the voter’s private key |
| Timestamp + window check | Limits replay to the active election period |
| Per-voter `has_voted` flag | Prevents a second accepted ballot from the same voter ID |
| JWT session for `/vote` | Ensures the `voter_id` in the body matches the authenticated subject |

This aligns with the proposal success criterion: *at least one simulated attack is documented and mitigated*.
