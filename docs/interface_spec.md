# Interface Specification

## Overview

This document defines the interface formats, required fields, validation rules, and error codes for the Secure Digital Voting System.

The goal of this specification is to ensure clarity, consistency, and misuse prevention in how system components communicate.

This document will be frozen during Week 5 (Spec Freeze).

---

# 1. System Actors

- Voter
- Election Authority (Admin)
- Voting Server

---

# 2. Registration Interface

## Endpoint
POST /register

## Request Format

{
  "voter_id": "string",
  "password": "string"
}

## Required Fields

- voter_id (string, unique)
- password (string, minimum 8 characters)

## Processing Rules

- Password must be hashed using bcrypt before storage.
- Duplicate voter_id must be rejected.
- Plaintext passwords must never be stored.

## Error Codes

- 400 – Invalid input format
- 409 – Voter already exists
- 500 – Internal server error

---

# 3. Login Interface

## Endpoint
POST /login

## Request Format

{
  "voter_id": "string",
  "password": "string"
}

## Required Fields

- voter_id
- password

## Processing Rules

- Password must be verified using bcrypt hash comparison.
- Session token generated upon successful login.

## Error Codes

- 400 – Invalid input format
- 401 – Authentication failed
- 404 – Voter not found

---

# 4. Vote Submission Interface

## Endpoint
POST /vote

## Request Format

{
  "voter_id": "string",
  "encrypted_vote": "string",
  "signature": "string",
  "timestamp": "string"
}

## Field Definitions

- voter_id: Unique identifier of voter
- encrypted_vote: RSA-encrypted vote data
- signature: Digital signature generated using voter private key
- timestamp: ISO 8601 formatted timestamp

## Required Fields

All fields are mandatory.

## Validation Rules

- Signature must be verified before accepting vote.
- Voter must not have already voted.
- Encrypted vote must not be empty.
- Timestamp must be within election window.

## Error Codes

- 400 – Invalid vote format
- 401 – Unauthorized (not logged in)
- 403 – Voter has already voted
- 409 – Invalid signature
- 422 – Vote outside election window
- 500 – Internal server error

---

# 5. Vote Tally Interface

## Endpoint
POST /tally

## Access Control

Admin-only endpoint.

## Processing Rules

- Verify integrity hash before decryption.
- Decrypt votes using election private key.
- Count votes securely.
- Generate final result summary.

## Error Codes

- 401 – Unauthorized access
- 403 – Election not closed
- 500 – Decryption failure

---

# 6. Data Storage Format

## Stored Vote Record Structure

{
  "voter_id": "string",
  "encrypted_vote": "string",
  "signature": "string",
  "hash": "string",
  "timestamp": "string"
}

## Storage Rules

- Only encrypted_vote is stored (never plaintext vote).
- Hash is computed using SHA-256 over encrypted_vote.
- No private keys are stored in plaintext.

---

# 7. Security Constraints

- All sensitive data must be encrypted in transit (HTTPS assumed).
- All private keys must be securely stored and access-controlled.
- Replay attacks must be prevented using timestamp validation.
- Duplicate voting must be blocked at application level.

---

# 8. Spec Freeze Policy

All message formats, required fields, and error codes will be finalized and frozen in Week 5.

After freeze:
- Interface changes require documented justification.
- Version tag will be created in repository.

---

# Conclusion

This interface specification defines structured communication rules, required validation logic, and clear error handling for the Secure Digital Voting System. The design emphasizes security, clarity, and misuse prevention in alignment with applied cryptography best practices.
