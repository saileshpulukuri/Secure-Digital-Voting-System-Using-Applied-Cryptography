# Key Lifecycle Management Plan

## Overview

This document defines the lifecycle management of cryptographic keys used in the Secure Digital Voting System. Proper key management is critical to maintaining confidentiality, integrity, authentication, and non-repudiation.

The key lifecycle includes:

- Key generation
- Key distribution
- Key storage
- Key usage
- Key rotation
- Key revocation
- Compromise handling
- Key destruction

This document will be finalized and frozen during Week 5 (Spec Freeze).

---

# 1. Key Types in the System

The system uses the following key types:

## 1.1 Election Key Pair
- Election Public Key
- Election Private Key

Purpose:
- Public key encrypts votes.
- Private key decrypts votes during tally phase.

## 1.2 Voter Key Pair
- Voter Public Key
- Voter Private Key

Purpose:
- Private key signs vote submissions.
- Public key verifies voter signature.

---

# 2. Key Generation

## 2.1 Election Key Generation

- Generated at system initialization.
- RSA 2048-bit key size.
- Generated using secure cryptographic random number generator.
- Generated only once per election cycle.

## 2.2 Voter Key Generation

Two possible models:

Option A (Server-managed):
- Keys generated during voter registration.
- Public key stored in database.
- Private key securely provided to voter.

Option B (Client-managed):
- Voter generates key pair locally.
- Only public key registered with system.

For this academic implementation, keys will be generated securely using standard cryptographic libraries.

---

# 3. Key Distribution

## Election Public Key
- Publicly available to all registered voters.
- Used only for vote encryption.

## Election Private Key
- Never distributed.
- Accessible only to authorized election authority.

## Voter Public Keys
- Stored in database.
- Used for signature verification.

## Voter Private Keys
- Must never be transmitted in plaintext.
- Must not be stored in source code.

---

# 4. Key Storage

## Election Private Key Storage

- Stored securely on server.
- Access restricted to admin-level processes.
- Not hardcoded in repository.
- Not committed to Git.

## Voter Public Keys

- Stored in database.
- Linked to voter ID.

## Password Protection

- Private keys (if stored) must be protected using secure file permissions.
- No private keys are stored in plaintext configuration files.

---

# 5. Key Usage Policy

## During Voting Phase

- Voters use election public key to encrypt vote.
- Voters use private key to sign vote.
- Server verifies signature using voter public key.

## During Tally Phase

- Admin verifies vote integrity (hash check).
- Election private key decrypts encrypted votes.
- Votes are counted only after decryption.

Decryption is strictly prohibited before election closes.

---

# 6. Key Rotation Policy

## Election Keys

- Valid only for a single election cycle.
- New key pair generated for each new election.
- Old keys archived securely.

## Voter Keys

- Valid until revoked or compromised.
- Future enhancement: periodic key rotation.

---

# 7. Key Compromise Handling

## If Election Private Key is Compromised

- Immediately invalidate current election.
- Generate new key pair.
- Restart election process.
- Document incident.

## If Voter Private Key is Compromised

- Revoke voter key.
- Generate new key pair.
- Re-register public key.

All compromise events must be logged and documented.

---

# 8. Key Revocation

- Compromised or invalid keys must be marked as revoked.
- Revoked public keys cannot be used for signature verification.
- System must reject votes signed with revoked keys.

---

# 9. Key Destruction

After election cycle ends:

- Old election private keys securely deleted.
- Backup copies destroyed.
- Revoked keys archived only if necessary for audit.

Secure deletion methods should be used where possible.

---

# 10. Misuse Prevention Measures

- Private keys never stored in repository.
- Keys never hardcoded in source files.
- Secure random number generation used for all key creation.
- Access control enforced for key-related operations.
- Keys used only for their intended purpose.

---

# Conclusion

Proper key lifecycle management is essential to maintaining the security guarantees of the Secure Digital Voting System. This plan ensures secure generation, storage, usage, rotation, and destruction of cryptographic keys in alignment with applied cryptography best practices.
