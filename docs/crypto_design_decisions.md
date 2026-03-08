# Cryptographic Design Decisions (CDDR)

## Overview

This document records the cryptographic design decisions for the Secure Digital Voting System. The goal is to ensure correct primitive usage, provide rationale for each choice, and document misuse prevention strategies.

The system is designed to satisfy the following core security properties:

- Confidentiality
- Integrity
- Authentication
- Non-repudiation
- Misuse resistance

---

# 1. Public-Key Encryption

## Algorithm Selected
RSA (2048-bit) with OAEP padding

## Purpose
RSA is used to encrypt votes before they are stored in the system. Only the election authority can decrypt votes after the election closes.

## Rationale

- RSA is a widely standardized algorithm (RFC 8017).
- 2048-bit key size provides strong security for academic and practical use.
- Public-key encryption simplifies key distribution in a voting environment.
- Allows separation between encryption (public key) and decryption (private key).

## Alternatives Considered

- AES-only encryption: Rejected because symmetric key distribution would introduce additional complexity and key-sharing risks.
- ECC: Considered but RSA was selected due to broader familiarity and simpler implementation for this academic project.

## Misuse Prevention

- Use RSA-OAEP padding to prevent deterministic encryption vulnerabilities.
- Never encrypt raw plaintext without padding.
- The private key will not be exposed in source code.
- Decryption is allowed only during election tally phase.

---

# 2. Digital Signatures

## Algorithm Selected
RSA Digital Signatures

## Purpose
Digital signatures ensure that only authenticated voters can submit votes and prevent impersonation.

## Rationale

- Provides authentication and non-repudiation.
- Ensures vote origin can be verified without revealing vote contents.
- Standardized under Digital Signature Standard (NIST FIPS 186-4).

## Alternatives Considered

- ECDSA: Considered for efficiency, but RSA signatures were selected to maintain consistency with RSA encryption.
- HMAC: Rejected because it requires shared secret keys and does not provide non-repudiation.

## Misuse Prevention

- All signatures must be verified before accepting votes.
- Invalid signatures result in rejection.
- The system prevents reuse of signatures for replay attacks.

---

# 3. Secure Hashing

## Algorithm Selected
SHA-256

## Purpose
SHA-256 is used to ensure vote integrity and detect any modification of stored encrypted votes.

## Rationale

- SHA-256 is part of the Secure Hash Standard (NIST FIPS 180-4).
- Resistant to collision attacks in practical contexts.
- Provides fixed-length output suitable for verification.

## Alternatives Considered

- SHA-1: Rejected due to known collision vulnerabilities.
- MD5: Rejected due to cryptographic weaknesses.

## Misuse Prevention

- Hash only encrypted vote data.
- Never rely on hashing alone for authentication.
- Verify hashes during tallying before decryption.

---

# 4. Password Hashing for Authentication

## Algorithm Selected
bcrypt

## Purpose
bcrypt is used to securely store user passwords during voter registration.

## Rationale

- Includes salting by default.
- Adaptive cost factor resists brute-force attacks.
- Specifically designed for password hashing.

## Alternatives Considered

- SHA-256 for password storage: Rejected because general hash functions are not suitable for password protection.
- Plaintext storage: Not acceptable under any circumstances.

## Misuse Prevention

- Passwords are never stored in plaintext.
- Use appropriate cost factor.
- Do not reuse password hashes across systems.

---

# 5. Key Management Overview

## Key Types

- Election Public/Private Key Pair
- Voter Public/Private Key Pairs

## Key Usage

- Public key encrypts votes.
- Private key decrypts votes after election closes.
- Voter private key signs vote submission.

## Misuse Prevention

- Private keys are stored securely and access-restricted.
- Keys are not transmitted in plaintext.
- Keys are generated using secure random number generators.

---

# 6. Security Goals Mapping

| Security Property | Mechanism Used |
|------------------|---------------|
| Confidentiality | RSA Encryption |
| Integrity | SHA-256 Hashing |
| Authentication | Digital Signatures |
| Non-repudiation | RSA Signatures |
| Password Security | bcrypt |

---

# 7. Spec Freeze Plan

All cryptographic primitives and interface formats will be finalized and frozen in Week 5. Any changes after freeze will require documented justification and version tagging in the repository.

---

# Conclusion

The selected cryptographic primitives align with standardized, secure, and academically accepted algorithms. The system design emphasizes correct usage, misuse prevention, and layered security to ensure confidentiality, integrity, authentication, and non-repudiation within the digital voting workflow.
