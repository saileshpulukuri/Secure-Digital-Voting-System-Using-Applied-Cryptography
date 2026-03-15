# Proposal v1 – Secure Digital Voting System

**Team Name:** Brute Force  
**Course:** Applied Cryptography  
**Week:** 2 – Proposal v1 & Scope Lock  

## Overview

This document defines the locked MVP scope, measurable success criteria, risk register, and feasibility plan for the Secure Digital Voting System. The objective is to ensure disciplined scope control and structured development aligned with applied cryptography principles.

## 1. Problem Statement

Digital voting systems must guarantee:

- Confidentiality of votes  
- Integrity of ballots  
- Authentication of voters  
- Resistance to tampering  

Traditional web-based systems without cryptographic enforcement are vulnerable to:

- Vote modification  
- Voter impersonation  
- Replay attacks  
- Data leakage  
- Unauthorized tally manipulation  

For a university-level election simulation, applied cryptography is required to provide enforceable security guarantees.

## 2. Stakeholders

The primary stakeholders of this system are:

- **Voters** – Students casting ballots securely  
- **Election Administrators** – Authorized users responsible for closing elections and tallying votes  
- **University Authority** – Ensures fairness and election integrity  
- **System Developers** – Responsible for secure implementation  

Each stakeholder depends on cryptographic protections to maintain trust.

## 3. Cryptographic Requirements

The system maps security properties to cryptographic mechanisms:

| Security Property | Mechanism |
|-------------------|------------|
| Confidentiality   | RSA (2048-bit with OAEP) |
| Integrity         | SHA-256 |
| Authentication    | RSA Digital Signatures |
| Password Security | bcrypt |

All primitives are selected based on standardized best practices and implemented using secure libraries.

## 4. MVP Definition (Locked Scope)

The Minimum Viable Product will include:

- Voter registration with secure password hashing  
- Election RSA key pair generation  
- Voter RSA key pair generation  
- Vote encryption using election public key  
- Digital signature verification  
- Encrypted vote storage  
- Double voting prevention  
- Admin-only election closure  
- Vote decryption and tally computation  
- Logging of major system events  
- Unit tests for cryptographic modules  

This MVP focuses strictly on core applied cryptographic workflow validation.

## 5. Explicit Non-Goals

The following are not part of the MVP:

- Blockchain integration  
- Homomorphic encryption  
- Distributed consensus mechanisms  
- Real-world production deployment  
- Mobile application  
- Advanced UI/UX frontend  
- Production-level scalability  
- Hardware security module integration  

These non-goals prevent scope expansion beyond course feasibility.

## 6. Measurable Success Criteria

The project will be considered successful if:

- 100% of stored votes are encrypted  
- Invalid digital signatures are rejected  
- Double voting attempts are blocked  
- Tally equals number of valid decrypted votes  
- At least 10 unit tests pass successfully  
- At least one simulated attack is documented and mitigated  

All criteria are objectively verifiable.

## 7. Demo Story

The demo will demonstrate:

1. Voter registration  
2. Key generation  
3. Vote casting  
4. Encrypted vote storage  
5. Invalid signature rejection  
6. Double voting prevention  
7. Election closure  
8. Vote decryption  
9. Final tally verification  

This sequence validates both correctness and security enforcement.

## 8. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Incorrect RSA implementation | Security vulnerability | Use standard libraries and peer review |
| Private key exposure | Election compromise | Restrict access and never commit keys |
| Signature verification errors | Acceptance of forged votes | Strict validation tests |
| Scope creep | Incomplete MVP | Locked scope and explicit non-goals |
| Team coordination delay | Missed milestones | Weekly issue tracking and milestone review |

## 9. Repository Updates

GitHub Repository:  
https://github.com/saileshpulukuri/Secure-Digital-Voting-System-Using-Applied-Cryptography  

Files added/updated:

- `/docs/project_candidates.md`
- `/docs/crypto_design_decisions.md`
- `/docs/interface_spec.md`
- `/docs/key_lifecycle.md`
- `/docs/proposal_v1.md`
- `.gitignore`
- `LICENSE`
- Structured folders `/docs`, `/src`, `/tests`
- ≥12 prioritized GitHub issues

All progress is tracked via structured commits.

## Conclusion

This proposal defines a realistic and measurable applied cryptography project. The MVP scope is locked, risks are identified with mitigations, and success criteria are objectively measurable. The Secure Digital Voting System is feasible, secure by design, and aligned with course expectations.
