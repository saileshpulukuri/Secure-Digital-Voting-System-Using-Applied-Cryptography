# Project Candidates and Selected Direction

## Overview

As part of the Applied Cryptography course, our team evaluated multiple project ideas that demonstrate practical applications of cryptographic primitives such as public-key encryption, digital signatures, secure hashing, and secure authentication. Below are the three candidate projects we considered, followed by our final selected direction.

---

## Candidate 1 – Secure Digital Voting System

This project aims to design and implement a secure digital voting system that ensures voter privacy, ballot integrity, and verifiable election outcomes using applied cryptography.

The system will simulate a university-level election process where:
- Voters authenticate securely.
- Votes are encrypted using public-key cryptography.
- Votes are digitally signed to prevent impersonation.
- Hash functions ensure integrity.
- Results are decrypted only after the election closes.

This project integrates multiple cryptographic primitives within a single secure workflow, making it highly suitable for applied cryptography analysis and attack simulation.

---

## Candidate 2 – Secure Academic File Sharing System

This project proposes a secure file-sharing platform where academic documents can be shared between users using hybrid encryption (AES for file encryption and RSA for key exchange).

The system would ensure:
- Confidential file storage.
- Secure key exchange.
- Integrity verification using hashing.
- User authentication using secure password hashing.

While this project demonstrates encryption and hashing concepts, it primarily focuses on data confidentiality and does not strongly emphasize authentication and non-repudiation in a multi-stage workflow.

---

## Candidate 3 – Digital Certificate Verification System

This project involves creating a system that digitally signs academic certificates and allows third parties to verify their authenticity using public-key cryptography.

The system would:
- Generate digital certificates.
- Apply digital signatures using a private key.
- Allow verification using public-key infrastructure.
- Prevent forgery and tampering.

Although this project clearly demonstrates digital signatures and integrity mechanisms, it involves a narrower cryptographic scope compared to a full voting workflow.

---

# Final Selected Direction: Secure Digital Voting System

After evaluating all three candidates, our team selected the **Secure Digital Voting System** as our final project direction.

## Reasons for Selection

1. **Comprehensive Cryptographic Coverage**  
   The voting system integrates encryption, digital signatures, hashing, and authentication within a single real-world workflow.

2. **Real-World Relevance**  
   Secure electronic voting is a highly researched and practical area of applied cryptography.

3. **Security Depth**  
   The project allows us to explore confidentiality, integrity, authentication, and non-repudiation simultaneously.

4. **Attack Simulation Opportunities**  
   The system enables realistic attack scenarios such as replay attacks, vote tampering, impersonation attempts, and signature forgery — making it ideal for Break-It Week.

5. **Clear Security Goals**  
   The system aligns strongly with cryptographic design principles and secure system architecture.

---

# Conclusion

The Secure Digital Voting System provides a balanced, technically rigorous, and practically relevant applied cryptography project. It allows our team to demonstrate correct primitive usage, misuse prevention, interface design clarity, and key lifecycle management within a structured and secure workflow.
