# µADR-021: Session Hijacking Fingerprint Protection
-----
tags: security session hijacking
status: accepted

## Context
Stolen session cookies expose active user sessions to unauthorized clients.

## Decision
- Bind user sessions to a SHA-256 User-Agent fingerprint.
- Immediately destroy session state if a fingerprint mismatch occurs.

## Guardrail / Consequences
Session fingerprints must be verified on every authenticated request.
