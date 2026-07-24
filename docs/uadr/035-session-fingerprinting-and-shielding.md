# µADR-035: Session Fingerprinting and Brute-Force Protection
-----
tags: #auth #security #session #bruteforce #architecture
status: accepted
context: Authentication state must prevent session hijacking and brute-force credential stuffing attempts.
decisions:
  - Generate a SHA-256 fingerprint from the client User-Agent during login and validate it on every `check()`.
  - Provide `BruteForceShield` with windowed attempt counters and decay periods.
consequences:
  - Invalidates hijacked session cookies if accessed from a different user agent string.
