# µADR-008: Redirect Loop Protection
-----
tags: security middleware redirects
status: accepted

## Context
Misconfigured authentication rules can trigger infinite internal HTTP redirect loops.

## Decision
- AuthenticationMiddleware tracks redirect counts per session within short time windows.
- Exceeding 5 redirects within 3 seconds halts execution and throws a descriptive exception.

## Guardrail / Consequences
Redirect loops must be intercepted server-side before reaching browser limits.
