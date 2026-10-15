# Security policy

Please do not deploy this starter with real users or sensitive conversations without a security review. It currently stores message content in plaintext and does not implement end-to-end encryption. Report issues privately to the project maintainer rather than posting exploit details publicly.

Before production: enforce HTTPS, use a unique secret, configure email/SMS providers, use a shared rate limiter, review WebAuthn RP/origin validation, scan uploads, back up the database and uploads, and test session/device revocation and restore procedures.
