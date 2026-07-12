# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `@goobits/security`, **please do not open a public GitHub issue**.

Instead, use GitHub's private vulnerability reporting:

1. Open the [Security advisories page](https://github.com/goobits/security/security/advisories) for this repository.
2. Click **Report a vulnerability**.
3. Provide a clear description of the issue, a minimal reproduction, and the package version affected.

You can also email `security@goobits.com` if private GitHub reporting is unavailable to you. Please include "security advisory" in the subject line.

We aim to acknowledge new reports within 5 business days and to ship a fix or mitigation guidance within 30 days, depending on severity.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | :white_check_mark: |
| < 2.0   | :x: (unsupported)     |

## Scope

In scope:

- Authentication / authorization weaknesses (CSRF, admin-auth, rate-limit bypass)
- Cryptographic weaknesses (constant-time violations, weak RNG, algorithm confusion)
- Header-injection or smuggling in cookie / CSP helpers
- Information leakage (token, secret, or PII surfaced by the library itself)

Out of scope:

- Vulnerabilities in dependencies supplied by this package or its consumers
  (report those to the affected upstream project, such as `jose` or `zod`)
- Issues that require an already-compromised host or already-leaked secret
- Misconfiguration in consumer code (we are happy to document hardening guidance, but it is not a CVE)

## Disclosure

After a fix lands, we will publish a GitHub Security Advisory with credit to the reporter (unless anonymity is requested).
