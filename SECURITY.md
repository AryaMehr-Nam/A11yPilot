# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.1.x` (`main`) | Yes |

## Security Architecture & Reporting

A11yPilot interacts directly with desktop accessibility trees and OS input APIs. Its core safety invariants include:

- **Loopback-Only Studio Binding:** The Localhost X-Ray Studio binds strictly to `127.0.0.1`, `localhost`, or `::1` and enforces `Host`, `Origin`, `Sec-Fetch-Site: cross-site`, `HttpOnly; SameSite=Strict` session cookies, and strict Content-Security-Policy (`script-src 'self'`).
- **Source-Level Secret Redaction:** Password and secret-named input fields are redacted to `[REDACTED:PASSWORD]` inside each OS backend and validated at the Pydantic model layer.
- **Safety Gates & Kill-Switch:** Destructive patterns, terminal processes, dangerous hotkeys, and system dialogs trigger `HIGH`/`CRITICAL` Human-in-the-Loop (HITL) gates (failing closed when headless) and can be halted immediately via `POST /api/emergency-stop`.
- **Zero-XSS Frontend:** All Studio DOM rendering uses `createElement`, `createElementNS`, and `textContent` with zero `innerHTML`/`eval` sinks or external CDN dependencies.

If you discover a security vulnerability, please open a private security advisory on GitHub rather than filing a public issue with an active exploit.
