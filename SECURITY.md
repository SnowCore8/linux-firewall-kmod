# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

1. **DO NOT** open a public issue
2. Email us directly or use GitHub's private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work to address the issue promptly.

## Security Best Practices

- Always run the daemon with systemd security hardening
- Use strict configuration validation mode (default)
- Keep your kernel and dependencies up to date
- Monitor Prometheus metrics for unusual activity
- Review logs regularly for attack patterns

## Security Features

- Security compilation flags (PIE, RELRO, Stack Protector)
- RCU concurrency safety
- Input validation on all interfaces
- Path traversal protection
- ReDoS prevention for custom regex
- TOCTOU race condition fixes

Thank you for helping keep Firewall secure!
