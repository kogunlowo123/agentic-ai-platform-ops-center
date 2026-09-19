# Security Policy

## Supported versions

Security fixes are released for the latest minor version on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Do not open a public issue for security reports. Use GitHub's private vulnerability reporting (the
**Report a vulnerability** button on this repository's **Security** tab) and include a description and
impact, the affected version or commit, and a minimal reproduction (telemetry, commands, configuration).
You can expect an acknowledgement within 3 business days and a triage decision within 10 business days.

## Trust boundary

| Input | Trust |
| ----- | ----- |
| Telemetry files and events | Untrusted. They come from applications and may be malformed or hostile |
| Model outputs inside telemetry | Untrusted text, analysed but never executed or forwarded to a model |
| Configuration, pricing, apps and suite files | Trusted operator input |
| Evaluation model responses | Untrusted text; only checked by deterministic assertions |

## Security controls

| Threat | Control | Location |
| ------ | ------- | -------- |
| Sensitive data retained | Text reduced to signals at ingestion; stored model has no text fields | `telemetry.py`, `models.py` |
| User identification | Keyed hash of `user_id`; raw ids never stored | `security.salted_hash` |
| Malformed or oversized input | Schema validation, per-line byte limit, total line limit, bounded field sizes | `models.py`, `telemetry.py` |
| Leaky error messages | Ingestion errors carry the line number and problem, never content; all errors redacted | `telemetry.py`, `redaction_util.py` |
| SQL injection | Bound parameters for every statement; tested with hostile filter values | `store.py`, `registry.py`, `alerts.py` |
| Credentials in output artifacts | Redaction of alert files, webhook payloads, evaluation previews and reports | `security.py`, `alerts.py`, `evals.py` |
| Webhook URL exposure | Held as `SecretStr`; not printed or logged | `config.py` |
| Report markup injection | Markdown cells escaped | `reporting.py` |
| Unauthorised model or prompt approval | Transition tables, separation of duties, audit log in the same transaction | `registry.py` |
| Tampered prompts in production | Content hash pinning and `verify_prompt` | `registry.py` |
| Monitoring blind spots | Agent failures raise alerts and never resolve existing ones | `agents/supervisor.py`, `alerts.py` |
| Upstream instability | Bounded retries on transient errors only; circuit breakers in the router | `retry.py`, `router.py` |
| Vulnerable dependencies | `pip-audit`, Dependabot, CodeQL | `.github/` |
| Container | Multi-stage build, non-root user | `Dockerfile` |

## Known limitations

- PII, credential and injection detection are pattern based. They miss unusual formats and produce
  false positives. They are signals for triage, not guarantees.
- Hashes are not anonymisation. Without a secret salt (`OPSCENTER_HASH_SALT`), low-entropy values such as
  short user ids or common questions can be recovered by guessing.
- The SQLite database is not encrypted. Protect it with disk encryption and file permissions. Alert
  titles, evidence and reports reveal application names, models and behaviour.
- There is no authentication layer. `opsctl` acts with the caller's filesystem permissions, and the
  registry's `--actor` value is asserted by the caller, not verified.
- Evaluation and routing send prompts to the configured provider. Keep sensitive data out of suites.
