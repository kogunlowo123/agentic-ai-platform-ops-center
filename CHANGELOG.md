# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-19

### Added

- Supervisor agent and six specialist agents (observability, cost, security, quality, drift,
  governance) with failure isolation.
- Telemetry ingestion for JSON Lines with strict validation, limits, duplicate handling, pricing and
  signals derived at ingestion (PII, credentials, injection, grounding, salted hashes). Raw text and user
  ids are never stored.
- SQLite storage for events, alerts, evaluation runs, registry and audit log.
- Alert lifecycle with fingerprints, acknowledgement, auto-resolution, reopening and file and webhook
  sinks.
- Model and prompt registry with lifecycle rules, separation of duties, hash-pinned prompts and an audit
  log.
- Evaluation suites with deterministic assertions, stored runs and regression detection.
- Multi-model router with cost, latency, quality and ordered strategies, tiers, fallback and circuit
  breakers.
- Statistics toolkit (percentiles, PSI, Kolmogorov-Smirnov) and a deterministic telemetry simulator with
  a realistic incident.
- Markdown and JSON reports with health scores; `opsctl` CLI with CI-friendly exit codes.
- Example configuration, Dockerfile, Makefile and GitHub Actions workflows for lint, format, types,
  tests, dependency audit, CodeQL and build validation.
