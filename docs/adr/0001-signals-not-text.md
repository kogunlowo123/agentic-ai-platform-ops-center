# ADR 0001: Store signals, not prompts and responses

- Status: Accepted
- Date: 2026-09-19

## Context

LLM telemetry is unusually sensitive. Prompts and responses contain personal data, credentials and
business secrets. A monitoring database that keeps them becomes a high-value target and a compliance
burden, and many teams cannot adopt a tool that requires it.

## Decision

Accept raw text in the incoming event, derive the signals the analyses need (sizes, PII and credential
counts, injection matches, grounding, salted hashes), and store only those. The stored model has no text
fields, so the property holds structurally. User ids are stored as keyed hashes.

## Consequences

- The database can be shared with more people and retained longer with lower risk. A test inspects the
  database dump for known text, ids and secrets.
- Signals must be defined up front. Analyses that need raw text cannot be added later without changing
  the ingestion contract, and past data cannot be re-analysed with new signals.
- Hashes are only as strong as the salt. The documentation and configuration steer operators to set one.
