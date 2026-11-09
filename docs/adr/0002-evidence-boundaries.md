# ADR-0002: Treat evidence, decisions, code, and verification as separate records

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

A plausible citation is not proof of scientific correctness. A test passing does not establish
collaboration approval. External documents and model output cannot be trusted as instructions.

## Decision

Persist references and their relationships as distinct domain objects. Require resolvable
identifiers, immutable records, provenance metadata, and explicit verification states.
Synthetic demonstrations must be clearly labeled and must never be classified as published.

## Consequences

The UI can later link a code function to evidence and scientific decisions without hiding
unverified assumptions. Additional checks will be required when revisions invalidate links.
