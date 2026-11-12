# CERN web OIDC — operator evidence intake guide (C3)

This is an **offline intake guide**, not an attestation of the actual CERN
Applications Portal configuration or an approval to implement web login.

## Collect evidence without collecting credentials

The three open decision areas are G1, G6 and G7, as defined in ADR 0031 and
reviewed in ADR 0032. An evidence reference is useful only to arrange an
independent review; it must not become a source of authority by itself.

| Gate | Operator needs to confirm | Reviewer's acceptance question |
| --- | --- | --- |
| G1 | Whether a **separate web/BFF** client exists, its authorized owner, client class and grant/credential method, exact HTTPS callback, scopes and deployment boundary | Is the registration genuine, owned and appropriate for the proposed server-only flow? |
| G6 | Which **official CERN policy** establishes required MFA/LoA and freshness, including whether application role enforcement attests required assurance | Is there positive provider-approved evidence rather than inference from absent missing-role hints? |
| G7 | Server-managed session and transaction architecture, shared atomic state, cookie/CSRF policy, TTL, logout, key ownership and global revocation | Does the design address multi-worker replay, fixation, role staleness and incident response? |

**Unresolved**: no production web client, positive assurance evidence or session
policy is approved by this increment. In particular, `ROLE_STATUS=CLAIMED`
from a native test does not satisfy any of these gates.

## Non-secret reference procedure

1. Create a restricted evidence/review item in an approved organizational
   tracking system. Keep confidential configuration, real user data and portal
   screenshots out of the ASCA repository and ordinary chat diagnostics.
2. Assign an opaque reference such as `EVIDENCE-1234` to each submitted item.
   The example is a **format illustration**, not an existing approval.
3. If desired, prepare a **local copy** of
   `docs/security/cern-web-operator-intake-template.json` outside the repository.
   Mark a gate `submitted_for_review` and supply only its opaque reference.
4. Run `uv run --locked python scripts/check_cern_web_operator_intake.py
   --record /path/to/local/nonsecret-intake.json` to validate the record's
   structure. The command does not access CERN, follow references or inspect
   evidence itself. Do not paste actual credentials into this command.
5. Seek independent reviewer sign-off *outside* the validator. Preserve the
   C2 evidence register's unverified states until a separate, reviewed ADR and
   implementation confirm each required deployment control.

The source-controlled template may remain unchanged at `not_supplied` even if
some evidence is being reviewed elsewhere. **Never commit a completed record
or any secret-bearing provider material.**

## Validator output semantics

| Output | Meaning |
| --- | --- |
| `RECORD=STRUCTURALLY_VALID_NON_AUTHORITATIVE` | Strict JSON schema check passed only |
| `G1/G6/G7=NOT_SUPPLIED` | No evidence reference was supplied |
| `G1/G6/G7=SUBMITTED_UNVERIFIED` | A syntactically valid reference was supplied; contents not checked |
| `RESULT=OPERATOR_REVIEW_REQUIRED` | All release gates remain unresolved |
| `RESULT=INVALID_EVIDENCE_RECORD` | The supplied file could not be safely parsed or validated |

The checker **never** emits `READY`, `APPROVED`, `AUTHORIZED`, `LOGGED_IN`, or
session credentials. A zero exit code indicates valid structure, not readiness.

## Constraints

- Do not record or print CERN application passwords, tokens, client secrets,
  signing keys, full callback URLs with parameters, usernames, group lists or
  unredacted identity assertions.
- Do not reinterpret a client-credentials option as an interactive user login.
- Do not assume MFA/LoA from missing-role arrays, `amr` or `acr` without a
  CERN-authoritative, reviewed semantics and freshness contract.
- Do not reuse the native public-client diagnostic as a web BFF trust root.
- Do not claim chATLAS/GitLab access from the ASCA application role.

See `docs/adr/0033-cern-web-operator-evidence-intake.md` for the decision and
`docs/development/phase1a2-5c3-acceptance.md` for the review gates.
