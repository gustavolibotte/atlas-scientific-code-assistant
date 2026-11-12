# CERN web OIDC: evidence and outstanding operator decisions (C2)

This is a **design review**, not proof of a working or authorized ASCA login.
CERN documentation cited below was available as saved public-page PDFs
captured on 2026-11-11; current provider settings may differ.

## What the available evidence supports

| Topic | Documentation or observation | What it does NOT establish |
| --- | --- | --- |
| CERN SSO registration | The CERN SSO registration form distinguishes public clients (unable to store a secret) from secret-capable clients and requests redirect URIs | Which settings a separate ASCA web client actually has |
| Client-credentials checkbox | An advanced option describes obtaining tokens for the application itself | This is NOT an interactive-user login requirement or a delegated chATLAS authorization |
| Redirect matching | CERN OIDC guidance recommends explicit registered redirect URLs; matching is case-sensitive | Approval of any ASCA web hostname or callback |
| Application roles | CERN guidance locates scoped roles at `resource_access[application].roles` | That the native `asca-developer` role is valid for a future web client |
| MFA and LoA | Missing-role arrays signal withheld roles; the Application Portal can define role requirements | A positive ASCA-reviewed assurance attestation or a verified `amr`/`acr` mapping |
| Token lifetime and logout | CERN guidance documents OIDC end-session behavior and application-specific expiry responsibility | A production ASCA session/revocation policy or SSO logout requirement |
| Native diagnostic | `ROLE_STATUS=CLAIMED` observed for `asca-glibotte-dev` in one permitted test | An authenticated ASCA session, web-client registration or current role freshness |
| CERN reference deployment | CAiMIRA documentation shows an HTTPS OIDC callback with client credentials kept in OpenShift secret storage | That ASCA runs on CERN OpenShift or can adopt CAiMIRA configuration unreviewed |

## Operator evidence needed before production code

**Web registration (G1/G2).** Confirm the separate CERN Application Portal
client identifier, owner, web app type and credential method; exact HTTPS
redirect URI; approved scopes; permitted grant types; web deployment and
reverse-proxy TLS boundary. Record *non-secret* evidence only. Do not include
client secrets, tokens, personal membership records or unredacted screenshots.

**Assurance (G6).** Obtain CERN provider guidance stating whether the
application-scoped role itself attests satisfied minimum LoA/MFA in a signed
ID Token, or which explicit positive, signed claims and freshness rules should
be used. Do not treat empty `cern_roles_missing_mfa` or
`cern_roles_missing_loa` as proof. Do not assume `amr`/`acr` semantics.

**Session architecture (G7).** Select a server-controlled, distributed
transaction and session store; define TTLs, cookie attributes, CSRF, rotation,
logout, role revalidation, global revocation, emergency invalidation,
clock/failure behavior and retention. Approve an audit-data minimization policy
before implementing persistence or handling real user identifiers.

**External resources (G8).** Document the target resource's acceptable token
audience and scopes, delegated consent, permission-check model, refresh and
revocation behavior. An ID Token intended for ASCA is not an API access token
for chATLAS or CERN GitLab.

## Review decision table

| Decision | Current answer | Required action |
| --- | --- | --- |
| Reuse `asca-glibotte-dev` as web BFF client? | **NO: not authorized by this review** | Review/register a separate web client |
| Is a public native callback suitable for the web API? | **NO** | Design an exact HTTPS BFF callback |
| May `ROLE_STATUS=CLAIMED` grant access? | **NO** | Establish trusted subject plus separate authorization |
| Do empty missing-MFA/LoA arrays prove satisfaction? | **NO** | Verify provider-positive assurance semantics |
| Which cookie/TTL/revocation values are approved? | **UNDECIDED** | Separate security owner review |
| Is chATLAS access enabled? | **NO** | Separate delegated resource policy |

## Source inventory and provenance

1. CERN *Registering your application to SSO*:
   https://auth.docs.cern.ch/applications/sso-registration/
   (saved public PDF, 2026-11-11, page 3: OIDC client registration form).
2. CERN *OIDC configuration and usage*:
   https://auth.docs.cern.ch/user-documentation/oidc/config/
   (saved public PDF, 2026-11-11, pages 2–5: roles, missing-MFA/LoA, logout and redirects).
3. CERN *Configuring your application*:
   https://auth.docs.cern.ch/applications/application-configuration/
   (saved public PDF, 2026-11-11, page 1: registration workflow).
4. CERN CAiMIRA deployment example:
   https://caimira.docs.cern.ch/root/deployment/
   (public example, not an ASCA registration record).
5. RFC 9700 (OAuth 2.0 security BCP): https://www.rfc-editor.org/rfc/rfc9700
6. OIDC Core: https://openid.net/specs/openid-connect-core-1_0.html

The source list is reproducible; none of these documents is a live
attestation of the current ASCA Applications Portal configuration.
