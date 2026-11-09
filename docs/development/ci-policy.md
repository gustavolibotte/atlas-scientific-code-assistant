# Continuous integration and branch protection

## Required quality gates

For pull requests targeting `main`, select the following **exact check names** from GitHub Actions:

- `Backend quality gate`
- `Frontend quality gate`

These are aggregation jobs. The backend gate depends on all nine jobs in the three-operating-system × three-Python-version matrix. The frontend gate depends on both Ubuntu matrix jobs. A failed matrix entry causes its corresponding gate to fail.

**Do not require the old `backend (ubuntu-latest, 3.11)` checks.** They disappear when the runner matrix is updated.

## Repository ruleset

Go to **Settings → Rulesets → New ruleset → New branch ruleset**.

- Name: `Protect main — ASCA quality gates`
- Enforcement: `Active`
- Target: default branch (`main`)
- Require a pull request before merging: enabled
- Required approvals: `0`
- Block force pushes: enabled
- Restrict deletions: enabled
- Require conversation resolution: enabled when offered
- Bypass list: empty

Before the first PR for this version, leave mandatory status checks disabled. After the new workflows have run successfully, edit the ruleset and require the two stable quality gates above. Enable up-to-date branches before merge when the checks are configured.

## Review workflow

1. Create a short-lived branch from clean `main`.
2. Make the change and execute the full local diagnostic suite.
3. Push the branch and open a pull request targeting `main`.
4. Verify all matrix jobs and both aggregate gates.
5. Review warnings, coverage and test output. Do not merge a failed or skipped gate.
6. Merge the PR only after the results are approved.
7. Confirm the post-merge `main` workflows also pass.

## Compatibility warnings

- **Action runtime Node.js 20:** The updated major actions use the modern GitHub Actions runtime. Check the first PR logs for any remaining notices.
- **Ubuntu migration:** Explicit labels ensure both Ubuntu 24.04 and 26.04 are exercised irrespective of `ubuntu-latest` changes.
- **Starlette/httpx:** The existing deprecation warning is not suppressed; address it in a dependency-focused change with full tests.
- **npm transitive dependencies:** Review deprecations independently of workflow infrastructure updates.
