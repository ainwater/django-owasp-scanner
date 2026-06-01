# A01 IDOR Review

Example only. Do not pass this file directly to `--idor-review`. Copy it outside git and replace every row with project-specific evidence before using it as audit evidence.

## Scope

- Product: Application
- Environment: staging
- Reviewer: security-reviewer
- Date: 2026-06-01
- Authorization window: documented separately

## Identifiers Reviewed

| Resource | Identifier | Predictable | Tenant-scoped | Notes |
|---|---|---|---|---|
| Invoice detail | `id` | yes | yes | Validate owner and cross-tenant denial |
| Admin report | `id` | yes | no | Admin-only resource |

## Test Cases

| Case | Actor | Target Object | Expected | Observed | Result |
|---|---|---|---|---|---|
| Owner reads own invoice | owner | invoice:own | allow | allow | pass |
| User reads another user's invoice | other_user | invoice:own | deny | deny | pass |
| Tenant B user reads tenant A invoice | owner@tenant-b | invoice:own@tenant-a | deny | deny | pass |
| Anonymous reads admin report | anonymous | admin-report:global | deny | deny | pass |

## Evidence

- Replace with links or references to real authenticated request evidence.
- Replace with response-body review notes for partial data disclosure.
- Replace with server-side authorization logs where available.

## Findings

- Example only; not a validated finding decision.

## Sign-off

- Status: pending
- Owner: security-reviewer
- Notes: Replace example rows with project-specific evidence before using this file as audit evidence.
