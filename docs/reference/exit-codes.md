---
title: Exit codes
description: The stable error codes and the exit status each one maps to.
order: 95
status: published
tags:
  - reference
---

# Exit codes

Every failure has a stable error code (`error.code` in the `--json` envelope), and the exit status
follows from it. forti and forti-mcp share the same codes.

| Exit | Code | Meaning | Typical fix |
|---|---|---|---|
| 0 | | success | |
| 1 | `internal` | a bug or an unexpected state | report it, with `--json` output |
| 2 | `usage` | bad arguments or request shape | `forti <command> --help` |
| 3 | `config` | missing or invalid profile, credentials or config file; an unwritable audit log | `forti configure`, `forti doctor` |
| 4 | `connection` | DNS, connect, TLS or timeout | `forti doctor`; `--ca-bundle`, `--resolve-ip`, `--port` |
| 4 | `auth` | HTTP 401/403: the key was rejected (never retried) | check the key, trusted hosts, admin profile |
| 5 | `not_found` | the object (or a stored plan, or forti-mcp) does not exist | check the key; `forti get <resource>` lists objects |
| 5 | `unknown_resource` | the path is not in the catalog | `forti discover <search>` |
| 6 | `validation` | unknown or read-only attribute, bad value | `forti discover <resource>` |
| 6 | `api` | another FortiOS error (details carry the HTTP status, FortiOS code and CLI messages) | read `details.cli_error` |
| 7 | `stale_plan` | the device changed since the plan was made | plan again |
| 7 | `approval_required` | apply on a guarded profile without a valid approval | `forti plan approve <id>` |
| 7 | `policy_denied` | the mode forbids it (read-only), the plan was already applied or failed its integrity check, or a critical plan's backup failed | `forti profile mode NAME guarded`; plan again |
| 8 | `partial_failure` | apply stopped part-way; the record says what happened | inspect the record and the rollback plan |
| 8 | `management_connectivity_lost` | apply stopped: the connectivity probe after a critical change failed | restore access through an independent path; see below |
| 8 | `outcome_unknown` | a change may or may not have reached the device | re-read the object before doing anything else |

`error.details` adds structure where it helps: `reason` (for example `read_only`, `already_applied`,
`before_changed`, `backup_failed`), `hint`, `http_status`, `fortios_error` and `cli_error` from
FortiOS, and for a stopped apply the full execution record with the rollback plan.

For exit 8, read [Applying a plan](/guides/planning-and-applying-changes#applying-a-plan) and
[Recovery aids are not guaranteed recovery](/guides/planning-and-applying-changes#recovery-aids-are-not-guaranteed-recovery).

`forti doctor` exits with the status of its first failed check. Warnings do not fail it.
