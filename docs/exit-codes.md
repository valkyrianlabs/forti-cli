# Exit codes

Every failure has a stable error code (`error.code` in the `--json` envelope), and the exit status
follows from it. forti and forti-mcp share the same codes.

| Exit | Code | Meaning | Typical fix |
|---|---|---|---|
| 0 | | success | |
| 1 | `internal` | a bug or an unexpected state | report it, with `--json` output |
| 2 | `usage` | bad arguments or request shape | `forti <command> --help` |
| 3 | `config` | missing or invalid profile, credentials or config file | `forti configure`, `forti doctor` |
| 4 | `connection` | DNS, connect, TLS or timeout | `forti doctor`; `--ca-bundle`, `--resolve-ip`, `--port` |
| 4 | `auth` | HTTP 401/403: the key was rejected (never retried) | check the key, trusted hosts, admin profile |
| 5 | `not_found` | the object does not exist (404) | check the key; `forti get <resource>` lists objects |
| 5 | `unknown_resource` | the path is not in the catalog | `forti discover <search>` |
| 6 | `validation` | unknown or read-only attribute, bad value | `forti discover <resource>` |
| 6 | `api` | another FortiOS error (details carry the HTTP status, FortiOS code and CLI messages) | read `details.cli_error` |
| 7 | `stale_plan` | the device changed since the plan was made | plan again |
| 7 | `approval_required` | apply on a guarded profile without a valid approval | `forti plan approve <id>` |
| 7 | `policy_denied` | the profile's mode forbids the operation (read-only) | `forti profile mode NAME guarded` |
| 8 | `partial_failure` | apply stopped part-way; the record says what happened | inspect the record and the rollback plan |
| 8 | `outcome_unknown` | a change may or may not have reached the device | re-read the object before doing anything else |

`forti doctor` exits with the status of its first failed check. Warnings do not fail it.
