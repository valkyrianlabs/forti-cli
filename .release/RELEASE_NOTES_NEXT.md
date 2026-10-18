<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Plans no longer pile up: applied plans are deleted, the rest ages out

Every plan used to stay in `~/.forti/state/plans/` forever, applied or not, with its approval records.
forti now cleans up after itself.

#### Applied plans are deleted

- Once an apply has started executing a plan, whatever the outcome (applied, `partial_failure`,
  `outcome_unknown`, `management_connectivity_lost`), the plan file and its approval records are
  deleted: the plan can never run again, and `forti history` and the rollback plan say what it did.
- A small marker, `state/plans/<id>.applied`, stays. It keeps the plan's summary and outcome (never
  values), so `forti plan list` still shows the plan as `applied`, `forti rollback <id>` still finds its
  rollback plan, and applying or approving it again is refused as **already applied**
  (`policy_denied`, reason `already_applied`, with `applied_at`), not "not found". `forti plan show` of
  an applied plan says when it was applied and that it is no longer stored.
- An apply refused before anything was sent (stale plan, approval required, read-only profile,
  tampered plan, unwritable audit log, failed pre-change backup) keeps the plan, so you can approve it
  or retry.
- Rollback plans are plans like any other: kept until they are applied or age out.
- Plans applied by earlier releases are deleted by the first purge; their markers stay.

#### Retention: 30 days by default

- Plans never applied, rollback plans, applied markers and approval records older than the retention
  period are deleted automatically, by the time each records (a plan id begins with its creation
  time), else the file's modification time. Stored action bodies no remaining plan refers to go with
  them.
- The purge runs on every plan and apply and on `forti plan list`. It never runs while an apply is
  executing (applies hold a shared lock on `state/plans/.lock`), so a plan in use is never deleted.
- `forti home retention` shows the period, `forti home retention DAYS` sets it (a whole number of days
  from 1 to 3650, stored as `plan_retention_days` in `config.json`), `forti home retention default`
  restores 30. `forti home` shows it too. A hand-edited value that is not a whole number from 1 to 3650
  is a `config` error naming the setting. Agents cannot change it: no MCP tool writes `config.json`.
- The audit log and configuration backups are not affected (backups keep the 20 most recent).

#### For tools built on the engine

- `list_plans` items gain `stored` (`false` for an applied plan listed from its marker, which also
  carries `applied_at`, `outcome` and `rollback_plan`); `show_plan` of an applied plan is `not_found`
  with reason `already_applied`; `purge_plans(Engine&)` runs the purge. Request and result shapes of
  discover, read, plan and apply are unchanged.
