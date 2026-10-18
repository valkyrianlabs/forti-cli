<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Engine: applied plans are deleted. An apply past mark_applied removes
  plans/<id>.json and approvals/<id>.{json,used} whatever its outcome; the
  .applied marker becomes a tombstone (summary, digest, outcome, rollback_plan,
  no values). Apply and approve refuse a repeat as already_applied before
  loading the plan; show_plan gives not_found reason already_applied;
  list_plans lists tombstones (stored: false). Refusals before mark_applied
  keep the plan.
- Engine: plan retention. purge_plans deletes unapplied and rollback plans,
  markers and approvals older than config.json plan_retention_days (integer
  1-3650, default 30; validated, config error otherwise) by recorded time
  (plan id timestamp, applied_at/approved_at/used_at) else mtime, approvals of
  missing plans and stale *.tmp.* files, then prunes blobs. Runs after every
  plan and apply and before list_plans; never throws.
  - Applies hold a shared flock on state/plans/.lock; the purge takes it
    LOCK_EX|LOCK_NB and skips while an apply runs.
  - Plans applied by earlier releases are deleted; bare markers are upgraded.
- CLI: forti home retention [DAYS|default]; forti home shows the retention;
  forti plan show latest picks the newest stored plan; forti apply of an
  applied plan reports already applied.
- Docs, man page, unit and integration tests for retention and locking.
