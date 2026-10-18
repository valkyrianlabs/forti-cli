<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Engine: content-addressed action bodies. An action body over 64 KiB of
  canonical JSON (inline_body_limit) is stored once as
  state/blobs/<sha256>.json (0600, dir 0700, atomic, shared by identical
  bodies); the record and wire carry body_ref {sha256, bytes} instead of the
  body, bound by the plan digest.
  - apply loads and verifies each blob (size, SHA-256) before any device
    request; missing or altered refuses as tampered.
  - Every apply prunes blobs that no unapplied plan references (flock with
    plan's blob writes); plan views and the CLI show only the reference.
  - Inline bodies and stored plans are unchanged; load_plan now also checks
    that an inline action's wire body is its body.
- Engine: action replies. The apply record keeps `reply` (results,
  read-redacted, 16 KiB cap, reply_truncated, reply_redacted). A results entry
  with "status": "error" fails the operation (code api; details errors,
  error_indexes, error_count, commands) and stops execution.
- Mock FortiOS: monitor/system/external-resource/dynamic (snapshot, add,
  remove, per-command "Connect pending" errors); unit and integration tests.
