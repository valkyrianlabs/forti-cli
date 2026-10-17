<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Child tables: one entry of a table attribute (`system.dhcp/server` `reserved-address`) on FortiOS's
  child paths, through forti-api 1.2.0's runtime schema.
  - Engine read: `child`, `child_key` (key = parent; fields/filter checked against the entry type;
    engine-side windowing; redaction as usual).
  - Engine plan/apply: `parent` + `child` on create/update/delete. The before-state, digest, diff, wire
    path, drift check, verification and rollback are the entry's; the risk tier is the resource's. The
    device-assigned id comes from `child_mkey`, else from `mkey` of a POST reply naming the child path.
    Stored plans are integrity-checked for the child path. Records without `parent`/`child` are unchanged.
  - Plans that set a whole keyed table attribute get a note pointing at child operations.
  - CLI: `forti get --child/--child-key`; `--parent/--child` on set, create, delete and plan; history,
    plan and apply output name the parent and child; help, man page and completions updated.
  - Mock FortiOS: `system.dhcp/server` with stateful child paths using the FortiOS 7.4.8 reply shapes,
    `monitor/system/dhcp` and `monitor/system/dhcp/revoke`; unit and integration tests.

