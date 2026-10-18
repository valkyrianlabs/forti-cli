<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Large monitor action bodies and action replies

Monitor actions can now carry bodies of many megabytes, such as a DNS threat-feed push of hundreds of
thousands of entries to `monitor/system/external-resource/dynamic`, and forti now reads what the
device answers to an action instead of assuming it worked.

### Large action bodies are stored once

- An action body over 64 KiB is no longer written into the plan (twice, before). It is stored once
  as `~/.forti/state/blobs/<sha256>.json` (owner-only, written atomically), and the plan names it:
  `"body_ref": {"sha256": "…", "bytes": N}`, in the operation and in its request record. Plans with the
  same body share one file.
- The reference is part of the plan's digest, so the digest, and an approval of it, cover the body's
  content. Apply checks the file's size and SHA-256 before it contacts the device: a missing or
  changed file refuses the plan as tampered, and nothing is sent.
- `forti plan show`, `forti plan list`, the plan an agent gets back and the apply record show the
  reference and the size, never the body.
- After every apply, whatever its outcome, forti deletes stored bodies that no plan still waiting to
  be applied refers to.
- Smaller bodies stay inline, and every existing plan works as before.

### Action replies and failed commands

- An action's apply record now keeps the device's reply: `reply` (its `results`, with the same secret
  redaction as a read, cut past 16 KiB with `reply_truncated: true`). `forti apply` prints it.
- Batch actions answer HTTP 200 with one result per command, and FortiOS reports a refused command
  there as `"status": "error"`: for example a threat-feed push sent while FortiOS has not loaded the
  feed yet ("Connect pending"). Such an operation is now `failed` with error code `api` and the error
  entries in its details (`errors`, `error_indexes`, `error_count`), and the apply stops there
  (`partial_failure`, exit 8). Before, it was reported as `applied_unverified`.
