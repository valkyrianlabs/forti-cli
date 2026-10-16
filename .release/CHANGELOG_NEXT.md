<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- New `forti history`: the audit log for people (newest last; `-p` filters by profile, `-n` limits,
  `--all` shows refused attempts, `--verbose` adds operations, approvals and the undo command;
  `--json` prints the events as recorded). Reads only the state directory.
- New `forti completion bash|zsh|fish`; the scripts are installed to
  `/usr/share/bash-completion/completions/forti`, `/usr/share/zsh/site-functions/_forti` and
  `/usr/share/fish/vendor_completions.d/forti.fish` (Meson option `completions`). Candidates come
  from the hidden `forti __complete` (profile names, resource paths, pending plan ids; no device
  access, no secrets).
