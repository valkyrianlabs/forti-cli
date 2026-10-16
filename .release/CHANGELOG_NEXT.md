<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- forti configure: prompts for a client certificate after the API key: reuse one
  (numbered list of `<home>/certs`), make one (issued by the forti CA or with its
  own CA), or name a PKCS#12 file. Prints the FortiOS commands for a newly chosen
  certificate and waits before the connection check. New `--cert NAME`.
- forti cert: certificates are named sets in `<home>/certs/<name>/`, independent
  of profiles, issued by the forti CA in `<home>/ca/` (made on first use, 20 years)
  unless `--own-ca`. `create [NAME]` works without a profile; new `list` and
  `use NAME [--profile P]`; `show`/`remove` take NAME, and `remove` detaches every
  profile using it. The printed FortiOS steps carry the CA certificate inline.
- forti install mcp: deny agents `<home>/ca/` (Claude Code `Read(/ca/**)`, Codex
  `"ca" = "deny"`).
- Tests: mock FortiOS can require TLS client certificates; interactive configure
  is tested end to end on a pseudo-terminal.

