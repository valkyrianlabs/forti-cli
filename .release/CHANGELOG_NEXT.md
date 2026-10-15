<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

## Packaging
- Initial release of forti-cli: /usr/bin/forti and its man page, built against
  the system libforti-api-dev (>= 1.0.1); the forti-api wrap is never used in
  package builds (--wrap-mode=nodownload).
- Release build profile: -O3 in place of dpkg's -O2, NDEBUG, and section
  garbage collection (-ffunction-sections -fdata-sections, --gc-sections); the
  network-free unit suite runs against that build unless nocheck.
- amd64 only (vl-release supports one architecture per package contract).
