<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- forti-api >= 1.1.1 (build-depends, wrap, meson): builds on macOS 15 / Xcode 16 again (forti-api G16).
- Homebrew bottles for arm64 and Intel, built on macOS 15.
- Recommend (not depend on) valkyrianlabs-archive-keyring: the .deb from a GitHub release installs
  without the repository, and the clean-install smoke test is a standalone install again. Release
  tooling vl-release 0.5.1 (refuses a hard dependency on the keyring).
