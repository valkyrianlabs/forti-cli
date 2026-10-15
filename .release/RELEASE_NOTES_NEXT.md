<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Documentation in Payload Markdown

The forti documentation is now authored with Payload Markdown directives, so the docs site renders
it as structured pages instead of plain Markdown. The content is the same, checked against the
code; new tables summarize it. The `forti` binary and the packages are unchanged.

- **Installation** puts APT, Homebrew and the source build side by side in tabs.
- **Quick start** is a numbered sequence of steps, from creating the API administrator to
  connecting an AI client.
- **Warnings are callouts**: authentication lockout, operating modes, wholesale replacement of
  table attributes, configuration backups, and the limits of rollback plans and backups when a
  change cuts off management access.
- **The overview** links every section through cards, with release, CI and license badges.
- **New summary tables**: every command at a glance (and whether it contacts the device), exit
  statuses grouped by meaning, the `forti plan list` states, how each operation is rolled back,
  and the `--filter` operators. The exit-code page gains a section on what to do after exit 8, and
  the security notes compare the three operating modes side by side and show the Claude Code
  permission rules as a copyable JSON block.
