<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- `forti install mcp --scope workspace`: register forti-mcp as project scope in the forti home
  (~/.forti or $FORTI_HOME), the recommended default and first interactive choice
  - scaffold, created and updated idempotently, never overwriting an edited file: `.mcp.json`,
    `.codex/config.toml`, the skill in `.claude/skills` and `.agents/skills`, `AGENTS.md`,
    `CLAUDE.md` (`@AGENTS.md`), and `.forti-workspace.json` recording what forti wrote
  - secret hygiene: `.claude/settings.json` gains `permissions.deny` rules (`Read(/credentials/**)`,
    `Read(/certs/**/*.pass)`, `Read(/certs/**/*.p12)`, `Read(/certs/**/ca/**)`, `Edit(/config.json)`),
    merged into an existing file; Codex gets `default_permissions = "forti-workspace"`, a permission
    profile that denies the same paths and makes config.json read-only for sandboxed commands
  - Codex trust for the forti home only with consent (asked interactively, default no; or
    `--trust-codex-workspace`): exactly `[projects."<home>"] trust_level = "trusted"` is added to the
    global config with a format-preserving edit, and removed on uninstall only if forti added it
- Home directory guard: project or local scope with $HOME as the project warns and asks
  "Are you sure?" (default no); without a terminal it is refused unless `--force`
- `forti mcp status` shows the workspace scope and scaffold health (JSON: `workspace`);
  `forti mcp uninstall --scope workspace` removes the registration and forti's scaffold files, never
  config.json, credentials, certs or state
- Skill: mentions the workspace convention and that the forti home's secrets are off limits
