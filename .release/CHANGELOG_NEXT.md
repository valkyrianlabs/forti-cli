<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

## Home, certificates and profiles
- One forti home: `$FORTI_HOME`, else `~/.forti` (0700), for config.json, credentials/, state/,
  cache/ and certs/. `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` still override.
  A pre-0.2 XDG setup (`~/.config/forti`, `~/.local/state/forti`, `~/.cache/forti`) stays in use
  until migrated.
- New `forti home` (every location, legacy flag) and `forti home migrate` (renames config.json,
  credentials/, state and cache into the home; modes kept; config.json last; idempotent; never
  overwrites a home config.json; refuses while a `FORTI_*_DIR` override is set).
- `forti doctor` has a first check, `home`, that warns on a pre-0.2 setup.
- New `forti cert create [--profile] [--days N] [--force] [--keychain]`: a private CA and a client
  certificate (CN `forti-<profile>`, RSA 3072, SHA-256) in `<home>/certs/<profile>/` through the
  `openssl` command (argv, no shell). The PKCS#12 uses PBE-SHA1-3DES with a SHA-1 MAC (OpenSSL 3
  without the legacy provider, LibreSSL and FortiOS read it). Sets the profile's client_cert and
  certificate password, prints the password-reading command (never the password) and the FortiOS
  steps (`config vpn certificate ca`, `config user peer`, `config user peergrp`,
  `config system api-user` `peer-auth`/`peer-group`). Plus `forti cert show` and `forti cert remove`.
- New SecretRef source `file` (absolute path; owner-only regular file, as the file store requires);
  `forti configure --cert-password-file PATH`.
- New `forti profile set NAME key=value...` (validated as config.json is; re-binds stored secrets when
  host or port change), `forti profile rename OLD NEW` (moves stored secrets, `certs/OLD`, references
  and the default) and `forti profile copy SOURCE NEW` (settings only, no secrets).
- `forti configure` on an existing profile prefills the API key command and keeps the current
  certificate password source on Enter.
- Debian: `forti-cli` depends on `openssl`.

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
