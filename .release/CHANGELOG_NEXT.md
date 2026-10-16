<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Depend on valkyrianlabs-archive-keyring so renewed APT signing-key metadata reaches existing installs
  through upgrades (it owns /usr/share/keyrings/valkyrianlabs.gpg and links an unmodified
  /etc/apt/keyrings/valkyrianlabs.gpg to it).
- New `forti history`: the audit log for people (newest last; `-p` filters by profile, `-n` limits,
  `--all` shows refused attempts, `--verbose` adds operations, approvals and the undo command;
  `--json` prints the events as recorded). Reads only the state directory.
- New `forti completion bash|zsh|fish`; the scripts are installed to
  `/usr/share/bash-completion/completions/forti`, `/usr/share/zsh/site-functions/_forti` and
  `/usr/share/fish/vendor_completions.d/forti.fish` (Meson option `completions`). Candidates come
  from the hidden `forti __complete` (profile names, resource paths, pending plan ids; no device
  access, no secrets).
- New `forti set|create|delete`: one command per change, at most one question. read-only shows the
  change and the mode command; guarded asks "Apply these changes? [y/N]" at a terminal and otherwise
  stops at the approval (a missing terminal is never a yes); autonomous applies. Resources are named
  as for `forti get`; `--dry-run`, `--verbose`, `--json`.
- New `forti approve [id] [--yes]` and `forti approve --watch`: approve a plan for the agent that made
  it. Without a terminal only `--yes` approves (previously stdout not being a terminal was enough).
  `forti plan approve` is the same command; it no longer offers "Apply now?".
- Plans are picked without an id only when one is waiting for the profile (made in the last day); at a
  terminal several are listed to choose from. Without a terminal apply/approve need the id.
- `forti apply`, `forti rollback` and `forti plan --apply` show the change concisely and ask once.
- Engine: approvals are bound to the digest of the plan shown (`approve_plan(..., shown_digest)`);
  audit events record the actor (`cli:USER`, `mcp:CLIENT`), a summary and who approved the plan;
  the approval command is `forti approve ID`.
- The forti workspace denies Claude Code's shell `forti approve`, `forti plan approve` and
  `forti profile mode`.
- `forti configure`: Enter on the empty API key prompt prints the FortiGate steps (no separate
  question); a second profile for the same FortiGate (serial or address) is noted; profiles record
  the serial the check saw.
- 401 advice: the key may be right; FortiOS also answers 401 outside the API user's trusted hosts.
  403 points at the admin profile.
- Build: hidden symbol visibility: `forti` starts in ~6 ms again (forti-api's inline schema tables
  were coalesced by dyld at every start, ~20 ms).
- Release: Homebrew bottles for arm64 and Intel, built on macOS 15.
