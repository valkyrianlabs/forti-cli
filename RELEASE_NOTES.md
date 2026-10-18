# forti-cli release notes

<!-- vl-release:entry version=0.7.0 -->
## 0.7.0 — Plans no longer pile up: applied plans are deleted, the rest ages out

_Released 2026-10-18_

Every plan used to stay in `~/.forti/state/plans/` forever, applied or not, with its approval records.
forti now cleans up after itself.

##### Applied plans are deleted

- Once an apply has started executing a plan, whatever the outcome (applied, `partial_failure`,
  `outcome_unknown`, `management_connectivity_lost`), the plan file and its approval records are
  deleted: the plan can never run again, and `forti history` and the rollback plan say what it did.
- A small marker, `state/plans/<id>.applied`, stays. It keeps the plan's summary and outcome (never
  values), so `forti plan list` still shows the plan as `applied`, `forti rollback <id>` still finds its
  rollback plan, and applying or approving it again is refused as **already applied**
  (`policy_denied`, reason `already_applied`, with `applied_at`), not "not found". `forti plan show` of
  an applied plan says when it was applied and that it is no longer stored.
- An apply refused before anything was sent (stale plan, approval required, read-only profile,
  tampered plan, unwritable audit log, failed pre-change backup) keeps the plan, so you can approve it
  or retry.
- Rollback plans are plans like any other: kept until they are applied or age out.
- Plans applied by earlier releases are deleted by the first purge; their markers stay.

##### Retention: 30 days by default

- Plans never applied, rollback plans, applied markers and approval records older than the retention
  period are deleted automatically, by the time each records (a plan id begins with its creation
  time), else the file's modification time. Stored action bodies no remaining plan refers to go with
  them.
- The purge runs on every plan and apply and on `forti plan list`. It never runs while an apply is
  executing (applies hold a shared lock on `state/plans/.lock`), so a plan in use is never deleted.
- `forti home retention` shows the period, `forti home retention DAYS` sets it (a whole number of days
  from 1 to 3650, stored as `plan_retention_days` in `config.json`), `forti home retention default`
  restores 30. `forti home` shows it too. A hand-edited value that is not a whole number from 1 to 3650
  is a `config` error naming the setting. Agents cannot change it: no MCP tool writes `config.json`.
- The audit log and configuration backups are not affected (backups keep the 20 most recent).

##### For tools built on the engine

- `list_plans` items gain `stored` (`false` for an applied plan listed from its marker, which also
  carries `applied_at`, `outcome` and `rollback_plan`); `show_plan` of an applied plan is `not_found`
  with reason `already_applied`; `purge_plans(Engine&)` runs the purge. Request and result shapes of
  discover, read, plan and apply are unchanged.

<!-- vl-release:entry version=0.6.0 -->
## 0.6.0 — Large monitor action bodies and action replies

_Released 2026-10-18_

Monitor actions can now carry bodies of many megabytes, such as a DNS threat-feed push of hundreds of
thousands of entries to `monitor/system/external-resource/dynamic`, and forti now reads what the
device answers to an action instead of assuming it worked.

#### Large action bodies are stored once

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

#### Action replies and failed commands

- An action's apply record now keeps the device's reply: `reply` (its `results`, with the same secret
  redaction as a read, cut past 16 KiB with `reply_truncated: true`). `forti apply` prints it.
- Batch actions answer HTTP 200 with one result per command, and FortiOS reports a refused command
  there as `"status": "error"`: for example a threat-feed push sent while FortiOS has not loaded the
  feed yet ("Connect pending"). Such an operation is now `failed` with error code `api` and the error
  entries in its details (`errors`, `error_indexes`, `error_count`), and the apply stops there
  (`partial_failure`, exit 8). Before, it was reported as `applied_unverified`.

<!-- vl-release:entry version=0.5.0 -->
## 0.5.0 — One DHCP reservation at a time: child tables

_Released 2026-10-17_

forti can now read and change **one entry of a table attribute**, such as one reservation of a DHCP
server, without touching the rest of the object. Before, changing one reservation meant writing the
server's whole `reserved-address` list back, and a list written from an old copy silently reverts
reservations someone else changed in the meantime.

```sh
forti get system.dhcp/server 1 --child reserved-address --fields id,ip,mac,description
forti create system.dhcp/server --parent 1 --child reserved-address ip=192.0.2.50 mac=00:00:5e:00:53:32
forti set system.dhcp/server 21 --parent 1 --child reserved-address description=printer
forti delete system.dhcp/server 21 --parent 1 --child reserved-address
```

- **Reads:** `forti get <resource> <key> --child ATTR [--child-key KEY]` lists the entries of the
  object's table attribute, or reads one. `--fields` and `--filter` name the entry's attributes and
  are checked before anything is sent; secrets are redacted as in every read.
- **Changes:** `forti set`, `create`, `delete` (and `forti plan`) take `--parent KEY --child ATTR`.
  The plan, the drift check, the verification and the rollback cover that one entry: a change to the
  object's other entries since planning does not make the plan stale, a change to this entry does.
  An update sends only the attributes it changes. A numeric id left out of `create` is assigned by
  the device, and forti records the id it reported, so `forti rollback` deletes exactly that entry.
  The risk tier is the object's.
- **Engine and MCP requests:** reads take `"child"` and `"child_key"`; operations take `"parent"` and
  `"child"`. Every existing request, result and stored plan works as before.
- A plan that sets a whole table attribute on an object now says, in its notes, how to change one
  entry instead.
- Documented: revoking DHCP leases is the monitor action `monitor/system/dhcp/revoke` with
  `{"ip": ["192.0.2.50"]}` (risk elevated).

### Webhook header secrets are redacted

Automation actions keep webhook headers as `http-headers` entries (`{"id", "key", "value"}`), and
FortiOS returns the value in cleartext. forti now redacts the value of every entry whose key names a
credential header (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token`, or
any name containing `token`, `secret`, `password` or `api-key`) in reads, plan diffs, request
previews, verification mismatches and error details, as it does for other secrets. Stored plan files
keep the real value (owner-only) so apply can write it, and a plan still refuses `"<redacted>"` as a
value.

Requires forti-api 1.2.0 (child tables).

<!-- vl-release:entry version=0.4.2 -->
## 0.4.2 — Bottles for every Mac on macOS 15 or later

_Released 2026-10-16_

- **Homebrew pours a bottle on macOS 15 or later, on Apple silicon and Intel.** forti 0.4.1 could
  not be built on macOS 15 at all, because forti-api 1.1.0 needed Xcode 26's C++ library; forti-api
  1.1.1 fixes that, and forti now requires it.
- **The `.deb` installs on its own again.** It recommends `valkyrianlabs-archive-keyring` instead of
  depending on it: installs from the APT repository still get the keyring (APT installs recommended
  packages by default), and the package from a GitHub release installs without the repository.

<!-- vl-release:entry version=0.4.1 -->
## 0.4.1 — One command per change, one approval for agents

_Released 2026-10-16_

(0.4.1 is the first published 0.4 release: 0.4.0 was tagged, but its release stopped before
publishing anything, at a packaging check. Nothing else changed.)

forti 0.4 makes a routine firewall change one command, with at most one question, and lets an agent
make one with a single approval in the chat. Planning, validation, drift checks, verification,
rollback plans and the audit log all still happen; you just no longer handle them by hand.

#### Changes in one command

```sh
forti set firewall/address/web comment="Web server"
forti create firewall/address name=web subnet="192.0.2.10 255.255.255.255"
forti delete firewall/address/web
forti rollback
```

forti reads the device, shows exactly what will change, and then follows the profile's mode:

- **read-only** shows the change, changes nothing, and prints the command that allows changes;
- **guarded** asks once, *Apply these changes? [y/N]*. Without a terminal it stops there and names
  `forti approve ID`: a missing terminal is never taken as a yes;
- **autonomous** applies straight away.

Resources are named as for `forti get` (`firewall/address/web`, `firewall address web`,
`address web`). `forti plan ... --apply`, `forti apply` and `forti rollback` work the same way, with
the same one question.

#### Approvals for agents

- **In the chat.** forti-mcp 0.4 asks you through the AI client itself (MCP elicitation) when the
  client supports it, as Claude Code and Codex do: you see the change and accept or decline. Your
  answer, not the agent, approves that exact plan.
- **In a terminal.** `forti approve ID` shows the plan an agent made and asks; `forti approve --watch`
  stays open and asks about each plan as agents make them. Without a terminal, `forti approve` needs
  `--yes`.
- An approval is bound to the plan you were shown: a plan changed after it was shown is refused.
- The `~/.forti` workspace denies Claude Code's shell `forti approve` and `forti profile mode`, so a
  guarded agent cannot approve its own plans by accident.
- With several plans waiting for one device, forti never guesses which one you mean: scripts and
  agents name their plan, and at a terminal you pick from the list.

#### See what changed

`forti history` lists what was applied: when, on which device, the result, who approved it and what
changed, newest last. `--verbose` adds every operation and the command that undoes it; refused
attempts are hidden unless `--all`.

#### Shell completion

Commands, options, profiles, resource paths and pending plan ids complete in bash, zsh and fish. The
packages install the scripts; `forti completion bash|zsh|fish` prints them.

#### Also

- **Setup:** one question fewer: press Enter at the empty API key prompt for the FortiGate commands
  that create a key. A second profile for the same FortiGate is pointed out.
- **401 errors** no longer imply a wrong key: FortiOS answers the same when this machine is outside
  the API user's trusted hosts, which forti now says first. 403 points at the admin profile.
- **Startup** is back to about 6 ms (0.3 took about 25 ms).
- **Homebrew** pours a bottle on Apple silicon Macs running macOS 26 or later; other Macs build from
  source.
- **APT** packages depend on `valkyrianlabs-archive-keyring`, which keeps the repository signing key
  current through normal upgrades.

<!-- vl-release:entry version=0.3.1 -->
## 0.3.1 — Setup in one pass, changes in one step, certificates built in

_Released 2026-10-16_

forti 0.3 is about getting started quickly and doing common things in fewer steps. (0.3.1 is the
first published 0.3 release: 0.3.0 was tagged, but its release stopped at a test that caught plans
made within the same second being ordered wrongly. That is fixed.)

### forti configure

- **One address.** `fw.example.net`, `192.0.2.1:8443`, `[2001:db8::1]:8443` or an https URL, at the
  prompt or as `--host`. The separate port prompt is gone.
- **Trust on first use.** A FortiGate with a self-signed or factory certificate no longer dead-ends.
  Right after the address, forti looks at the certificate (handshake only: no request, no API key),
  shows its names and SHA-256 fingerprint, and asks. A yes pins that exact certificate as the
  profile's CA bundle, so verification stays on against it. A factory certificate that names the
  serial number is verified for that name while forti connects to the address. Verification cannot
  be turned off.
- **No API key yet?** Answer n to *Do you have a REST API key?* and forti prints the FortiOS commands
  that create a REST API admin (admin profile, trusted host with this machine's address, key).
- **The key** is typed hidden, or `env:VARIABLE` / `cmd:COMMAND` to read it from elsewhere.
- **Fewer questions.** VDOM, CA bundle and connect-to IP are asked only when needed (the VDOM when
  the device has several) or with `--advanced`. The profile is named last, after the device.
- **Failures keep your answers.** The check says what failed, once, and offers fixes: type the key
  again (never retried on its own), change the address, trust the certificate, give a CA bundle,
  connect to an IP, save without checking.
- **More FortiGates:** `forti configure --like fw01`, or *Start from fw01's settings?* at the
  terminal, asks only for the address and the key; mode, VDOM, timeouts and the client certificate
  come along.
- Scripts may leave out `--profile` for the first profile (`default`).

### Client certificates

- `forti configure` asks *Use a client certificate?*: reuse one (a numbered list; Enter takes the
  first) or make one, then forti prints the FortiGate commands, CA inline and ready to paste, and
  waits for you to run them before the check. `--cert NAME` does the same in scripts.
- Certificates are named (`~/.forti/certs/<name>/`) and need no profile: one can serve every
  FortiGate. The **forti CA** (`~/.forti/ca/`) issues them; a FortiGate imports it once, and
  renewing (`forti cert create NAME --force`) needs no change on the FortiGate.
- New: `forti cert list`, `forti cert use NAME -p PROFILE`. `doctor` warns 30 days before a
  certificate expires.

### Changes: plan, approve, apply, undo

- Plan IDs: a unique prefix, the last part (`b75ef1`), or `latest`. Without an ID at a terminal,
  forti takes the newest plan waiting to be applied and shows it first.
- Guarded mode at a terminal: `forti apply` shows the plan and asks *Approve and apply?*; after
  `forti plan approve`, *Apply now?*. Without a terminal nothing is approved implicitly.
- `--apply` on the plan commands plans and applies in one command, as the mode allows.
- **`forti rollback [PLAN]`** undoes the last apply (or a named plan) with its rollback plan.
- `plan create` takes `attr=value`; misspelt attributes get *did you mean …?*.

### Reads

- Resources as admins name them: `forti get firewall address`, `forti get address` (a unique last
  word), `forti get firewall/address/web` (the key in the path). Ambiguous names list the candidates.
- `--all` reads every page. Paging notes go to stderr, so pipelines never take them for data.

### AI clients

- `forti mcp install` (the old `forti install mcp` still works): Enter applies, and trusts the
  Codex workspace when you chose it. Each client is probed once; paths show as `~`.
- forti-cli installs forti-mcp with it (Homebrew dependency, Debian Recommends), and Homebrew
  installs pour a bottle instead of compiling.
- The workspace denies agents the forti CA's key. Set up before 0.3? Run `forti mcp install
  --scope workspace` again to add the rule.

### Errors and help

- An unknown profile, or several profiles and no default, lists the profiles and how to choose one.
- A missing client certificate or CA bundle is reported before any request, with the command that
  recreates it. The read-only refusal names `forti profile mode NAME guarded`.
- `forti` with nothing configured says where to start. Per-command help ends in one line of global
  options; `man forti` keeps the full reference.

Certificates and profiles made by 0.2 keep working.

<!-- vl-release:entry version=0.2.0 -->
## 0.2.0 — One home for forti: ~/.forti, certificates and the MCP workspace

_Released 2026-10-16_

### Everything in ~/.forti

forti now keeps everything in one directory, the forti home: `~/.forti`, or `$FORTI_HOME`. Profiles
and file-stored secrets, plans, approvals, the audit log, backups and client certificates all live
there. `forti home` shows every location.

Coming from 0.1? Nothing breaks: an existing `~/.config/forti` setup keeps working, and `forti home`
and `forti doctor` point it out. Move it with one command:

```sh
forti home migrate
```

It moves the configuration, stored credentials, state and cache, keeps their permissions, never
overwrites an existing `~/.forti/config.json`, and is safe to run again. Keychain entries need no change.

### Client certificates in one command

FortiOS can require a client certificate from the REST API user on top of the API key. forti now
makes everything that needs:

```sh
forti cert create --profile fw01
```

This creates a private CA and a client certificate in `~/.forti/certs/fw01/`, points the profile at
them, and prints the exact FortiGate commands: import the CA, create the PKI user and peer group, and
enable `peer-auth` for the API user. The certificate's password stays in a private file (or, with
`--keychain`, in the macOS Keychain). forti never prints it; it shows the command that reads it.
`forti cert show` reports expiry and fingerprints, and `forti cert remove` cleans up. It uses the system
`openssl` command (macOS's built-in one works).

### Several FortiGates, less typing

- `forti profile copy fw01 fw02` starts a new profile from an existing one's settings (never its key).
- `forti profile set fw02 host=fw02.example.net port=8443` changes settings without prompts.
- `forti profile rename lab fw01` takes the stored key, the certificates and the default along.
- `forti configure --profile fw02` edits an existing profile with every prompt prefilled.

### The MCP workspace

`forti install mcp` now recommends one place for the FortiGate tools: the forti home, `~/.forti`.
Pick "~/.forti workspace (recommended)" (or pass `--scope workspace`), then start your agent there:

```sh
forti install mcp --client all --scope workspace --trust-codex-workspace --yes
cd ~/.forti && claude      # or: codex
```

An agent started in `~/.forti` gets `forti_discover`, `forti_read`, `forti_plan` and `forti_apply`;
an agent started in any other project does not. The workspace comes with a short `AGENTS.md` (and a
`CLAUDE.md` pointing at it) and the forti skill for both clients.

The same directory holds your profiles, credentials and certificates, so the workspace keeps them
out of the agent's context: Claude Code gets deny rules in `.claude/settings.json` for
`credentials/`, certificate passwords, PKCS#12 files and CA keys, and for editing `config.json`;
Codex gets a `forti-workspace` permission profile that denies the same paths to the commands it
runs. Your own settings in those files are kept.

Codex only reads a project's `.codex/config.toml` once the project is trusted. forti asks before it
marks `~/.forti` as trusted in your global Codex config (or takes `--trust-codex-workspace`), adds
exactly that one entry, and removes it again on uninstall only if it added it.

`forti install mcp` also warns when the project directory is your home directory itself: an agent
started anywhere under it would get the firewall tools. It asks "Are you sure?" (default no), and
refuses without a terminal unless you pass `--force`.

`forti mcp status` shows the workspace and the health of its files; `forti mcp uninstall --scope
workspace` removes the registration and the files forti wrote, and never touches `config.json`,
credentials, certificates or state.


### Documentation

The quick start now goes from install to an agent working in `~/.forti` in five commands, and a new
Client certificates guide walks through `forti cert create` and the FortiGate side.

<!-- vl-release:entry version=0.1.1 -->
## 0.1.1 — Documentation in Payload Markdown

_Released 2026-10-15_

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

<!-- vl-release:entry version=0.1.0 -->
## 0.1.0 — forti: FortiOS from the command line

_Released 2026-10-15_

The first release of `forti`, a native FortiOS command-line interface built on
[forti-api](https://github.com/valkyrianlabs/forti-api). It reaches every endpoint the SDK
generates (487 configuration tables and singletons from FortiOS 7.4.8, plus monitor data) without a
hand-written command per resource, and it registers the companion MCP server with AI clients in one
command.

- **Discover and read anything.** `forti discover` searches resources and shows their attributes,
  merging the device's own schema (help, options, ranges) with `--live`. `forti get` reads
  configuration and monitor data with FortiOS filters, field projection and paging. Text output for
  people, a stable JSON envelope with `--json`, and consistent exit codes for scripts.
- **Profiles and credentials.** `forti configure` (interactive or flag-driven) stores device
  profiles, with the API key in the macOS Keychain or an owner-only file, or read from an environment
  variable or a command. A key is never accepted as an argument, and a stored key only goes to the
  host it was saved for. TLS is always verified; `--ca-bundle` and `--resolve-ip` cover self-signed
  and internal names. `forti doctor` checks the whole path, from file modes to authentication.
- **Planned, verified changes.** `forti plan` validates changes against the SDK's types and the live
  objects and records the exact diff, request bodies and risk tier. `forti apply` executes a plan once,
  in order, never retries a write, verifies every change by reading it back, writes a rollback plan
  and an audit record, and reports partial failures and unknown outcomes truthfully. Critical changes
  (management access, routing, interfaces, admins) take a configuration backup first and are followed
  by a management connectivity check.
- **Operating modes.** Each profile is `read-only` (the default), `guarded` (a person runs
  `forti plan approve <id>`) or `autonomous`. The FortiOS API account's permissions remain the real
  boundary. Rollback plans and backups need a working management path, so they are not a substitute
  for console or out-of-band access.
- **AI clients in one command.** `forti install mcp` registers the native `forti-mcp` server with
  Claude Code and Codex (user or project scope), preserves existing configuration, never writes a
  secret into it, optionally installs the forti agent skill, and is idempotent; `forti mcp status`,
  `repair` and `uninstall` manage it afterwards.
- Device secrets in read results are redacted unless you ask for them (`forti get --reveal`).

### Install

- Debian/Ubuntu (amd64), from the ValkyrianLabs APT repository: `sudo apt install forti-cli`.
- macOS (Homebrew): `brew install valkyrianlabs/tap/forti-cli` (builds from source).
- From source: Meson and a C++23 compiler (GCC 13+ or Apple clang); see the README.

Then `forti configure`, `forti doctor`, `forti get firewall/policy`, and `forti install mcp`.
