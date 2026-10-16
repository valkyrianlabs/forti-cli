<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Setup in one pass, changes in one step, certificates built in

forti 0.3 is about getting started quickly and doing common things in fewer steps. (0.3.1 is the
first published 0.3 release: 0.3.0 was tagged, but its release stopped at a test that caught plans
made within the same second being ordered wrongly. That is fixed.)

## forti configure

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

## Client certificates

- `forti configure` asks *Use a client certificate?*: reuse one (a numbered list; Enter takes the
  first) or make one, then forti prints the FortiGate commands, CA inline and ready to paste, and
  waits for you to run them before the check. `--cert NAME` does the same in scripts.
- Certificates are named (`~/.forti/certs/<name>/`) and need no profile: one can serve every
  FortiGate. The **forti CA** (`~/.forti/ca/`) issues them; a FortiGate imports it once, and
  renewing (`forti cert create NAME --force`) needs no change on the FortiGate.
- New: `forti cert list`, `forti cert use NAME -p PROFILE`. `doctor` warns 30 days before a
  certificate expires.

## Changes: plan, approve, apply, undo

- Plan IDs: a unique prefix, the last part (`b75ef1`), or `latest`. Without an ID at a terminal,
  forti takes the newest plan waiting to be applied and shows it first.
- Guarded mode at a terminal: `forti apply` shows the plan and asks *Approve and apply?*; after
  `forti plan approve`, *Apply now?*. Without a terminal nothing is approved implicitly.
- `--apply` on the plan commands plans and applies in one command, as the mode allows.
- **`forti rollback [PLAN]`** undoes the last apply (or a named plan) with its rollback plan.
- `plan create` takes `attr=value`; misspelt attributes get *did you mean …?*.

## Reads

- Resources as admins name them: `forti get firewall address`, `forti get address` (a unique last
  word), `forti get firewall/address/web` (the key in the path). Ambiguous names list the candidates.
- `--all` reads every page. Paging notes go to stderr, so pipelines never take them for data.

## AI clients

- `forti mcp install` (the old `forti install mcp` still works): Enter applies, and trusts the
  Codex workspace when you chose it. Each client is probed once; paths show as `~`.
- forti-cli installs forti-mcp with it (Homebrew dependency, Debian Recommends), and Homebrew
  installs pour a bottle instead of compiling.
- The workspace denies agents the forti CA's key. Set up before 0.3? Run `forti mcp install
  --scope workspace` again to add the rule.

## Errors and help

- An unknown profile, or several profiles and no default, lists the profiles and how to choose one.
- A missing client certificate or CA bundle is reported before any request, with the command that
  recreates it. The read-only refusal names `forti profile mode NAME guarded`.
- `forti` with nothing configured says where to start. Per-command help ends in one line of global
  options; `man forti` keeps the full reference.

Certificates and profiles made by 0.2 keep working.
