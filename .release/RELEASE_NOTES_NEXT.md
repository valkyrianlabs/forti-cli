<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# One command per change, one approval for agents

(0.4.1 is the first published 0.4 release: 0.4.0 was tagged, but its release stopped before
publishing anything, at a packaging check. Nothing else changed.)

forti 0.4 makes a routine firewall change one command, with at most one question, and lets an agent
make one with a single approval in the chat. Planning, validation, drift checks, verification,
rollback plans and the audit log all still happen; you just no longer handle them by hand.

### Changes in one command

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

### Approvals for agents

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

### See what changed

`forti history` lists what was applied: when, on which device, the result, who approved it and what
changed, newest last. `--verbose` adds every operation and the command that undoes it; refused
attempts are hidden unless `--all`.

### Shell completion

Commands, options, profiles, resource paths and pending plan ids complete in bash, zsh and fish. The
packages install the scripts; `forti completion bash|zsh|fish` prints them.

### Also

- **Setup:** one question fewer: press Enter at the empty API key prompt for the FortiGate commands
  that create a key. A second profile for the same FortiGate is pointed out.
- **401 errors** no longer imply a wrong key: FortiOS answers the same when this machine is outside
  the API user's trusted hosts, which forti now says first. 403 points at the admin profile.
- **Startup** is back to about 6 ms (0.3 took about 25 ms).
- **Homebrew** pours a bottle on Apple silicon Macs running macOS 26 or later; other Macs build from
  source.
- **APT** packages depend on `valkyrianlabs-archive-keyring`, which keeps the repository signing key
  current through normal upgrades.
