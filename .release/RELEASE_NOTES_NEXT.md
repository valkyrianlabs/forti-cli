<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Homebrew installs without `brew trust`

`brew install valkyrianlabs/tap/forti-cli` works on current Homebrew with an empty trust store: no
`brew tap`, no `brew trust`. Homebrew trusts the formulae you name in full and refuses to load any
other formula from a third-party tap, even a build dependency of a bottle it pours. The formula
used to depend on `valkyrianlabs/tap/forti-api`, so the install stopped with "Refusing to load
formula valkyrianlabs/tap/forti-api from untrusted tap valkyrianlabs/tap". It now depends on
homebrew/core only and compiles in forti-api 1.3.0 from that release's archive.

Homebrew no longer installs forti-mcp with forti-cli (it was the second formula from the tap that
the install had to load). Name both to get `forti mcp install`'s server:

```sh
brew install valkyrianlabs/tap/forti-cli valkyrianlabs/tap/forti-mcp
```

If an earlier forti-cli installed forti-mcp for you, run `brew install valkyrianlabs/tap/forti-mcp`
once: Homebrew then records it as installed on request, and `brew autoremove` leaves it. APT is
unchanged (forti-cli still recommends forti-mcp).
