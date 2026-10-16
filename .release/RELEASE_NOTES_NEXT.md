<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Client certificates in forti configure, shared across FortiGates

Setting up a client certificate no longer takes a separate command, and it no longer needs an
existing profile.

## forti configure makes or reuses the certificate

After the API key, `forti configure` asks *Use a client certificate?*. Answer **y** and either reuse
one you already have (a numbered list: Enter takes the first, `0` makes a new one) or make a new one.
forti then prints the FortiGate commands for it, with the CA certificate inline and ready to paste,
and waits: press Enter once the FortiGate is set up, and the connection check proves the API key and
the certificate work together (`s` saves without checking). A certificate made there is kept even if
the check fails, so you never redo the FortiGate side. Scripts use `forti configure --cert NAME`.

## Certificates are named, and the forti CA issues them

- A certificate lives in `~/.forti/certs/<name>/` and needs no profile: `forti cert create fw01`
  works before any profile exists, and one certificate can serve every FortiGate you manage.
- The **forti CA** (`~/.forti/ca/`, made on first use) issues them. A FortiGate imports it once and
  then accepts any forti certificate you register on it. Renewing (`forti cert create NAME --force`)
  keeps the CA and the CN, so the FortiGate needs no change. `--own-ca` gives a certificate a CA of
  its own instead, as 0.2 did.
- New: `forti cert list` (the forti CA and every certificate, with issuer, expiry and the profiles
  using it) and `forti cert use NAME --profile P`. `forti cert show` and `remove` take a NAME;
  `remove` detaches the certificate from every profile that used it.

Certificates made by 0.2 keep working: they appear in `forti cert list` as certificates with their
own CA, under the profile's name.

## AI workspace

The forti CA's key is denied to agents like the other private files. If you set up the `~/.forti`
workspace with an earlier release, run `forti install mcp --scope workspace` again to add the rule.

