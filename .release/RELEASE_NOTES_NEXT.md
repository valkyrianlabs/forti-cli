<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# forti: FortiOS from the command line

The first release of `forti`, the FortiOS command-line interface built on forti-api.

## Install

- Debian/Ubuntu (amd64), from the ValkyrianLabs APT repository: `sudo apt install forti-cli`.
- macOS (Homebrew): `brew install valkyrianlabs/tap/forti-cli` (builds from source).
