<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Bottles for every Mac on macOS 15 or later

- **Homebrew pours a bottle on macOS 15 or later, on Apple silicon and Intel.** forti 0.4.1 could
  not be built on macOS 15 at all, because forti-api 1.1.0 needed Xcode 26's C++ library; forti-api
  1.1.1 fixes that, and forti now requires it.
- **The `.deb` installs on its own again.** It recommends `valkyrianlabs-archive-keyring` instead of
  depending on it: installs from the APT repository still get the keyring (APT installs recommended
  packages by default), and the package from a GitHub release installs without the repository.

