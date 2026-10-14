#!/usr/bin/env python3
"""Embeds skill/forti/SKILL.md in a C++ header, so `forti install mcp --skill` needs no data files.

Also checks the frontmatter (name, description length) so an invalid skill fails the build instead of
being silently ignored by Claude Code or Codex.
"""
import re
import sys

DELIMITER = "forti_skill"


def main(source: str, output: str) -> int:
    with open(source, encoding="utf-8") as f:
        text = f.read()
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not match:
        sys.exit(f"{source}: frontmatter must start on line 1")
    fields = dict(line.split(":", 1) for line in match.group(1).splitlines() if ":" in line)
    if fields.get("name", "").strip() != "forti":
        sys.exit(f"{source}: frontmatter needs `name: forti`")
    description = fields.get("description", "").strip()
    if not description or len(description) >= 1024:
        sys.exit(f"{source}: description must be 1-1023 characters (is {len(description)})")
    if f"){DELIMITER}\"" in text:
        sys.exit(f"{source}: contains the raw-string delimiter")
    with open(output, "w", encoding="utf-8") as f:
        f.write("// Generated from skill/forti/SKILL.md by src/install/embed_skill.py. Do not edit.\n")
        f.write("#pragma once\n#include <string_view>\n\nnamespace forti::install {\n")
        f.write(f'    inline constexpr std::string_view embedded_skill = R"{DELIMITER}(')
        f.write(text)
        f.write(f'){DELIMITER}";\n}}  // namespace forti::install\n')
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
