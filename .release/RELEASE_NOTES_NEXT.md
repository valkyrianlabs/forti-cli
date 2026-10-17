<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# One DHCP reservation at a time: child tables

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

Requires forti-api 1.2.0 (child tables).

