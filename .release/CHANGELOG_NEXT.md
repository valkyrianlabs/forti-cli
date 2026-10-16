<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

- configure: one address prompt (host[:port] or https URL, also --host); trust
  on first use via forti-api probe_tls (show, confirm, pin the device
  certificate as ca_bundle; serial-named certificates via resolve_ip); API
  key as typed / env:VAR / cmd:CMD; FortiOS commands for a REST API admin;
  VDOM / CA bundle / resolve-ip only on need or --advanced; name after the
  device; recovery menu that keeps answers; --like PROFILE; first scripted
  profile defaults to "default".
- cert: named sets in <home>/certs/<name>/, issued by the forti CA in
  <home>/ca/ unless --own-ca; configure offers reuse/create (--cert NAME);
  new cert list and cert use; FortiOS steps carry the CA inline.
- plan/apply: id prefixes, last part and latest; newest pending plan at a
  terminal; inline approval for guarded apply; Apply now? after approve;
  --apply; new rollback command; plan create attr=value; attribute
  suggestions; digest only with --verbose.
- get/discover: CLI word order, unique leaf names, keys in the path, --all;
  paging notes on stderr; attribute suggestions.
- mcp: `forti mcp install` (install mcp kept), Yes defaults for apply and
  Codex trust, one probe per client, ~ paths; workspace denies <home>/ca/.
- doctor: certificate expiry (30 days), the fix for a missing certificate,
  ~ paths, summary after the report. Errors list profiles; missing
  certificate files are caught before any request.
- Packaging: Homebrew bottle built and published with each release; the
  formula depends on forti-mcp and the .deb recommends it.
- plans: created_ns orders plans made within one second (`latest`, plan list);
  0.3.0 was tagged but not published.
