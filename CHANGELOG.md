# Changelog

## 2.2.0 — 2026-09-25 (first public release)

Security hardening after an internal review and a comparison with other Proton Pass MCP servers:

- **Target resolution before approval.** Items are resolved from metadata (`vault list` / `item list`) and read by share/item ID. The Touch ID dialog shows the real title and vault. `item` + `uri` together are refused, and ambiguous titles are refused with candidates.
- **`pass_inject` rebuilt.** Every reference is resolved and rewritten to canonical IDs and listed in the dialog. The approval is bound to the content hash, target and overwrite flag. Rendering uses a private copy of the template, writes atomically with mode `0600`, refuses symlinks, and needs `overwrite: true` for existing files.
- **New `pass_get_totp`.** It returns numeric codes only. TOTP seed reads through `pass_get_item` are refused.
- Dialog text is sanitized (control, bidi and zero-width characters removed) and length-capped. Input sizes are limited by schema.
- Listings are projected onto a field whitelist. Errors never echo `pass-cli` stdout.
- Minimal child environment, timeouts on every subprocess and dialog, serialized tool calls, `--flag=value` arguments, `umask 077`.
- Approvals are recorded only after a successful read, with collision-free keys.
- Optional `PASS_AGENT_ALLOWED_VAULTS` and `PASS_KEYCHAIN_BIOMETRY_ONLY`.
- MCP tool annotations and server instructions. `pass_status` shows the `pass-cli` version.
- `passx` no longer passes the key as a command-line argument to `env`.
- English UI, docs, `install.sh`, an end-to-end security test suite (fake `pass-cli` + fake keychain), CI with SHA-pinned actions, and Dependabot.

## 2.0.0 — 2026-08-16

- Auto re-login also recognizes `non-existent session` / `failed to authenticate`.

## 1.x — 2026-07-02

- Auto re-login recognizes `No active session` / `session expired`.
- New tool `pass_item_fields` (field names only, values discarded).
- Touch ID per secret and session (v2 model).
