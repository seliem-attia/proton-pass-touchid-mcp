# Changelog

## 2.1.0 — 2026-09-25 (first public release)

- English UI strings, tool descriptions and docs.
- Touch ID dialog marks the reason as agent-supplied and shows the `pass_inject` target path.
- `uri` must be a `pass://` reference, and positional arguments are passed after `--`, so input can never be parsed as a `pass-cli` flag.
- `pass_inject` refuses `outFile == inFile` and sets `0600` on the rendered file.
- Configurable paths: `PASS_CLI_BIN` (auto-detected), `PASS_AGENT_KEYCHAIN_SERVICE`, `PASS_AGENT_SESSION_DIR`, `PASS_KEYCHAIN_BIN`.
- `scripts/install.sh` for a reproducible setup; CI builds the helper and audits dependencies.

## 2.0.0 — 2026-08-16

- Auto re-login also recognizes `non-existent session` / `failed to authenticate`.

## 1.x — 2026-07-02

- Auto re-login recognizes `No active session` / `session expired`.
- New tool `pass_item_fields` (field names only, values discarded).
- Touch ID per secret and session (v2 model).
