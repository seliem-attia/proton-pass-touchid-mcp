# Security Policy & Threat Model

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/seliem-attia/proton-pass-touchid-mcp/security/advisories/new)
instead. You will get an answer within a few days.

## Assumptions

- Every tool argument comes from an AI agent that may be prompt-injected. It is untrusted.
- The human at the Mac reads the Touch ID dialog before approving.
- The macOS user account itself is not compromised.

## What this project protects against

| Threat | Protection |
|---|---|
| Secrets leaking from plain-text `.env` / MCP config files | Secrets stay in Proton Pass; files are rendered on demand, atomically, with mode `0600` |
| An agent silently reading *all* secrets through the MCP | Each distinct secret needs its own named Touch ID approval per session |
| An agent faking the dialog ("Sandbox key" while reading production) | The target is resolved from metadata first; the dialog shows the real title/vault; `item` and `uri` cannot be combined; agent text is sanitized and capped |
| One template approval reused for more secrets | The approval is bound to the SHA-256 of the canonicalized template and the target; the dialog lists every referenced secret; rendering uses a private copy |
| Overwriting arbitrary files through `pass_inject` | Symlinks and non-regular files are refused; existing files need `overwrite: true`, which is shown in the dialog |
| Option injection into `pass-cli` | `execFile` without a shell; values passed as `--flag=value`; `pass://` references validated |
| Secret values in error messages or listings | Errors never contain stdout, and stderr only when it matches a value-free message class; listings are projected onto a field whitelist |
| TOTP seed exfiltration | Only numeric codes are returned (`pass_get_totp`); TOTP fields, whole-item reads and `?totp=uri` references are refused |
| Template references hidden from the dialog (e.g. with U+0085 whitespace that only pass-cli's regex treats as space) | The parser mirrors pass-cli's Unicode whitespace, and any leftover `{{ … pass:// … }}` after canonicalization rejects the template; max 10 secrets so all are listed |
| Inherited credentials / env overrides from the MCP client | Child processes get a minimal environment |
| Stacked or racing dialogs | Tool calls are serialized; every subprocess and dialog has a timeout |
| An agent reading vaults it should not see | The agent token is scoped to granted vaults; optional `PASS_AGENT_ALLOWED_VAULTS` |
| Not knowing what the agent accessed | A mandatory `reason` per read, plus Proton's server-side audit log |
| Session database copied from disk | The `pass-cli` session is SQLCipher-encrypted with a key held in the login keychain |

## Known limitations

1. **Agents with a shell or file access can bypass the MCP.** Claude Code, Cursor agents and similar tools can run the keychain helper or `pass-cli` directly, or edit this server's code and config. The per-secret guarantee holds only for access *through the MCP*. The hard boundary is the agent token's vault scope: one session-unlock tap can give a shell-capable agent everything the token can read. Use a dedicated vault.
2. **Touch ID is enforced by the helper, not by a keychain ACL.** The key is stored in the file-based login keychain. A process running as your user can call `security find-generic-password -w` and read it after the normal keychain dialog, without Touch ID. A copied `login.keychain-db` plus your login password also decrypts it on another machine. Binding the key to the Secure Enclave or the data-protection keychain needs an Apple Developer certificate. **Mitigation:** FileVault, a short screen-lock timeout, no untrusted software under your account.
3. **The fallback is not biometric.** By default the dialog also accepts the login password or Apple Watch, so a broken sensor cannot lock you out. Set `PASS_KEYCHAIN_BIOMETRY_ONLY=1` to require the fingerprint itself.
4. **The reason text is written by the agent.** It is sanitized, capped and labelled "Agent's reason", but it can still be dishonest. Judge the **item, vault and field lines**, not the reason.
5. **Approved secrets enter the model context.** Anything `pass_get_item` / `pass_get_totp` returns is part of the conversation and is sent to your model provider. Prefer `pass_inject` with `outFile`.
6. **Approval is per session.** An approved secret can be read again by the same MCP process without a new prompt until it exits. Restart the MCP server to reset.
7. **`pass_item_fields` reads the item without a per-secret tap.** Values are discarded inside the server and never returned. The read is logged by Proton.
8. **Environment variables.** The key is handed to `pass-cli` through `PROTON_PASS_ENCRYPTION_KEY`, as required by the env key provider. Processes of the same user may be able to inspect a child's environment.
9. **Loose field matching inside an item.** pass-cli matches field names case-insensitively and may fall back to a section-qualified field (`api_key` → `Prod.api_key`). This stays within the item shown in the dialog.
10. **Item-level shares are not reachable.** Items granted to the agent one by one (not via a vault) do not appear in `vault list`, so this server cannot resolve them.
11. **`passx run`** hands the session key to the child process (a pass-cli design). `passx` blocks it unless `PASSX_ALLOW_RUN=1`.
12. **Ad-hoc code signature.** The helper is signed ad-hoc. Build it yourself from source; do not use binaries from untrusted places.

## Hardening checklist

- [ ] Dedicated vault for AI agents; grant the agent token **only** that vault.
- [ ] Short token expiry (`--expiration 3m` / `6m`); renew with `pass-cli agent renew`.
- [ ] `PASS_AGENT_ALLOWED_VAULTS` set to that vault.
- [ ] `PASS_KEYCHAIN_BIOMETRY_ONLY=1` if you never need the password fallback.
- [ ] FileVault on, screen lock ≤ 5 minutes.
- [ ] Review `pass_audit` from time to time.
- [ ] Never commit rendered `.env` files (see `.gitignore`).
