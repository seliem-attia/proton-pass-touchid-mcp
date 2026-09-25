# Security Policy & Threat Model

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/seliem-attia/proton-pass-touchid-mcp/security/advisories/new)
instead. You will get an answer within a few days.

## What this project protects against

| Threat | Protection |
|---|---|
| Secrets leaking from plain-text `.env` / MCP config files | Secrets stay in Proton Pass; `.env` files are rendered on demand with mode `0600` |
| An AI agent silently reading *all* your secrets | Each distinct secret needs its own named Touch ID approval per session |
| An agent reading vaults it should not see | The agent token (PAT) is scoped to the vaults you grant |
| Not knowing what the agent accessed | A mandatory `reason` per read, plus Proton's server-side audit log (`pass_audit`) |
| Session database copied from disk | The `pass-cli` session is SQLCipher-encrypted with a key held in the login keychain |
| Key left on disk after use | The session key is held in RAM only, for the lifetime of the MCP process |

## Known limitations (by design or platform)

1. **Touch ID is enforced by the helper, not by a keychain ACL.** Keychain items are
   stored in the file-based login keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
   A process running as your user can call `security find-generic-password -w` and read
   the key after the normal keychain dialog, without Touch ID. Binding to the Secure
   Enclave / data-protection keychain needs an Apple Developer certificate with
   `keychain-access-groups`. **Mitigation:** FileVault, a short screen-lock timeout, and
   no untrusted software running under your account.
2. **The reason text is written by the AI agent.** A prompt-injected agent can write a
   misleading reason. The Touch ID dialog labels it as agent-supplied. Check the
   **item and vault name** before you approve.
3. **Approved secrets enter the model context.** Anything `pass_get_item` returns is part
   of the conversation and is sent to your model provider. Prefer `pass_inject` with
   `outFile` for credentials the agent only needs to *use*.
4. **Approval is per session.** Once a secret is approved, the same MCP process can read
   it again without a new prompt until the process exits. Restart the MCP server to reset.
5. **`pass_item_fields` reads the item without a per-secret tap.** Values are discarded
   inside the server and never returned, but the read is logged by Proton.
6. **`pass_inject` can write anywhere your user can write**, and it overwrites existing files (`-f`).
   The target path is shown in the Touch ID dialog. Check it.
7. **Environment variables.** The key is passed to `pass-cli` through
   `PROTON_PASS_ENCRYPTION_KEY`, as required by the env key provider. Other processes of the
   same user may be able to inspect the environment of child processes.
8. **Ad-hoc code signature.** The helper is signed ad-hoc (`codesign --sign -`). Build it
   yourself from source; do not use binaries from untrusted places.

## Hardening checklist

- [ ] Dedicated vault for AI agents; grant the agent **only** that vault.
- [ ] Short agent token expiry (`--expiration 3m` / `6m`); renew with `pass-cli agent renew`.
- [ ] FileVault on, screen lock ≤ 5 minutes.
- [ ] Review `pass_audit` from time to time.
- [ ] Never commit rendered `.env` files (see `.gitignore`).
