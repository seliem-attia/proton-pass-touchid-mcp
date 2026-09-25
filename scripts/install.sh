#!/bin/bash
# Installs proton-pass-touchid-mcp into $PASS_AGENT_HOME (default ~/.config/proton-pass-agent):
#   1. copies the MCP server + passx and installs npm dependencies
#   2. builds the Touch ID keychain helper from source
#   3. creates a random session encryption key in the login keychain (if missing)
#   4. stores your agent token (PAT) in the login keychain and signs pass-cli in as the agent
# Re-running is safe: existing keychain entries and sessions are kept.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${PASS_AGENT_HOME:-$HOME/.config/proton-pass-agent}"
SERVICE="${PASS_AGENT_KEYCHAIN_SERVICE:-proton-pass-agent}"
SESSION="${PASS_AGENT_SESSION_DIR:-$TARGET/session}"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || fail "macOS only (Touch ID + login keychain)."
command -v swiftc >/dev/null || fail "swiftc not found. Install the Xcode Command Line Tools: xcode-select --install"
command -v node   >/dev/null || fail "Node.js >= 18 not found."
command -v npm    >/dev/null || fail "npm not found."
PASS_CLI="${PASS_CLI_BIN:-$(command -v pass-cli || true)}"
[ -n "$PASS_CLI" ] || fail "pass-cli not found. Install Proton Pass CLI first (see README)."

say "Installing into $TARGET"
mkdir -p "$TARGET/mcp" "$SESSION"
chmod 700 "$TARGET" "$SESSION"
cp "$REPO/mcp/index.mjs" "$REPO/mcp/smoke-test.mjs" "$REPO/mcp/package.json" "$REPO/mcp/package-lock.json" "$TARGET/mcp/"
cp "$REPO/bin/passx" "$TARGET/passx"
chmod 755 "$TARGET/passx"
(cd "$TARGET/mcp" && npm ci --omit=dev --no-audit --no-fund --silent)

# The keychain entries trust the helper by its code signature. An ad-hoc signature changes
# with EVERY build (swiftc output is not reproducible), and macOS then asks for the login
# password. So the helper is only rebuilt when its source changed, and existing entries are
# then re-bound to the new build (one Touch ID + one keychain password prompt per entry, once).
has_item() { security find-generic-password -s "$SERVICE" -a "$1" >/dev/null 2>&1; }
SRC_HASH="$( { cat "$REPO/helper/pass-keychain.swift"; swiftc --version 2>/dev/null; } | shasum -a 256 | cut -d' ' -f1)"
HASH_FILE="$TARGET/.pass-keychain.sha256"
REBUILT=0
if [ -x "$TARGET/pass-keychain" ] && [ "$(cat "$HASH_FILE" 2>/dev/null)" = "$SRC_HASH" ]; then
  say "Touch ID keychain helper unchanged — keeping the existing build"
else
  say "Building Touch ID keychain helper"
  swiftc -O "$REPO/helper/pass-keychain.swift" -o "$TARGET/pass-keychain.new"
  codesign --force --sign - "$TARGET/pass-keychain.new" >/dev/null 2>&1 || fail "codesign of the helper failed"
  chmod 755 "$TARGET/pass-keychain.new"
  mv -f "$TARGET/pass-keychain.new" "$TARGET/pass-keychain"
  echo "$SRC_HASH" > "$HASH_FILE"   # record right away, so an aborted re-bind never triggers another rebuild
  REBUILT=1
fi
if [ "$REBUILT" = 1 ]; then
  for acct in encryption-key pat; do
    if has_item "$acct"; then
      say "Re-binding keychain entry '$acct' to the new helper build"
      echo "    macOS asks for your login password once for this entry (then Touch ID only)."
      "$TARGET/pass-keychain" rebind "$SERVICE" "$acct" "Proton Pass MCP setup: re-authorize helper for '$acct'" \
        || fail "re-binding '$acct' failed; the entry is unchanged (or kept as '$acct.rebind'). Retry with:
  \"$TARGET/pass-keychain\" rebind $SERVICE $acct"
    fi
  done
fi

if has_item encryption-key; then
  say "Session encryption key already in keychain ($SERVICE/encryption-key) — keeping it"
else
  say "Creating random session encryption key in the login keychain"
  openssl rand -base64 48 | tr -d '\n' | "$TARGET/pass-keychain" store "$SERVICE" encryption-key
fi

if has_item pat; then
  say "Agent token already in keychain ($SERVICE/pat) — keeping it"
else
  cat <<'EOF'

Create an agent token first (as your normal Proton user account, in another terminal):

  pass-cli login                                  # sign in as yourself (once)
  pass-cli agent create "Claude Code" --expiration 1y --vault "AI Secrets"

Grant only the vault(s) the agent really needs. Copy the printed token (pst_...::...).

EOF
  read -r -s -p "Paste agent token (input hidden): " PAT; echo
  [ -n "$PAT" ] || fail "empty token"
  printf '%s' "$PAT" | "$TARGET/pass-keychain" store "$SERVICE" pat
  unset PAT
fi

say "Signing pass-cli in as the agent (Touch ID prompts follow)"
KEY="$("$TARGET/pass-keychain" read "$SERVICE" encryption-key "Proton Pass MCP setup: unlock session key")"
if PROTON_PASS_KEY_PROVIDER=env PROTON_PASS_ENCRYPTION_KEY="$KEY" PROTON_PASS_SESSION_DIR="$SESSION" \
     "$PASS_CLI" info >/dev/null 2>&1; then
  say "Existing agent session is valid"
else
  PAT="$("$TARGET/pass-keychain" read "$SERVICE" pat "Proton Pass MCP setup: sign in with agent token")"
  PROTON_PASS_KEY_PROVIDER=env PROTON_PASS_ENCRYPTION_KEY="$KEY" PROTON_PASS_SESSION_DIR="$SESSION" \
    PROTON_PASS_PERSONAL_ACCESS_TOKEN="$PAT" "$PASS_CLI" login
  unset PAT
fi
unset KEY

cat <<EOF

Done. Add the server to your MCP client:

  Claude Code:     claude mcp add --scope user proton-pass -e PASS_CLI_BIN="$PASS_CLI" -- node "$TARGET/mcp/index.mjs"
  Claude Desktop:  see examples/claude_desktop_config.json and set "PASS_CLI_BIN": "$PASS_CLI"

Optional terminal wrapper:  ln -s "$TARGET/passx" /opt/homebrew/bin/passx
Smoke test (lists titles only):  node "$TARGET/mcp/smoke-test.mjs"
EOF
