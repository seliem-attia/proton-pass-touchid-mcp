#!/usr/bin/env node
// Proton Pass Touch ID MCP server
// --------------------------------
// Wraps Proton's official `pass-cli` (env key provider). The session encryption
// key and the agent PAT live in the macOS login keychain behind a Touch ID gate
// (see ../helper/pass-keychain.swift).
//
// Touch ID model (per session = lifetime of this process):
//   • Session unlock: the session key is read ONCE via Touch ID on first access.
//   • Per secret: every distinct item/field requires ONE dedicated Touch ID tap on
//     first read. The dialog NAMES the item, vault and the reason given by the agent.
//   • After that, this one secret is approved for the session; another secret = new tap.
//   • The key lives in RAM only (never on disk) and is gone when the process exits.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HOME = process.env.PASS_AGENT_HOME
  || path.dirname(path.dirname(fileURLToPath(import.meta.url))); // install dir (parent of mcp/)
const SESSION_DIR = process.env.PASS_AGENT_SESSION_DIR || path.join(HOME, "session");
const KC_BIN = process.env.PASS_KEYCHAIN_BIN || path.join(HOME, "pass-keychain");
const PASS_CLI = process.env.PASS_CLI_BIN
  || ["/opt/homebrew/bin/pass-cli", "/usr/local/bin/pass-cli"].find(existsSync)
  || "pass-cli";
const KC_SERVICE = process.env.PASS_AGENT_KEYCHAIN_SERVICE || "proton-pass-agent";
const AGENT_NAME = process.env.PASS_AGENT_NAME || "";

const exec = (file, args, opts = {}) =>
  new Promise((resolve) => {
    execFile(file, args, { maxBuffer: 8 * 1024 * 1024, ...opts }, (err, stdout, stderr) =>
      resolve({ code: err?.code ?? 0, stdout: stdout?.toString() ?? "", stderr: stderr?.toString() ?? "", err })
    );
  });

// ---- Session state (process lifetime) ---------------------------------------
let sessionKey = null;                 // env-provider key, RAM only
const approvedSecrets = new Set();     // "vault|item|field" already Touch-ID-approved this session

async function keychainRead(account, reason) {
  const r = await exec(KC_BIN, ["read", KC_SERVICE, account, reason]);
  if (r.code !== 0) throw new Error(`Keychain/Touch ID failed (${account}): ${r.stderr.trim() || "cancelled"}`);
  return r.stdout; // raw secret, no trimming
}
async function touchIdGate(reason) {
  const r = await exec(KC_BIN, ["auth", reason]);
  if (r.code !== 0) throw new Error("Touch ID denied or cancelled");
}

// Load the session key once per session (one Touch ID). `label` is shown in that prompt.
async function ensureKey(label) {
  if (!sessionKey) sessionKey = await keychainRead("encryption-key", label);
  return sessionKey;
}

// The reason text comes from the AI agent, so the dialog marks it as such.
const agentLabel = (what, reason) => `${what}\nReason given by the AI agent: ${reason}`;

// Gate one specific secret: one named Touch ID per (item/field) per session.
async function gateSecret({ vault, item, uri, field, reason }) {
  const id = `${vault || ""}|${item || uri || ""}|${field || "*"}`;
  const what = item || uri || "(item)";
  const where = vault ? ` · vault "${vault}"` : "";
  const fld = field ? ` · field "${field}"` : "";
  const label = agentLabel(`Secret "${what}"${where}${fld}`, reason);
  if (approvedSecrets.has(id)) { await ensureKey(label); return; }
  if (!sessionKey) {
    // First secret of the session: the key-read prompt already names this secret → one tap.
    sessionKey = await keychainRead("encryption-key", label);
  } else {
    // Key already unlocked: dedicated named tap for THIS secret.
    await touchIdGate(label);
  }
  approvedSecrets.add(id);
}

function baseEnv(extra = {}) {
  return {
    ...process.env,
    PROTON_PASS_KEY_PROVIDER: "env",
    PROTON_PASS_ENCRYPTION_KEY: sessionKey,
    PROTON_PASS_SESSION_DIR: SESSION_DIR,
    ...extra,
  };
}
function looksLikeAuthError(r) {
  const s = (r.stderr + r.stdout).toLowerCase();
  // pass-cli reports expired sessions differently depending on the command, e.g.
  // "No active session" (vault/item list), "unauthenticated client" (info) and
  // "failed to authenticate: non-existent session" (info, after a server-side session loss).
  return (
    r.code !== 0 &&
    (s.includes("authenticated client") ||
      s.includes("no session") ||
      s.includes("no active session") ||
      s.includes("session expired") ||
      s.includes("non-existent session") ||
      s.includes("failed to authenticate") ||
      s.includes("unauthorized"))
  );
}
async function relogin() {
  const pat = (await keychainRead("pat", "Proton Pass: sign in again (agent token)")).trim();
  await exec(PASS_CLI, ["logout", "--force"], { env: baseEnv() });
  const r = await exec(PASS_CLI, ["login"], { env: baseEnv({ PROTON_PASS_PERSONAL_ACCESS_TOKEN: pat }) });
  if (r.code !== 0) throw new Error("Re-login failed: " + (r.stderr.trim() || r.stdout.trim()));
}
// Run a pass-cli command (key must already be loaded). Auto-recover once from an expired session.
async function runPass(args, { agentReason } = {}) {
  const extra = agentReason ? { PROTON_PASS_AGENT_REASON: agentReason } : {};
  let r = await exec(PASS_CLI, args, { env: baseEnv(extra) });
  if (looksLikeAuthError(r)) { await relogin(); r = await exec(PASS_CLI, args, { env: baseEnv(extra) }); }
  if (r.code !== 0) throw new Error(r.stderr.trim() || r.stdout.trim() || `pass-cli exit ${r.code}`);
  return r.stdout.trim();
}

// Build the item selector for `item view`. A URI is passed positionally, so it must be
// a real pass:// reference and can never be interpreted as a pass-cli flag.
function itemSelector({ vault, item, uri }) {
  if (uri) {
    if (!/^pass:\/\/\S+$/.test(uri)) throw new Error("'uri' must look like pass://SHARE_ID/ITEM_ID[/FIELD].");
    return [uri];
  }
  if (!item) throw new Error("Provide 'item' (+ optional 'vault') or 'uri'.");
  return [...(vault ? ["--vault-name", vault] : []), "--item-title", item];
}

const ok = (text) => ({ content: [{ type: "text", text }] });
const fail = (e) => ({ content: [{ type: "text", text: "Error: " + (e?.message || String(e)) }], isError: true });
const UNLOCK = "Proton Pass: unlock session";

// ---- Server ------------------------------------------------------------------
const server = new McpServer({ name: "proton-pass-touchid-mcp", version: "2.1.0" });

server.tool(
  "pass_status",
  "Proton Pass session status (signed-in agent). The first access of a session unlocks it via Touch ID.",
  {},
  async () => { try { await ensureKey(UNLOCK); return ok(await runPass(["info"])); } catch (e) { return fail(e); } }
);
server.tool(
  "pass_list_vaults",
  "Lists the vaults this agent can access (JSON). No secret values.",
  {},
  async () => { try { await ensureKey(UNLOCK); return ok(await runPass(["vault", "list", "--output", "json"])); } catch (e) { return fail(e); } }
);
server.tool(
  "pass_list_items",
  "Lists item metadata (titles/IDs) of one vault or of all accessible vaults. No secret values.",
  { vault: z.string().optional().describe("Vault name; omit for all accessible items") },
  async ({ vault }) => {
    try {
      await ensureKey(UNLOCK);
      // `item list` takes the vault as a POSITIONAL argument, not --vault-name.
      const args = ["item", "list", "--output", "json"];
      if (vault) args.push("--", vault);
      return ok(await runPass(args));
    } catch (e) { return fail(e); }
  }
);
server.tool(
  "pass_item_fields",
  "Lists ONLY the field names of an item (standard and custom fields). Values are discarded inside the MCP process and never returned. Useful to pick the 'field' for pass_get_item or to build pass:// references for pass_inject. The underlying item read is audited by Proton (reason).",
  {
    reason: z.string().min(3).describe("Required: why are the field names needed? (Proton audit log)"),
    vault: z.string().optional().describe("Vault name"),
    item: z.string().optional().describe("Item title"),
    uri: z.string().optional().describe("Alternative: pass://SHARE_ID/ITEM_ID"),
  },
  async ({ reason, vault, item, uri }) => {
    try {
      const selector = itemSelector({ vault, item, uri });
      await ensureKey(UNLOCK);
      const raw = await runPass(["item", "view", "--output", "json", ...selector], { agentReason: reason });
      const parsed = JSON.parse(raw);
      // Extract structure only — no string value from the item leaves this function.
      const found = { title: null, standard: new Set(), custom: [] };
      const STANDARD = new Set(["username", "password", "totp", "email", "note"]);
      (function walk(node, depth) {
        if (depth > 12 || node == null) return;
        if (Array.isArray(node)) { for (const n of node) walk(n, depth + 1); return; }
        if (typeof node !== "object") return;
        if (!found.title && typeof node.title === "string") found.title = node.title;
        if (Array.isArray(node.extra_fields)) {
          for (const f of node.extra_fields) {
            if (f && typeof f.name === "string") {
              const type = f.content && typeof f.content === "object" ? Object.keys(f.content)[0] : undefined;
              found.custom.push(type ? `${f.name} (${type})` : f.name);
            }
          }
        }
        for (const [k, v] of Object.entries(node)) {
          if (k === "extra_fields") continue;
          if (STANDARD.has(k) && typeof v === "string" && v.length > 0) found.standard.add(k);
          walk(v, depth + 1);
        }
      })(parsed, 0);
      return ok(JSON.stringify(
        { title: found.title, standardFields: [...found.standard], customFields: found.custom },
        null, 2
      ));
    } catch (e) { return fail(e); }
  }
);
server.tool(
  "pass_get_item",
  "Reads ONE item/field. Requires a meaningful 'reason' (audited by Proton) and a dedicated, named Touch ID tap per secret and session.",
  {
    reason: z.string().min(3).describe("Required: why is access needed? Shown in the Touch ID dialog and logged by Proton."),
    vault: z.string().optional().describe("Vault name"),
    item: z.string().optional().describe("Item title"),
    uri: z.string().optional().describe("Alternative: pass://SHARE_ID/ITEM_ID[/FIELD]"),
    field: z.string().optional().describe("Only this field, e.g. 'password' or 'totp'"),
  },
  async ({ reason, vault, item, uri, field }) => {
    try {
      const selector = itemSelector({ vault, item, uri });
      await gateSecret({ vault, item, uri, field, reason });   // named Touch ID per secret/session
      const args = ["item", "view", ...selector];
      if (field) args.push("--field", field);
      return ok(await runPass(args, { agentReason: reason }));
    } catch (e) { return fail(e); }
  }
);
server.tool(
  "pass_inject",
  "Renders a template file containing pass:// references (e.g. .env.tpl) into a file with mode 0600. Prefer always setting 'outFile': without it the rendered secrets are returned into the conversation. Can resolve SEVERAL secrets at once — one named Touch ID tap covers the whole render.",
  {
    reason: z.string().min(3).describe("Required: reason (Proton audit log + Touch ID dialog)."),
    inFile: z.string().describe("Path to the template file with pass:// references"),
    outFile: z.string().optional().describe("Target file; if omitted, the rendered content is returned"),
  },
  async ({ reason, inFile, outFile }) => {
    try {
      const src = path.resolve(inFile);
      const dst = outFile ? path.resolve(outFile) : null;
      if (dst && dst === src) throw new Error("'outFile' must differ from 'inFile'.");
      const id = `inject|${src}|${dst || "(stdout)"}`;
      const target = dst ? ` → "${dst}"` : " → returned to the AI agent";
      const label = agentLabel(`Render template "${src}"${target}`, reason);
      if (!approvedSecrets.has(id)) {
        if (!sessionKey) sessionKey = await keychainRead("encryption-key", label); else await touchIdGate(label);
        approvedSecrets.add(id);
      } else { await ensureKey(label); }
      const args = ["inject", "-i", src, "-f"];
      if (dst) args.push("-o", dst);
      const out = await runPass(args, { agentReason: reason });
      if (dst) { await chmod(dst, 0o600); return ok(`Written to ${dst} (mode 0600)`); }
      return ok(out);
    } catch (e) { return fail(e); }
  }
);
server.tool(
  "pass_audit",
  "Shows Proton's audit log for this agent (which items were read, when and why).",
  { limit: z.number().int().positive().max(500).optional().describe("Max entries (default 50)") },
  async ({ limit }) => {
    try {
      await ensureKey(UNLOCK);
      const n = String(limit || 50);
      const base = ["agent", "monitor", "--output", "json", "--limit", n];
      let out;
      if (AGENT_NAME) {
        try { out = await runPass([...base, "--", AGENT_NAME]); } catch { out = await runPass(base); }
      } else {
        out = await runPass(base);
      }
      return ok(out);
    } catch (e) { return fail(e); }
  }
);

await server.connect(new StdioServerTransport());
process.stderr.write(`proton-pass-touchid-mcp v2.1 ready · Touch ID per secret/session · session ${SESSION_DIR}\n`);
