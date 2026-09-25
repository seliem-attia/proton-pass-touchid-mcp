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
//     first read. The target is resolved from metadata FIRST, so the dialog shows the
//     item title and vault that will really be read, not names typed by the agent.
//   • Templates: the dialog lists every secret the template references; the approval
//     is bound to the exact (canonicalized) template content and target file.
//   • The key lives in RAM only (never on disk) and is gone when the process exits.
//
// All tool arguments are treated as attacker-controlled (prompt injection).

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, link, lstat, mkdtemp, readFile, realpath, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import os from "node:os";
import path from "node:path";

process.umask(0o077); // every file this process (or pass-cli) creates is private by default

const HOME = process.env.PASS_AGENT_HOME
  || path.dirname(path.dirname(fileURLToPath(import.meta.url))); // install dir (parent of mcp/)
const SESSION_DIR = process.env.PASS_AGENT_SESSION_DIR || path.join(HOME, "session");
const KC_BIN = process.env.PASS_KEYCHAIN_BIN || path.join(HOME, "pass-keychain");
const PASS_CLI = process.env.PASS_CLI_BIN
  || ["/opt/homebrew/bin/pass-cli", "/usr/local/bin/pass-cli", path.join(os.homedir(), ".local/bin/pass-cli")].find(existsSync)
  || "pass-cli";
const KC_SERVICE = process.env.PASS_AGENT_KEYCHAIN_SERVICE || "proton-pass-agent";
const AGENT_NAME = process.env.PASS_AGENT_NAME || "";
// Optional second layer on top of the agent token's vault scope: comma-separated vault names or share IDs.
const ALLOWED_VAULTS = (process.env.PASS_AGENT_ALLOWED_VAULTS || "").split(",").map((s) => s.trim()).filter(Boolean);

const CLI_TIMEOUT_MS = 60_000;          // pass-cli call
const AUTH_TIMEOUT_MS = 120_000;        // user has this long to answer a Touch ID dialog
const MAX_TEMPLATE_BYTES = 256 * 1024;
const MAX_TEMPLATE_SECRETS = 10;       // all of them must fit into the Touch ID dialog

const exec = (file, args, opts = {}) =>
  new Promise((resolve) => {
    execFile(file, args, { maxBuffer: 8 * 1024 * 1024, killSignal: "SIGKILL", env: baseEnvNoKey(), ...opts }, (err, stdout, stderr) =>
      resolve({
        code: err ? (typeof err.code === "number" ? err.code : 1) : 0,
        timedOut: Boolean(err?.killed),
        stdout: stdout?.toString() ?? "",
        stderr: stderr?.toString() ?? "",
      })
    );
  });

const baseEnvNoKey = () => {
  const env = {};
  for (const k of ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "PASS_KEYCHAIN_BIOMETRY_ONLY"]) if (process.env[k] !== undefined) env[k] = process.env[k];
  return env;
};

// ---- Display hygiene ------------------------------------------------------------
// Strip control, format (bidi, zero-width) and line-separator characters and cap the
// length, so agent-supplied text can neither fake extra dialog lines nor push the real
// item name out of view.
const clean = (s, n = 80) => {
  const t = String(s ?? "").replace(/[\p{C}\u2028\u2029]/gu, " ").replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
};
const stripAnsi = (s) => s.replace(/\u001b\[[0-9;]*[A-Za-z]/g, "");
// Error text for the agent: never stdout (may carry secret values), and stderr only when
// it matches a known, value-free message class. Everything else becomes a generic error.
const SAFE_ERROR = /(not found|does not exist|no such|ambiguous|authenticat|session|logged out|not allowed|permission|forbidden|access denied|invalid (secret )?reference|invalid (item|share|vault)|not a totp field|no totp fields|network|connection|timed out|rate limit)/i;
const cliError = (r) => {
  if (r.timedOut) return "pass-cli timed out";
  const msg = stripAnsi(r.stderr).split("\n").map((l) => l.trim()).filter(Boolean).pop() || "";
  return SAFE_ERROR.test(msg) ? clean(msg, 300) : `pass-cli failed (exit ${r.code})`;
};

// ---- Session state (process lifetime) ---------------------------------------
let sessionKey = null;                 // env-provider key, RAM only
const approvedSecrets = new Set();     // canonical approval keys, added only after a successful read

async function keychainRead(account, reason) {
  const r = await exec(KC_BIN, ["read", KC_SERVICE, account, reason], { timeout: AUTH_TIMEOUT_MS });
  if (r.code !== 0) throw new Error(`Keychain/Touch ID failed (${account}): ${r.timedOut ? "timed out" : clean(r.stderr) || "cancelled"}`);
  return r.stdout; // raw secret, no trimming
}
async function touchIdGate(reason) {
  const r = await exec(KC_BIN, ["auth", reason], { timeout: AUTH_TIMEOUT_MS });
  if (r.code !== 0) throw new Error(r.timedOut ? "Touch ID timed out" : "Touch ID denied or cancelled");
}

const UNLOCK = "Proton Pass: unlock agent session (metadata only, no secret values)";
async function ensureKey(label = UNLOCK) {
  if (!sessionKey) sessionKey = await keychainRead("encryption-key", label);
  return sessionKey;
}
// Tool calls run strictly one after another: parallel calls could otherwise stack Touch ID
// dialogs or race two re-logins.
let queue = Promise.resolve();
const exclusive = (fn) => { const p = queue.then(fn, fn); queue = p.catch(() => {}); return p; };

// Child processes get a minimal environment: nothing inherited from the MCP client
// (tokens, PROTON_PASS_* overrides) can leak into or redirect pass-cli.
function baseEnv(extra = {}) {
  return {
    ...baseEnvNoKey(),
    NO_COLOR: "1",
    PROTON_PASS_NO_UPDATE_CHECK: "1",    // no network update check on every call
    PROTON_PASS_DISABLE_TELEMETRY: "1",
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
      s.includes("session has been invalidated") ||
      s.includes("unauthorized"))
  );
}
async function relogin() {
  const pat = (await keychainRead("pat", "Proton Pass: sign the agent in again (agent token)")).trim();
  await exec(PASS_CLI, ["logout", "--force"], { env: baseEnv(), timeout: CLI_TIMEOUT_MS });
  const r = await exec(PASS_CLI, ["login"], { env: baseEnv({ PROTON_PASS_PERSONAL_ACCESS_TOKEN: pat }), timeout: CLI_TIMEOUT_MS });
  if (r.code !== 0) throw new Error("Re-login failed: " + cliError(r));
}
// Run a pass-cli command (key must already be loaded). Auto-recover once from an expired session.
async function runPass(args, { agentReason } = {}) {
  const extra = agentReason ? { PROTON_PASS_AGENT_REASON: agentReason } : {};
  const run = () => exec(PASS_CLI, args, { env: baseEnv(extra), timeout: CLI_TIMEOUT_MS });
  let r = await run();
  if (looksLikeAuthError(r)) { await relogin(); r = await run(); }
  if (r.code !== 0) throw new Error(cliError(r));
  return r.stdout.trim();
}
function parseJson(raw) {
  try { return JSON.parse(raw); } catch { throw new Error("Unexpected pass-cli output (not JSON)"); }
}

// ---- Metadata (never contains secret values) -----------------------------------
// Listings are cached for the duration of ONE tool call (reset in tool()).
let listCache = new Map();
const cached = async (key, fn) => { if (!listCache.has(key)) listCache.set(key, await fn()); return listCache.get(key); };
// Output is projected onto an explicit whitelist, independent of what pass-cli prints.
async function listVaults() {
  const j = parseJson(await cached("vaults", () => runPass(["vault", "list", "--output", "json"])));
  const vaults = (Array.isArray(j) ? j : j.vaults || []).map((v) => ({
    name: String(v.name ?? ""), share_id: String(v.share_id ?? ""), vault_id: String(v.vault_id ?? ""),
  }));
  return ALLOWED_VAULTS.length ? vaults.filter((v) => ALLOWED_VAULTS.includes(v.name) || ALLOWED_VAULTS.includes(v.share_id)) : vaults;
}
async function listItems(shareId) {
  const j = parseJson(await cached(`items:${shareId}`, () => runPass(["item", "list", `--share-id=${shareId}`, "--output", "json"])));
  return (Array.isArray(j) ? j : j.items || []).map((i) => ({
    id: String(i.id ?? ""), share_id: String(i.share_id ?? shareId), title: String(i.title ?? ""),
    item_type: String(i.item_type ?? ""), state: String(i.state ?? ""),
  }));
}
const isTrashed = (i) => /trash|^2$/i.test(i.state);

// Resolve a (vault selector, item selector) pair to exactly one real item.
// vaultSel: vault name or share ID (null = all accessible vaults); itemSel: title or item ID.
async function resolveItem(vaultSel, itemSel) {
  const vaults = await listVaults();
  const candidates = vaultSel == null ? vaults : vaults.filter((v) => v.share_id === vaultSel || v.name === vaultSel);
  if (!candidates.length) throw new Error(`Vault not found or not accessible to this agent: "${clean(vaultSel, 60)}"`);
  let matches = [];
  for (const v of candidates) {
    for (const it of await listItems(v.share_id)) {
      if (it.id === itemSel || it.title === itemSel) matches.push({ ...it, vault: v.name });
    }
  }
  if (matches.some((m) => !isTrashed(m))) matches = matches.filter((m) => !isTrashed(m));
  if (!matches.length) throw new Error(`Item not found: "${clean(itemSel, 60)}"${vaultSel == null ? "" : ` in vault "${clean(vaultSel, 60)}"`}`);
  if (matches.length > 1) {
    const list = matches.slice(0, 10).map((m) => `"${m.title}" (vault "${m.vault}", uri pass://${m.share_id}/${m.id})`).join("; ");
    throw new Error(`Ambiguous: ${matches.length} items match. Use 'vault' or a 'uri' with IDs: ${list}`);
  }
  return matches[0];
}

// pass://<vault name|share id>/<item title|item id>[/<field>][?query], segments URL-encoded.
function parseRef(uri) {
  const s = String(uri).trim();
  if (!s.startsWith("pass://")) throw new Error("A reference must start with pass://");
  const body = s.slice("pass://".length);
  // Queries such as ?totp=uri would make pass-cli return the TOTP seed: not supported.
  if (body.includes("?")) throw new Error("Query parameters in pass:// references are not supported");
  let segs;
  try { segs = body.split("/").map((p) => decodeURIComponent(p)); } catch { throw new Error("Malformed URL-encoding in pass:// reference"); }
  const [vault, item, ...rest] = segs;
  if (!vault || !item) throw new Error("Expected pass://VAULT/ITEM[/FIELD]");
  const field = rest.filter(Boolean).join("/") || null;
  return { vault, item, field };
}
const encodeField = (f) => f.split("/").map(encodeURIComponent).join("/");

// Resolve tool arguments to a single target (item + field).
async function resolveTarget({ vault, item, uri, field }) {
  if (uri && (item || vault)) throw new Error("Use either 'uri' or 'item' (+ optional 'vault'), not both.");
  if (!uri && !item) throw new Error("Provide 'item' (+ optional 'vault') or 'uri'.");
  let vaultSel = vault ?? null, itemSel = item, uriField = null;
  if (uri) ({ vault: vaultSel, item: itemSel, field: uriField } = parseRef(uri));
  if (uriField && field && uriField !== field) throw new Error("Field given twice ('uri' and 'field') with different values.");
  const target = await resolveItem(vaultSel, itemSel);
  return { ...target, field: field ?? uriField ?? null };
}

// One named Touch ID per resolved secret and session. Returns the approval key; the caller
// commits it only after the read succeeded.
async function gateSecret(t, reason) {
  const id = JSON.stringify(["item", t.share_id, t.id, t.field]);
  if (approvedSecrets.has(id)) return id;
  const label = [
    "AI agent requests a Proton Pass secret",
    `Item: ${clean(t.title, 60)}`,
    `Vault: ${clean(t.vault, 40)}`,
    `Field: ${t.field ? clean(t.field, 40) : "ALL FIELDS (whole item)"}`,
    `Agent's reason: ${clean(reason, 120)}`,
  ].join("\n");
  await touchIdGate(label);
  return id;
}

const ok = (text) => ({ content: [{ type: "text", text }] });
const fail = (e) => ({ content: [{ type: "text", text: "Error: " + (e?.message || String(e)) }], isError: true });

const zReason = z.string().min(3).max(300);
const zName = z.string().min(1).max(200);

// ---- Server ------------------------------------------------------------------
const server = new McpServer(
  { name: "proton-pass-touchid-mcp", version: "2.2.1" },
  {
    instructions:
      "Proton Pass secrets behind a human Touch ID approval. Each secret read shows the user a dialog with the item, " +
      "vault and your reason; write an honest, specific reason. Request single fields instead of whole items. " +
      "Prefer pass_inject with outFile when a secret only has to end up in a file, so it never enters the conversation. " +
      "Never repeat secret values back to the user unless they explicitly ask.",
  }
);

// Hints for MCP clients (they guide, they do not enforce anything).
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const ANNOTATIONS = {
  pass_status: { title: "Proton Pass status", ...READ_ONLY },
  pass_list_vaults: { title: "List vaults", ...READ_ONLY },
  pass_list_items: { title: "List items (metadata)", ...READ_ONLY },
  pass_item_fields: { title: "List field names of an item", ...READ_ONLY },
  pass_get_item: { title: "Read a secret (Touch ID)", ...READ_ONLY },
  pass_get_totp: { title: "Get a TOTP code (Touch ID)", ...READ_ONLY, idempotentHint: false },
  pass_inject: { title: "Render a template with secrets (Touch ID)", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  pass_audit: { title: "Proton audit log", ...READ_ONLY },
};
function tool(name, description, inputSchema, handler) {
  server.registerTool(
    name,
    { title: ANNOTATIONS[name].title, description, inputSchema, annotations: ANNOTATIONS[name] },
    (args) => exclusive(async () => {
      listCache = new Map();
      try { return await handler(args ?? {}); } catch (e) { return fail(e); } finally { listCache = new Map(); }
    })
  );
}

tool(
  "pass_status",
  "Proton Pass session status (signed-in agent). The first access of a session unlocks it via Touch ID.",
  {},
  async () => {
    await ensureKey();
    const version = (await exec(PASS_CLI, ["--version"], { timeout: CLI_TIMEOUT_MS })).stdout.trim() || "unknown";
    const info = await runPass(["info"]);
    return ok(`${info}\n\npass-cli: ${version}\nMCP server: proton-pass-touchid-mcp 2.2.1` +
      (ALLOWED_VAULTS.length ? `\nVault allowlist: ${ALLOWED_VAULTS.join(", ")}` : ""));
  }
);
tool(
  "pass_list_vaults",
  "Lists the vaults this agent can access (name, share_id, vault_id). No secret values.",
  {},
  async () => { try { await ensureKey(); return ok(JSON.stringify({ vaults: await listVaults() }, null, 2)); } catch (e) { return fail(e); } }
);
tool(
  "pass_list_items",
  "Lists item metadata (title, id, share_id, vault, item_type, state) of one vault or of all accessible vaults. No secret values.",
  { vault: zName.optional().describe("Vault name or share ID; omit for all accessible vaults") },
  async ({ vault }) => {
    try {
      await ensureKey();
      const vaults = await listVaults();
      const selected = vault == null ? vaults : vaults.filter((v) => v.name === vault || v.share_id === vault);
      if (!selected.length) throw new Error(`Vault not found or not accessible to this agent: "${clean(vault, 60)}"`);
      const items = [];
      for (const v of selected) for (const it of await listItems(v.share_id)) items.push({ ...it, vault: v.name });
      return ok(JSON.stringify({ items }, null, 2));
    } catch (e) { return fail(e); }
  }
);
tool(
  "pass_item_fields",
  "Lists ONLY the field names of an item (standard and custom fields). Values are discarded inside the MCP process and never returned. Useful to pick the 'field' for pass_get_item or to build pass:// references for pass_inject. The underlying item read is audited by Proton (reason).",
  {
    reason: zReason.describe("Required: why are the field names needed? (Proton audit log)"),
    vault: zName.optional().describe("Vault name or share ID"),
    item: zName.optional().describe("Item title or item ID"),
    uri: z.string().max(1000).optional().describe("Alternative: pass://VAULT/ITEM (names or IDs)"),
  },
  async ({ reason, vault, item, uri }) => {
    try {
      await ensureKey();
      const t = await resolveTarget({ vault, item, uri });
      let parsed;
      try {
        parsed = parseJson(await runPass(["item", "view", `--share-id=${t.share_id}`, `--item-id=${t.id}`, "--output", "json"], { agentReason: reason }));
      } catch {
        throw new Error("Could not read the item structure"); // never echo pass-cli output here
      }
      // Extract structure only — no string value from the item leaves this function.
      const found = { standard: new Set(), custom: [] };
      // Field names pass-cli understands (pass-domain field.rs); "title" is metadata, not a field.
      const STANDARD = new Set(["address", "birthdate", "card_type", "cardholder_name", "city", "company", "country",
        "country_or_region", "cvv", "email", "expiration_date", "first_name", "full_name", "gender", "job_title",
        "last_name", "license_number", "middle_name", "note", "number", "organization", "passport_number", "password",
        "phone_number", "pin", "postal_code", "region", "social_security_number", "ssid", "state_or_province",
        "totp_uri", "urls", "username", "verification_number", "website", "zip_or_postal_code"]);
      const nonEmpty = (v) => (typeof v === "string" && v.length > 0) || (Array.isArray(v) && v.length > 0);
      (function walk(node, depth) {
        if (depth > 12 || node == null) return;
        if (Array.isArray(node)) { for (const n of node) walk(n, depth + 1); return; }
        if (typeof node !== "object") return;
        const typeOf = (f) => (f.content && typeof f.content === "object" ? Object.keys(f.content)[0] : undefined);
        if (Array.isArray(node.extra_fields)) {
          for (const f of node.extra_fields) {
            if (f && typeof f.name === "string") found.custom.push(typeOf(f) ? `${f.name} (${typeOf(f)})` : f.name);
          }
        }
        if (typeof node.section_name === "string" && Array.isArray(node.section_fields)) {
          for (const f of node.section_fields) {
            if (f && typeof f.name === "string") {
              const n = `${node.section_name}.${f.name}`;
              found.custom.push(typeOf(f) ? `${n} (${typeOf(f)})` : n);
            }
          }
        }
        for (const [k, v] of Object.entries(node)) {
          if (k === "extra_fields" || k === "section_fields") continue;
          if (STANDARD.has(k) && nonEmpty(v)) found.standard.add(k === "totp_uri" ? "totp (codes via pass_get_totp)" : k);
          walk(v, depth + 1);
        }
      })(parsed, 0);
      return ok(JSON.stringify({
        title: t.title, vault: t.vault, uri: `pass://${t.share_id}/${t.id}`,
        standardFields: [...found.standard], customFields: found.custom,
      }, null, 2));
    } catch (e) { return fail(e); }
  }
);
tool(
  "pass_get_item",
  "Reads ONE item or field and returns its value into the conversation. Requires a meaningful 'reason' (audited by Proton) and a dedicated Touch ID tap per secret and session; the dialog shows the resolved item and vault. Prefer pass_inject with outFile when the secret only needs to end up in a file.",
  {
    reason: zReason.describe("Required: why is access needed? Shown in the Touch ID dialog and logged by Proton."),
    vault: zName.optional().describe("Vault name or share ID"),
    item: zName.optional().describe("Item title or item ID"),
    uri: z.string().max(1000).optional().describe("Alternative: pass://VAULT/ITEM[/FIELD] (names or IDs)"),
    field: z.string().min(1).max(200).optional().describe("The field to read, e.g. 'password' or 'api_key' (required unless the uri ends with /FIELD). Use pass_item_fields to see names."),
  },
  async ({ reason, vault, item, uri, field }) => {
    try {
      await ensureKey();
      const t = await resolveTarget({ vault, item, uri, field });
      // Whole-item reads would also print TOTP seeds and every other field: not offered.
      if (!t.field) throw new Error("Specify a single 'field' (see pass_item_fields for the names).");
      if (/(^|\.)totp(_uri)?$/i.test(t.field)) throw new Error("TOTP fields are only available as codes via pass_get_totp (the seed is never returned).");
      const approval = await gateSecret(t, reason);
      const args = ["item", "view", `--share-id=${t.share_id}`, `--item-id=${t.id}`];
      args.push(`--field=${t.field}`);
      const out = await runPass(args, { agentReason: reason });
      approvedSecrets.add(approval);
      return ok(out);
    } catch (e) { return fail(e); }
  }
);
tool(
  "pass_get_totp",
  "Returns the CURRENT one-time code(s) of an item's TOTP field(s) — never the TOTP seed. Requires a reason and a Touch ID tap per item and session.",
  {
    reason: zReason.describe("Required: why is the code needed? Shown in the Touch ID dialog and logged by Proton."),
    vault: zName.optional().describe("Vault name or share ID"),
    item: zName.optional().describe("Item title or item ID"),
    uri: z.string().max(1000).optional().describe("Alternative: pass://VAULT/ITEM (names or IDs)"),
    field: z.string().min(1).max(200).optional().describe("Specific TOTP field; omit for all TOTP fields of the item"),
  },
  async ({ reason, vault, item, uri, field }) => {
    await ensureKey();
    const t = await resolveTarget({ vault, item, uri, field });
    const approval = await gateSecret({ ...t, field: t.field ? `${t.field} (TOTP code)` : "TOTP code(s)" }, reason);
    const args = ["item", "totp", `--share-id=${t.share_id}`, `--item-id=${t.id}`, "--output", "json"];
    if (t.field) args.push(`--field=${t.field}`);
    const j = parseJson(await runPass(args, { agentReason: reason }));
    const tokens = {};
    // pass-cli flattens the map ({"totp":"123456",…}); older builds may wrap it in "tokens".
    const src = j && typeof j.tokens === "object" ? j.tokens : j ?? {};
    for (const [k, v] of Object.entries(src)) if (/^\d{6,10}$/.test(String(v))) tokens[k] = String(v);
    if (!Object.keys(tokens).length) throw new Error("No TOTP code returned");
    approvedSecrets.add(approval);
    return ok(JSON.stringify({ item: t.title, vault: t.vault, tokens }, null, 2));
  }
);

tool(
  "pass_inject",
  "Renders a template containing {{ pass://VAULT/ITEM/FIELD }} references (e.g. .env.tpl) into 'outFile' (mode 0600, written atomically; symlinks refused). One Touch ID tap per render; the dialog lists every referenced secret and the target. Without 'outFile' the rendered secrets are returned into the conversation. Existing files are only replaced with overwrite=true.",
  {
    reason: zReason.describe("Required: reason (Proton audit log + Touch ID dialog)."),
    inFile: z.string().min(1).max(1024).describe("Path to the template file"),
    outFile: z.string().min(1).max(1024).optional().describe("Target file (recommended); if omitted, the rendered content is returned"),
    overwrite: z.boolean().optional().describe("Allow replacing an existing regular file at outFile"),
  },
  async ({ reason, inFile, outFile, overwrite }) => {
    let tmpDir = null, tmpOut = null;
    try {
      const src = await realpath(path.resolve(inFile)).catch(() => { throw new Error("'inFile' not found"); });
      const st = await stat(src);
      if (!st.isFile()) throw new Error("'inFile' is not a regular file");
      if (st.size > MAX_TEMPLATE_BYTES) throw new Error(`Template larger than ${MAX_TEMPLATE_BYTES} bytes`);
      const content = await readFile(src, "utf8");

      // Target: parent directory resolved (so the dialog shows the real location); the file
      // itself must be absent (or a regular file with overwrite=true) — never a symlink.
      let dst = null;
      if (outFile) {
        const abs = path.resolve(outFile);
        const parent = await realpath(path.dirname(abs)).catch(() => null);
        if (!parent || !(await stat(parent)).isDirectory()) throw new Error("Target directory does not exist");
        dst = path.join(parent, path.basename(abs));
        if (dst === src) throw new Error("'outFile' must differ from 'inFile'.");
        const existing = await lstat(dst).catch(() => null);
        if (existing && !existing.isFile()) throw new Error("'outFile' exists and is not a regular file (symlinks are refused)");
        if (existing && !overwrite) throw new Error("'outFile' exists; pass overwrite=true to replace it");
      }

      // pass-cli's pattern is \{\{\s*(pass://[^}]+)\s*\}\} with Rust's Unicode \s, which also
      // covers U+0085 (NEL) — JavaScript's \s does not. Every reference is resolved and rewritten
      // to canonical share/item IDs, so pass-cli renders exactly the secrets shown in the dialog.
      const REF = /\{\{[\s\u0085]*(pass:\/\/[^}]+)[\s\u0085]*\}\}/g;
      const trimRef = (u) => u.replace(/^[\s\u0085]+|[\s\u0085]+$/g, "");
      const uris = [...new Set([...content.matchAll(REF)].map((m) => trimRef(m[1])))];
      if (!uris.length) throw new Error("The template contains no {{ pass://… }} references");
      await ensureKey();
      const canon = new Map(), secrets = new Map();
      for (const u of uris) {
        const r = parseRef(u);
        if (!r.field) throw new Error(`Reference without field: ${clean(u, 80)}`);
        if (/(^|\.)totp(_uri)?$/i.test(r.field)) throw new Error("TOTP fields cannot be rendered into templates (use pass_get_totp).");
        const t = await resolveItem(r.vault, r.item);
        canon.set(u, `pass://${encodeURIComponent(t.share_id)}/${encodeURIComponent(t.id)}/${encodeField(r.field)}`);
        secrets.set(`${t.share_id}/${t.id}/${r.field.toLowerCase()}`, `${clean(t.title, 40)} · ${clean(r.field, 30)} (${clean(t.vault, 30)})`);
      }
      if (secrets.size > MAX_TEMPLATE_SECRETS) throw new Error(`Too many secrets in one template (max ${MAX_TEMPLATE_SECRETS}); split it up.`);
      const rewritten = content.replace(REF, (_m, u) => `{{ ${canon.get(trimRef(u))} }}`);
      // Anything left that pass-cli might still treat as a reference means our view differs from
      // pass-cli's (unusual whitespace, odd nesting): refuse instead of rendering unseen secrets.
      if (/\{\{[^}]*pass:\/\//i.test(rewritten.replace(REF, ""))) {
        throw new Error("The template contains a pass:// reference in an unsupported form; write it as {{ pass://VAULT/ITEM/FIELD }}.");
      }

      const digest = createHash("sha256").update(rewritten).digest("hex");
      const approval = JSON.stringify(["inject", digest, dst, Boolean(overwrite)]);
      if (!approvedSecrets.has(approval)) {
        await touchIdGate([
          `AI agent requests ${secrets.size} Proton Pass secret(s) via template`,
          `Template: ${clean(src, 90)}`,
          `Target: ${dst ? clean(dst, 90) + (overwrite ? " (replaces existing file)" : "") : "RETURNED INTO THE AI CONVERSATION"}`,
          `Secrets:\n  ${[...secrets.values()].join("\n  ")}`,
          `Agent's reason: ${clean(reason, 120)}`,
        ].join("\n"));
      }

      // Render from a private copy, so the template cannot be swapped after approval.
      tmpDir = await mkdtemp(path.join(os.tmpdir(), "ppmcp-"));
      const tpl = path.join(tmpDir, "template.tpl");
      await writeFile(tpl, rewritten, { mode: 0o600 });
      if (!dst) {
        const out = await runPass(["inject", "-i", tpl], { agentReason: reason });
        approvedSecrets.add(approval);
        return ok(out);
      }
      tmpOut = path.join(path.dirname(dst), `.${path.basename(dst)}.${randomBytes(6).toString("hex")}.tmp`);
      await runPass(["inject", "-i", tpl, "-o", tmpOut, "--file-mode", "0600"], { agentReason: reason });
      await chmod(tmpOut, 0o600);
      if (overwrite) {
        await rename(tmpOut, dst); // atomic; replaces the path itself, never follows a symlink
      } else {
        await link(tmpOut, dst);   // fails with EEXIST if something appeared meanwhile
        await unlink(tmpOut);
      }
      tmpOut = null;
      approvedSecrets.add(approval);
      return ok(`Written ${secrets.size} secret reference(s) to ${dst} (mode 0600)`);
    } catch (e) {
      return fail(e);
    } finally {
      if (tmpOut) await rm(tmpOut, { force: true }).catch(() => {});
      if (tmpDir) await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  }
);
tool(
  "pass_audit",
  "Shows Proton's audit log for this agent (which items were read, when and why).",
  { limit: z.number().int().positive().max(500).optional().describe("Max entries (default 50)") },
  async ({ limit }) => {
    try {
      await ensureKey();
      const base = ["agent", "monitor", "--output", "json", `--limit=${limit || 50}`];
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
process.stderr.write(`proton-pass-touchid-mcp v2.2 ready · Touch ID per secret/session · session ${SESSION_DIR}\n`);
