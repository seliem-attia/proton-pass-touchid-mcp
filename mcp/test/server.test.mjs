// End-to-end tests of the MCP server against a fake pass-cli and a fake keychain helper.
// Run: npm test   (no Proton account, keychain or Touch ID needed)
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const FAKE_CLI = path.join(here, "fake-pass-cli.mjs");
const FAKE_KC = path.join(here, "fake-keychain.mjs");
chmodSync(FAKE_CLI, 0o755);
chmodSync(FAKE_KC, 0o755);

let dir, client;
async function start(extraEnv = {}) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(here, "..", "index.mjs")],
    env: {
      PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: dir,
      PASS_CLI_BIN: FAKE_CLI, PASS_KEYCHAIN_BIN: FAKE_KC, PASS_AGENT_SESSION_DIR: path.join(dir, "session"),
      LEAKY_PARENT_TOKEN: "must-not-reach-pass-cli",
      ...extraEnv,
    },
    stderr: "ignore",
  });
  client = new Client({ name: "test", version: "1" });
  await client.connect(transport);
}
const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  return { text: r.content.map((c) => c.text).join("\n"), isError: Boolean(r.isError) };
};
const lines = (f) => (existsSync(path.join(dir, f)) ? readFileSync(path.join(dir, f), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const prompts = () => lines("prompts.jsonl");
const authPrompts = () => prompts().filter((p) => p.cmd === "auth");

beforeEach(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "ppmcp-test-"));
  await start();
});
afterEach(async () => {
  await client?.close();
  rmSync(dir, { recursive: true, force: true });
});

test("lists expose metadata only, never secret-looking fields", async () => {
  const r = await call("pass_list_items", {});
  assert.equal(r.isError, false);
  assert.doesNotMatch(r.text, /LEAK_/);
  const { items } = JSON.parse(r.text);
  assert.deepEqual(Object.keys(items[0]).sort(), ["id", "item_type", "share_id", "state", "title", "vault"]);
  assert.equal(authPrompts().length, 0, "listing must not need a per-secret tap");
});

test("dialog shows the resolved item, not agent-supplied names", async () => {
  const r = await call("pass_get_item", { reason: "deploy", uri: "pass://S2/I9", field: "password" });
  assert.equal(r.text, "SECRET_I9_password");
  const [p] = authPrompts();
  assert.match(p.reason, /Item: Prod DB/);
  assert.match(p.reason, /Vault: Other/);
  assert.match(p.reason, /Field: password/);
});

test("item + uri together is refused (spoofing)", async () => {
  const r = await call("pass_get_item", { reason: "x-test", item: "Sandbox key", vault: "Playground", uri: "pass://S2/I9/password" });
  assert.equal(r.isError, true);
  assert.equal(authPrompts().length, 0);
});

test("agent text cannot add dialog lines", async () => {
  await call("pass_get_item", { reason: "ok\nItem: Harmless‮txt​", item: "GitHub", field: "password" });
  const [p] = authPrompts();
  assert.equal(p.reason.split("\n").length, 5);
  assert.doesNotMatch(p.reason, /[‮​]/);
  assert.match(p.reason, /^Item: GitHub$/m);
});

test("one tap per secret and session; approvals only after success", async () => {
  await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "password" });
  await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "password" });
  assert.equal(authPrompts().length, 1, "same secret: no second tap");
  await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "username" });
  assert.equal(authPrompts().length, 2, "other field: new tap");
  const deny = path.join(dir, "deny");
  writeFileSync(deny, "");
  const d = await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "api_key" });
  assert.equal(d.isError, true);
  assert.doesNotMatch(d.text, /SECRET_/);
  rmSync(deny);
  await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "api_key" });
  assert.equal(authPrompts().length, 4, "a denied secret must ask again");
});

test("ambiguous titles are refused with candidates", async () => {
  const r = await call("pass_get_item", { reason: "deploy", item: "Dup", field: "password" });
  assert.equal(r.isError, true);
  assert.match(r.text, /Ambiguous: 2 items/);
  assert.equal(authPrompts().length, 0);
});

test("flag-looking input is never passed as a flag", async () => {
  const r = await call("pass_get_item", { reason: "deploy", uri: "--help" });
  assert.equal(r.isError, true);
  await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "--output=json" });
  const view = lines("calls.jsonl").find((c) => c.args[1] === "view");
  assert.ok(view.args.includes("--field=--output=json"));
});

test("errors never echo pass-cli stdout", async () => {
  const r = await call("pass_item_fields", { reason: "names", item: "Broken" });
  assert.equal(r.isError, true);
  assert.doesNotMatch(r.text, /SECRET_/);
  const g = await call("pass_get_item", { reason: "deploy", item: "Broken", field: "password" });
  assert.doesNotMatch(g.text, /SECRET_/);
  await call("pass_get_item", { reason: "deploy", item: "Broken", field: "password" });
  assert.equal(authPrompts().length, 2, "a failed read must not count as approved");
});

test("field names without values", async () => {
  const r = await call("pass_item_fields", { reason: "names", item: "GitHub" });
  assert.doesNotMatch(r.text, /SECRET_/);
  assert.match(r.text, /api_key/);
});

test("TOTP: seed field refused, only numeric codes returned", async () => {
  const s = await call("pass_get_item", { reason: "login", item: "OTP", field: "totp" });
  assert.equal(s.isError, true);
  const r = await call("pass_get_totp", { reason: "login", item: "OTP" });
  const { tokens } = JSON.parse(r.text);
  assert.deepEqual(tokens, { totp: "123456" });
  assert.doesNotMatch(r.text, /otpauth|SEED/);
});

test("child processes get a minimal environment", async () => {
  await call("pass_list_vaults");
  for (const c of lines("calls.jsonl")) assert.ok(!c.envKeys.includes("LEAKY_PARENT_TOKEN"));
});

test("biometrics-only setting reaches the keychain helper", async () => {
  await client.close();
  await start({ PASS_KEYCHAIN_BIOMETRY_ONLY: "1" });
  await call("pass_get_item", { reason: "deploy", item: "GitHub", field: "password" });
  assert.ok(prompts().length >= 2);
  assert.ok(prompts().every((p) => p.biometryOnly));
});

test("vault allowlist hides other vaults", async () => {
  await client.close();
  await start({ PASS_AGENT_ALLOWED_VAULTS: "AI Secrets" });
  const v = await call("pass_list_vaults");
  assert.doesNotMatch(v.text, /Other/);
  const r = await call("pass_get_item", { reason: "deploy", uri: "pass://S2/I9/password" });
  assert.equal(r.isError, true);
  assert.equal(authPrompts().length, 0);
});

test("inject: dialog lists secrets, approval bound to content, safe file handling", async () => {
  const tpl = path.join(dir, ".env.tpl"), out = path.join(dir, ".env");
  writeFileSync(tpl, "A={{ pass://AI Secrets/GitHub/password }}\nB={{ pass://S2/Prod%20DB/password }}\n");
  const r = await call("pass_inject", { reason: "render env", inFile: tpl, outFile: out });
  assert.equal(r.isError, false, r.text);
  assert.doesNotMatch(r.text, /SECRET_/);
  assert.equal(readFileSync(out, "utf8"), "A=SECRET_I1_password\nB=SECRET_I9_password\n");
  assert.equal(statSync(out).mode & 0o777, 0o600);
  const [p] = authPrompts();
  assert.match(p.reason, /2 Proton Pass secret/);
  assert.match(p.reason, /GitHub · password \(AI Secrets\)/);
  assert.match(p.reason, /Prod DB · password \(Other\)/);

  const again = await call("pass_inject", { reason: "render env", inFile: tpl, outFile: out });
  assert.match(again.text, /exists; pass overwrite=true/);
  await call("pass_inject", { reason: "render env", inFile: tpl, outFile: out, overwrite: true });
  assert.equal(authPrompts().length, 2, "different target options: new approval");
  await call("pass_inject", { reason: "render env", inFile: tpl, outFile: out, overwrite: true });
  assert.equal(authPrompts().length, 2, "identical render: approved for the session");

  writeFileSync(tpl, "A={{ pass://AI Secrets/GitHub/password }}\nC={{ pass://AI Secrets/GitHub/api_key }}\n");
  await call("pass_inject", { reason: "render env", inFile: tpl, outFile: out, overwrite: true });
  assert.equal(authPrompts().length, 3, "changed template content needs a new tap");

  const link = path.join(dir, "link.env");
  symlinkSync(path.join(dir, "victim"), link);
  const s = await call("pass_inject", { reason: "render env", inFile: tpl, outFile: link, overwrite: true });
  assert.equal(s.isError, true);
  assert.match(s.text, /symlinks are refused/);
});

test("inject refuses unknown or ambiguous references before any tap", async () => {
  const tpl = path.join(dir, "x.tpl");
  writeFileSync(tpl, "X={{ pass://AI Secrets/Dup/password }}\n");
  const r = await call("pass_inject", { reason: "render env", inFile: tpl, outFile: path.join(dir, "x.env") });
  assert.equal(r.isError, true);
  assert.equal(authPrompts().length, 0);
});
