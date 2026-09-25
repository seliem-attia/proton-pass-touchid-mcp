#!/usr/bin/env node
// Fake pass-cli for tests. Logs every call to $TMPDIR/calls.jsonl.
// Item values are "SECRET_<item>_<field>" so tests can assert where secrets end up.
import { appendFileSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

const dir = process.env.TMPDIR;
const args = process.argv.slice(2);
appendFileSync(path.join(dir, "calls.jsonl"), JSON.stringify({ args, envKeys: Object.keys(process.env).sort() }) + "\n");

const VAULTS = [
  { name: "AI Secrets", share_id: "S1", vault_id: "V1" },
  { name: "Other", share_id: "S2", vault_id: "V2" },
];
const ITEMS = {
  S1: [
    { id: "I1", title: "GitHub" },
    { id: "I2", title: "Dup" },
    { id: "I3", title: "Dup" },
    { id: "I4", title: "Broken" },
    { id: "I5", title: "OTP" },
    { id: "I6", title: "Sections" },
  ],
  S2: [{ id: "I9", title: "Prod DB" }],
};
const opt = (name) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  if (hit) return hit.slice(name.length + 3);
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const out = (s) => process.stdout.write(s + "\n");
const find = (share, id) => (ITEMS[share] || []).find((i) => i.id === id);

// Simulate a server-side session loss once, if the test asked for it.
const invalidate = path.join(dir, "invalidate-once");
if (existsSync(invalidate) && args[0] !== "login" && args[0] !== "logout") {
  rmSync(invalidate);
  console.error("Your session has been invalidated and you have been logged out automatically.");
  process.exit(1);
}
if (process.env.PROTON_PASS_ENCRYPTION_KEY !== "testkey") { console.error("Error: wrong key"); process.exit(1); }

const [cmd, sub] = args;
if (cmd === "--version") out("Proton Pass CLI 9.9.9 (fake)");
else if (cmd === "info") out("Agent: Test Agent");
else if (cmd === "vault" && sub === "list") out(JSON.stringify({ vaults: VAULTS }));
else if (cmd === "item" && sub === "list") {
  const share = opt("share-id");
  // Deliberately includes a secret-looking field: the MCP must drop it.
  out(JSON.stringify({ items: (ITEMS[share] || []).map((i) => ({ ...i, share_id: share, vault_id: "V", state: "Active", item_type: "login", password: `LEAK_${i.id}` })) }));
} else if (cmd === "item" && sub === "view") {
  const it = find(opt("share-id"), opt("item-id"));
  if (!it) { console.error("Error: item not found"); process.exit(1); }
  if (it.id === "I4") { out(`SECRET_${it.id}_password`); console.error("Error: boom"); process.exit(1); }
  const field = opt("field");
  if (field) out(`SECRET_${it.id}_${field}`);
  else if (opt("output") === "json" && it.id === "I6") out(JSON.stringify({ item: { title: it.title, content: { content: { Custom: { sections: [{ section_name: "Prod", section_fields: [{ name: "token", content: { Hidden: "SECRET_I6_Prod.token" } }] }] } }, extra_fields: [] } } }));
  else if (opt("output") === "json") out(JSON.stringify({ item: { title: it.title, content: { content: { Login: { username: `SECRET_${it.id}_username`, password: `SECRET_${it.id}_password`, totp_uri: "otpauth://totp/x?secret=SEED" } }, extra_fields: [{ name: "api_key", content: { Hidden: `SECRET_${it.id}_api_key` } }] } } }));
  else out(`- Title: ${it.title}\npassword: SECRET_${it.id}_password`);
} else if (cmd === "item" && sub === "totp") {
  out(JSON.stringify({ totp: "123456", totp_uri: "123456", weird: "otpauth://totp/x?secret=SEED" }));
} else if (cmd === "inject") {
  const tpl = readFileSync(opt("in-file") ?? args[args.indexOf("-i") + 1], "utf8");
  // Mirrors Rust regex semantics: \s is Unicode White_Space and includes U+0085.
  const rendered = tpl.replace(/\{\{[\s\u0085]*(pass:\/\/[^}]+)[\s\u0085]*\}\}/g, (_m, u) => {
    const [share, item, field] = u.replace(/^[\s\u0085]+|[\s\u0085]+$/g, "").slice(7).split("/").map(decodeURIComponent);
    const v = VAULTS.find((x) => x.share_id === share || x.name === share);
    const it = v && (ITEMS[v.share_id] || []).find((i) => i.id === item || i.title === item);
    if (!it) { console.error(`Error: Invalid secret reference: ${u}`); process.exit(1); }
    return `SECRET_${it.id}_${field}`;
  });
  const o = args.indexOf("-o");
  if (o >= 0) writeFileSync(args[o + 1], rendered, { mode: 0o644 }); else process.stdout.write(rendered);
} else if (cmd === "login" || cmd === "logout") out("ok");
else if (cmd === "agent" && sub === "monitor") out(JSON.stringify({ entries: [] }));
else { console.error(`Error: unsupported fake command ${args.join(" ")}`); process.exit(2); }
