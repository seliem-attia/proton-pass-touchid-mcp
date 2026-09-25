// Smoke test: starts the MCP server over stdio and lists item titles (never secret values).
// Usage: PASS_SMOKE_VAULT="My Vault" node smoke-test.mjs   (vault optional)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import path from "node:path";

const server = path.join(path.dirname(fileURLToPath(import.meta.url)), "index.mjs");
const vault = process.env.PASS_SMOKE_VAULT;
const t = new StdioClientTransport({ command: process.execPath, args: [server], env: process.env });
const c = new Client({ name: "smoke", version: "1.0.0" });
await c.connect(t);

console.log(`pass_list_items(${vault ? `"${vault}"` : "all"}) → titles only, no secrets:`);
const r = await c.callTool({ name: "pass_list_items", arguments: vault ? { vault } : {} });
const txt = r.content[0].text;
try {
  const j = JSON.parse(txt);
  const items = j.items || j;
  console.log("Items:", Array.isArray(items) ? items.length : "?");
  if (Array.isArray(items)) items.slice(0, 40).forEach(it => console.log("  •", it.title || it.name));
} catch { console.log(txt.slice(0, 800)); }
await c.close(); process.exit(r.isError ? 1 : 0);
