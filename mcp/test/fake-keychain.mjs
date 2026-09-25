#!/usr/bin/env node
// Fake pass-keychain for tests: records every Touch ID dialog text to $TMPDIR/prompts.jsonl.
// Touch ID is "denied" while the file $TMPDIR/deny exists.
import { appendFileSync, existsSync } from "node:fs";
import path from "node:path";

const dir = process.env.TMPDIR;
const [cmd, ...rest] = process.argv.slice(2);
const reason = cmd === "auth" ? rest[0] : rest[2];
appendFileSync(path.join(dir, "prompts.jsonl"), JSON.stringify({ cmd, account: cmd === "read" ? rest[1] : null, reason, biometryOnly: process.env.PASS_KEYCHAIN_BIOMETRY_ONLY === "1" }) + "\n");
if (existsSync(path.join(dir, "deny"))) { console.error("Touch ID denied or cancelled"); process.exit(1); }
if (cmd === "auth") process.exit(0);
if (cmd === "read") process.stdout.write(rest[1] === "pat" ? "pst_fake::token" : "testkey");
else process.exit(64);
