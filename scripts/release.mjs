#!/usr/bin/env node
/**
 * One command to release nel-veil-mcp.
 *
 * The reason this exists: publishing needs a human twice, and only twice —
 * npm's 2FA and the MCP registry's GitHub device-code login. Everything AROUND
 * those two moments is mechanical, and doing it by hand is where every failed
 * release so far came from:
 *
 *   - `mcp-publisher publish` reads ./server.json from the CURRENT directory,
 *     so running it from the home dir fails with "server.json not found". This
 *     script chdirs to the package root itself, so that cannot happen.
 *   - The registry refuses to register a version npm does not serve yet, so a
 *     back-to-back publish fails with "version X was not found". This script
 *     polls npm until the version is live before it touches the registry.
 *   - The registry JWT expires in minutes, so login and publish must be
 *     adjacent. This script runs them adjacently.
 *   - A stale npm token reports E404 on PUT, which reads as "package missing"
 *     rather than "you are logged out". This script checks `npm whoami` FIRST
 *     and says plainly what is wrong.
 *
 * Usage, from anywhere:
 *   node scripts/release.mjs            publish the version in package.json
 *   node scripts/release.mjs --dry-run  run every check, publish nothing
 */

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(ROOT);

const DRY = process.argv.includes("--dry-run");
const PUBLISHER = process.env.MCP_PUBLISHER || "C:\\Users\\apoll\\mcp-publisher.exe";

const step = (n, msg) => console.log(`\n[${n}] ${msg}`);
const die = (msg) => { console.error(`\nFAILED: ${msg}`); process.exit(1); };
const run = (cmd, opts = {}) => execSync(cmd, { stdio: "inherit", ...opts });
const capture = (cmd) => execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const server = JSON.parse(readFileSync("server.json", "utf8"));
const V = pkg.version;

console.log(`nel-veil-mcp release ${V}${DRY ? "  (dry run)" : ""}`);
console.log(`cwd: ${ROOT}`);

// ── 1. The manifests must agree, or the registry rejects the submission ──
step(1, "checking manifests agree");
if (server.version !== V) die(`server.json version ${server.version} != package.json ${V}`);
if (server.packages[0].version !== V) die(`server.json packages[0].version ${server.packages[0].version} != ${V}`);
if (pkg.mcpName !== server.name) die(`package.json mcpName ${pkg.mcpName} != server.json name ${server.name}`);
console.log(`    ok: ${V}, mcpName ${pkg.mcpName}`);

// ── 2. Already published? Stop before wasting a 2FA prompt ──────────────
step(2, "checking npm does not already have this version");
// npm returns a bare STRING for one version, an ARRAY for many. Object.keys()
// on an array yields indices, which silently defeats the guard below - the dry
// run reported "latest on npm is 4".
const npmVersions = () => {
  try {
    const raw = JSON.parse(capture("npm view nel-veil-mcp versions --json"));
    return Array.isArray(raw) ? raw : [raw];
  } catch {
    return [];
  }
};
const published = npmVersions();
if (published.includes(V)) die(`nel-veil-mcp@${V} is already on npm. Bump the version first.`);
console.log(`    ok: latest on npm is ${published[published.length - 1] ?? "(none)"}`);

// ── 3. npm auth. A stale token 404s on PUT and looks like a missing package ──
step(3, "checking npm login");
let who;
try { who = capture("npm whoami"); }
catch { die("not logged in to npm. Run:  npm login   (browser flow, land as nelproinc)"); }
if (who !== "nelproinc") die(`logged in as "${who}", but the package is owned by nelproinc. Run: npm logout && npm login`);
console.log(`    ok: ${who}`);

// ── 4. Build and prove the built server actually works ──────────────────
step(4, "build + smoke test");
run("npm run build");
run("node scripts/mcp-smoke.mjs example.com");

if (DRY) { console.log("\nDry run complete. Nothing was published."); process.exit(0); }

// ── 5. npm. This is the first of two moments needing you. ──────────────
step(5, "publishing to npm  (2FA prompt incoming)");
run("npm publish");

// ── 6. npm is eventually consistent; the registry checks it synchronously ──
step(6, "waiting for npm to serve the new version");
let live = false;
for (let i = 0; i < 30; i++) {
  try {
    if (npmVersions().includes(V)) { live = true; break; }
  } catch { /* retry */ }
  execSync(process.platform === "win32" ? "timeout /t 5 /nobreak >nul" : "sleep 5", { stdio: "ignore" });
  process.stdout.write("    .");
}
if (!live) die(`npm still does not serve ${V} after ~2.5 min. Re-run once it does; npm publish is already done, so skip step 5.`);
console.log(`\n    ok: npm serves ${V}`);

// ── 7 + 8. Login and publish must be adjacent: the JWT expires in minutes ──
step(7, "MCP registry login  (GitHub device code incoming)");
run(`"${PUBLISHER}" login github`);

step(8, "publishing to the MCP registry");
run(`"${PUBLISHER}" publish`);

// ── 9. Verify from the outside, not from this working copy ─────────────
step(9, "verifying");
const npmLatest = capture("npm view nel-veil-mcp version");
console.log(`    npm latest: ${npmLatest}${npmLatest === V ? "  ok" : "  MISMATCH"}`);
try {
  const body = capture(`curl.exe -s "https://registry.modelcontextprotocol.io/v0.1/servers?search=nel-veil"`);
  const entry = JSON.parse(body).servers.find((e) => e._meta?.["io.modelcontextprotocol.registry/official"]?.isLatest);
  console.log(`    registry latest: ${entry?.server?.version}${entry?.server?.version === V ? "  ok" : "  MISMATCH"}`);
} catch { console.log("    registry check failed; verify by hand"); }

console.log(`\nReleased ${V}.`);
