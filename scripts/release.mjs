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
 * IT IS RESUMABLE, AND THAT IS THE POINT. A release is two publishes to two
 * registries with a human in the middle of each, so it WILL sometimes stop
 * half-done — 0.1.5 reached npm and then this script crashed before the
 * registry. Re-running decides what is left by asking npm and the registry what
 * they already serve, then skips those steps. The recovery for any failure is
 * therefore just to run it again: there is no "resume from step N" to get
 * right, and re-running after a full success is a no-op rather than a
 * duplicate-version error.
 *
 * Usage, from anywhere:
 *   node scripts/release.mjs            publish whatever is not yet published
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
const skip = (n, msg) => console.log(`\n[${n}] ${msg}  (already done, skipping)`);
const die = (msg) => { console.error(`\nFAILED: ${msg}`); process.exit(1); };
const run = (cmd) => execSync(cmd, { stdio: "inherit" });
const capture = (cmd) => execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/**
 * Synchronous sleep via Atomics.wait on a SharedArrayBuffer.
 *
 * NOT `timeout /t 5`, which is what broke the 0.1.5 release: Windows' timeout
 * needs a real console for its keypress handling, and under `npm run` stdin is
 * a pipe, so it exits 1 and execSync throws. This is pure JS — no child
 * process, no stdin, nothing that can fail.
 */
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

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

/**
 * What npm actually serves, read over HTTP rather than via `npm view`.
 *
 * Two traps, both hit for real. `npm view <pkg> versions --json` returns a bare
 * STRING for a single-version package and an ARRAY for many, and Object.keys()
 * on the array yields INDICES — the first version of this script printed
 * "latest on npm is 4". And `npm view` reads a local cache: it kept reporting
 * 0.1.4 for minutes after 0.1.5 was live, which would have made the poll below
 * spin for its full timeout.
 */
function npmVersions() {
  try {
    const json = JSON.parse(capture("curl.exe -s https://registry.npmjs.org/nel-veil-mcp"));
    return Object.keys(json.versions || {});
  } catch {
    try {
      const raw = JSON.parse(capture("npm view nel-veil-mcp versions --json"));
      return Array.isArray(raw) ? raw : [raw];
    } catch {
      return [];
    }
  }
}

/** The version the MCP registry currently serves as latest, or null. */
function registryVersion() {
  try {
    const body = capture('curl.exe -s "https://registry.modelcontextprotocol.io/v0.1/servers?search=nel-veil"');
    const entry = JSON.parse(body).servers.find(
      (e) => e._meta?.["io.modelcontextprotocol.registry/official"]?.isLatest
    );
    return entry?.server?.version ?? null;
  } catch {
    return null;
  }
}

// ── 2. Decide what is actually left to do ───────────────────────────────
step(2, "checking what still needs publishing");
const onNpm = npmVersions();
const needsNpm = !onNpm.includes(V);
const regNow = registryVersion();
const needsRegistry = regNow !== V;
console.log(`    npm      serves ${onNpm[onNpm.length - 1] ?? "(nothing)"}  ->  ${needsNpm ? "PUBLISH" : "up to date"}`);
console.log(`    registry serves ${regNow ?? "(unknown)"}  ->  ${needsRegistry ? "PUBLISH" : "up to date"}`);

if (!needsNpm && !needsRegistry) {
  console.log(`\nNothing to do: ${V} is already on npm and the MCP registry.`);
  process.exit(0);
}

// ── 3. npm auth. A stale token 404s on PUT and looks like a missing package ──
if (needsNpm) {
  step(3, "checking npm login");
  let who;
  try {
    who = capture("npm whoami");
  } catch {
    die("not logged in to npm. Run:  npm login   (browser flow, land as nelproinc)");
  }
  if (who !== "nelproinc") {
    die(`logged in as "${who}", but the package is owned by nelproinc. Run: npm logout && npm login`);
  }
  console.log(`    ok: ${who}`);
} else {
  skip(3, "npm login check");
}

// ── 4. Build and prove the built server actually works ──────────────────
step(4, "build + smoke test");
run("npm run build");
run("node scripts/mcp-smoke.mjs example.com");

if (DRY) {
  const todo = [needsNpm && "npm", needsRegistry && "MCP registry"].filter(Boolean).join(" + ");
  console.log(`\nDry run complete. Nothing was published.`);
  console.log(`Would publish to: ${todo}`);
  process.exit(0);
}

// ── 5. npm. The first of two moments needing you. ──────────────────────
if (needsNpm) {
  step(5, "publishing to npm  (2FA prompt incoming)");
  run("npm publish");

  // ── 6. npm is eventually consistent; the registry checks it synchronously ──
  step(6, "waiting for npm to serve the new version");
  let live = false;
  for (let i = 0; i < 30; i++) {
    if (npmVersions().includes(V)) {
      live = true;
      break;
    }
    sleep(5000);
    process.stdout.write(".");
  }
  if (!live) {
    die(`npm still does not serve ${V} after ~2.5 min. Run this script again once it does; it will skip the npm publish automatically.`);
  }
  console.log(`\n    ok: npm serves ${V}`);
} else {
  skip(5, "npm publish");
}

// ── 7 + 8. Login and publish must be adjacent: the JWT expires in minutes ──
if (needsRegistry) {
  step(7, "MCP registry login  (GitHub device code incoming)");
  run(`"${PUBLISHER}" login github`);

  step(8, "publishing to the MCP registry");
  run(`"${PUBLISHER}" publish`);
} else {
  skip(7, "MCP registry publish");
}

// ── 9. Verify from the outside, not from this working copy ─────────────
step(9, "verifying");
const npmOk = npmVersions().includes(V);
console.log(`    npm serves ${V}: ${npmOk ? "yes" : "NO"}`);
const regFinal = registryVersion();
console.log(`    registry latest: ${regFinal ?? "(unknown)"}${regFinal === V ? "  ok" : "  MISMATCH"}`);

if (!npmOk || regFinal !== V) {
  die("release incomplete. Run this script again; it will pick up whatever is missing.");
}
console.log(`\nReleased ${V}.`);
