/**
 * End-to-end MCP smoke test — speaks real JSON-RPC over STDIO to the built server.
 *
 *   node scripts/mcp-smoke.mjs            (against production)
 *   NEL_API_URL=http://127.0.0.1:4310 node scripts/mcp-smoke.mjs
 *
 * This is deliberately NOT a unit test of the handlers. It launches dist/index.js
 * exactly the way `npx nel-veil-mcp` would, performs the initialize handshake,
 * lists the tools, and calls one for real. If the transport, the tool schemas, or
 * the wiring to the API is wrong, this fails where a unit test would pass.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET = process.argv[2] ?? "github.com";

const child = spawn(process.execPath, [join(ROOT, "dist", "index.js")], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env },
});

let buf = "";
const pending = new Map();
let nextId = 1;

child.stdout.on("data", (chunk) => {
  buf += chunk.toString();
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      console.log("  [non-JSON on stdout — would corrupt the protocol]", line.slice(0, 80));
      continue;
    }
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

child.stderr.on("data", (d) => {
  const s = d.toString().trim();
  if (s) console.log("  [stderr]", s.slice(0, 120));
});

function send(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => reject(new Error(`timeout waiting for ${method}`)), 90_000);
  });
}

function notify(method, params) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

const ok = (label, cond) => console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
let failures = 0;
const check = (label, cond) => {
  if (!cond) failures++;
  ok(label, cond);
};

try {
  const init = await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "nel-veil-smoke", version: "1.0.0" },
  });
  check("initialize handshake succeeds", !!init.result);
  check("server identifies as nel-veil", init.result?.serverInfo?.name === "nel-veil");
  notify("notifications/initialized", {});

  const list = await send("tools/list", {});
  const tools = list.result?.tools ?? [];
  const names = tools.map((t) => t.name).sort();
  check(`tools/list returns 9 tools (got ${tools.length})`, tools.length === 9);
  check(
    "the exact expected tool set is exposed",
    names.join(",") ===
      [
        "check_compliance",
        "check_email_spoofing",
        "check_exposed_files",
        "check_security_headers",
        "check_subdomain_takeover",
        "check_tls",
        "get_scan_report",
        "list_compliance_frameworks",
        "scan_domain",
      ].join(",")
  );

  // ── The compliance pair ──────────────────────────────────────────────────
  // Schema-level only, so the smoke test stays fast: the assessment itself runs
  // a full passive scan and is covered by the backend's own suites.
  const byToolName = Object.fromEntries(tools.map((t) => [t.name, t]));
  const compTool = byToolName.check_compliance;
  check("check_compliance takes a domain", !!compTool?.inputSchema?.properties?.domain);
  check(
    "check_compliance offers the frameworks and region filters",
    !!compTool?.inputSchema?.properties?.frameworks && !!compTool?.inputSchema?.properties?.region
  );
  check(
    "check_compliance requires only the domain",
    JSON.stringify(compTool?.inputSchema?.required ?? []) === JSON.stringify(["domain"])
  );
  check(
    "check_compliance tells the agent to read coverage before quoting a score",
    /COVERAGE/i.test(compTool?.description ?? "") && /Not assessed/.test(compTool?.description ?? "")
  );
  check(
    "check_compliance disclaims audit, certification and legal advice",
    /NOT AUDIT RESULTS/i.test(compTool?.description ?? "") &&
      /not legal advice/i.test(compTool?.description ?? "")
  );
  const fwTool = byToolName.list_compliance_frameworks;
  check(
    "the catalogue tool takes no arguments",
    Object.keys(fwTool?.inputSchema?.properties ?? {}).length === 0
  );
  check(
    "the catalogue tool is closed-world — it contacts no third-party host",
    fwTool?.annotations?.openWorldHint === false
  );
  check(
    "the catalogue tool says some entries can never be assessed",
    /assessable/i.test(fwTool?.description ?? "")
  );
  // Word-boundary matched on the underscore-delimited parts of the name. A bare
  // /port/ substring test matches "get_scan_report", which is exactly the kind of
  // false positive that trains people to ignore a failing security check.
  const ACTIVE_WORDS = new Set([
    "port", "ports", "portscan", "exploit", "poc", "probe", "bruteforce",
    "brute", "attack", "intrusive", "enumerate", "fuzz", "payload",
  ]);
  check(
    "no tool name hints at active scanning",
    !names.some((n) => n.split(/[_-]/).some((part) => ACTIVE_WORDS.has(part.toLowerCase())))
  );
  check("every tool has a description", tools.every((t) => (t.description ?? "").length > 100));
  check(
    "every tool is annotated read-only and non-destructive",
    tools.every((t) => t.annotations?.readOnlyHint === true && t.annotations?.destructiveHint === false)
  );
  // check_tls is deliberately NOT described as passive: it queries Qualys SSL
  // Labs, which actively assesses the target. This assertion used to demand that
  // EVERY tool claim passivity, which is how the inaccurate copy passed review in
  // the first place — the test was enforcing the wrong thing. It now enforces
  // what is actually true, and pins the disclosure so it cannot quietly vanish.
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  // Only tools that actually reach out to a TARGET carry this disclosure.
  // get_scan_report reads a scan NEL already has, and
  // list_compliance_frameworks returns a static catalogue and takes no domain
  // at all — neither of them sends anything to a third party, so requiring them
  // to promise "no port scanning" would be noise rather than a safety claim.
  const NON_TARGETING = new Set(["get_scan_report", "list_compliance_frameworks"]);
  check(
    "every tool that contacts a target states it is free and does no port scanning / exploit testing",
    tools
      .filter((t) => !NON_TARGETING.has(t.name))
      .every((t) => /free/i.test(t.description) && /no port scanning|NO port scanning/i.test(t.description))
  );
  check(
    "and the non-targeting tools say they contact no target",
    /runs no scan/i.test(byToolName.list_compliance_frameworks?.description ?? "") &&
      /cannot start a new scan/i.test(byToolName.get_scan_report?.description ?? "")
  );
  check(
    "REGRESSION — check_tls DISCLOSES that it is not passive (Qualys SSL Labs assesses the target)",
    /NOT passive/i.test(byName.check_tls?.description ?? "") &&
      /SSL Labs/.test(byName.check_tls?.description ?? "")
  );
  check(
    "REGRESSION — check_tls does not PROMISE certificate expiry it never returns",
    (() => {
      // Match a promise, not the disclaimer. The description legitimately contains
      // the phrase "does NOT report certificate expiry dates" — a bare substring
      // test flags the very sentence that fixes the problem.
      const d = byName.check_tls?.description ?? "";
      const promises = /Returns[^.]*expiry|including expiry dates|how many days remain until expiry|who issued it, how many/i.test(d);
      const disclaims = /does NOT report certificate expiry/i.test(d);
      return !promises && disclaims;
    })()
  );
  check(
    "REGRESSION — scan_domain discloses the admin-panel paths it requests",
    /phpmyadmin/i.test(byName.scan_domain?.description ?? "") &&
      !/NO endpoint enumeration/.test(byName.scan_domain?.description ?? "")
  );
  check(
    "REGRESSION — check_subdomain_takeover no longer claims DNS-only",
    !/reads DNS only/i.test(byName.check_subdomain_takeover?.description ?? "")
  );

  console.log(`\n  calling check_email_spoofing on ${TARGET} ...`);
  const call = await send("tools/call", {
    name: "check_email_spoofing",
    arguments: { domain: TARGET },
  });
  const body = call.result?.content?.[0]?.text ?? "";
  check("tool call returns text content", body.length > 0);
  check("the result is not an error", call.result?.isError !== true);
  check("the result carries a score", /Score: \d+\/100/.test(body));
  check("the result carries the honest footer", /passive/i.test(body) && /nelprofessional\.com/.test(body));
  console.log("\n----- tool output -----");
  console.log(body.split("\n").slice(0, 12).map((l) => "  " + l).join("\n"));
  console.log("-----------------------\n");
} catch (err) {
  failures++;
  console.log("FAIL  harness error:", err.message);
} finally {
  child.kill();
}

console.log(failures === 0 ? "\nALL SMOKE CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
