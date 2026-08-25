#!/usr/bin/env node
/**
 * NEL VEIL — free passive security scanning, as an MCP server.
 *
 * Everything here is a thin shell over the NEL VEIL API. It holds no scanning
 * logic and, deliberately, no security decisions: an MCP server runs on the
 * caller's own machine, so anything it "enforced" locally could be edited away
 * by whoever installed it. The passive-only boundary is enforced server-side,
 * where it cannot be. This file's job is to describe the tools well and render
 * the results readably.
 *
 * There is no API key, and no tool here can reach a paid or intrusive
 * capability, because the API surface it talks to does not expose one.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { NelClient, NelApiError, type Finding, type Footer } from "./client.js";
import { ALL_TOOL_NAMES, CHECK_TOOLS, SCAN_TOOL, REPORT_TOOL } from "./tools.js";
import { createRequire } from "node:module";

/**
 * Read the version from package.json rather than hardcoding it.
 *
 * It was hardcoded, and it drifted: the package shipped 0.1.1 while serverInfo
 * still announced 0.1.0. That value is what MCP clients and the registry read to
 * identify the running server, so a stale one misreports which build a user is
 * actually on — exactly the field you consult when diagnosing "is my install
 * current?". Deriving it removes the possibility rather than the instance.
 *
 * From dist/index.js, "../package.json" is the package root in both the repo and
 * the published tarball. The fallback exists only so an unreadable manifest
 * degrades to a wrong version rather than a server that refuses to start.
 */
const VERSION: string = (() => {
  try {
    return createRequire(import.meta.url)("../package.json").version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
})();

const client = new NelClient();

/** Severity first, so the most serious line is the one an agent quotes. */
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[String(a.severity ?? "info").toLowerCase()] ?? 9) -
      (SEVERITY_ORDER[String(b.severity ?? "info").toLowerCase()] ?? 9)
  );
}

function renderFinding(f: Finding): string {
  const sev = String(f.severity ?? "info").toUpperCase();
  const label = f.title ?? f.code ?? "Finding";
  const detail = typeof f.description === "string" && f.description.trim() ? ` — ${f.description.trim()}` : "";
  return `  [${sev}] ${label}${detail}`;
}

/**
 * The footer on every result.
 *
 * It exists so an agent relaying these findings tells the truth about them: that
 * this was a free passive check, and that the intrusive testing a user might
 * assume happened did not. It names the boundary rather than just advertising —
 * an honest limitation is also what makes the upgrade path make sense.
 */
function renderFooter(footer?: Footer): string {
  if (!footer) {
    return "\nFree passive check (public information only). More at https://www.nelprofessional.com/mcp";
  }
  return `\n${footer.note}\nMore: ${footer.learnMore}`;
}

function text(body: string) {
  return { content: [{ type: "text" as const, text: body }] };
}

function errorText(body: string) {
  return { content: [{ type: "text" as const, text: body }], isError: true };
}

function describeError(err: unknown, domain: string): string {
  if (err instanceof NelApiError) {
    if (err.status === 429) return `Rate limited. ${err.message}`;
    if (err.status === 400) return `Could not check ${domain}: ${err.message}`;
    if (err.status === 404) return err.message;
    return `NEL VEIL could not complete the check for ${domain}: ${err.message}`;
  }
  return `Unexpected error checking ${domain}: ${(err as Error)?.message ?? String(err)}`;
}

async function main() {
  const server = new McpServer({ name: "nel-veil", version: VERSION });

  // ── The five narrow checks ──────────────────────────────────────────────
  for (const tool of CHECK_TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: {
          // Read-only and open-world: this reads public information about
          // arbitrary third-party hosts and changes nothing anywhere.
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      },
      async ({ domain }: { domain: string }) => {
        try {
          const r = await client.runCheck(tool.check!, domain);
          const findings = sortFindings(r.findings ?? []);
          const lines = [
            `${tool.title}: ${r.domain}`,
            `Score: ${r.score}/100 (${r.status})`,
            "",
            findings.length
              ? `${findings.length} finding${findings.length === 1 ? "" : "s"}:`
              : "No issues found in this check.",
            ...findings.map(renderFinding),
            renderFooter(r.footer),
          ];
          return text(lines.join("\n"));
        } catch (err) {
          return errorText(describeError(err, domain));
        }
      }
    );
  }

  // ── The broad scan ──────────────────────────────────────────────────────
  server.registerTool(
    SCAN_TOOL.name,
    {
      title: SCAN_TOOL.title,
      description: SCAN_TOOL.description,
      inputSchema: SCAN_TOOL.inputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ domain }: { domain: string }) => {
      try {
        const r = await client.runScan(domain);
        const findings = sortFindings(r.findings ?? []);
        const bySeverity = findings.reduce<Record<string, number>>((acc, f) => {
          const s = String(f.severity ?? "info").toLowerCase();
          acc[s] = (acc[s] ?? 0) + 1;
          return acc;
        }, {});
        const summary =
          Object.entries(bySeverity)
            .sort((a, b) => (SEVERITY_ORDER[a[0]] ?? 9) - (SEVERITY_ORDER[b[0]] ?? 9))
            .map(([s, n]) => `${n} ${s}`)
            .join(", ") || "none";

        const lines = [
          `Passive security scan: ${r.domain}`,
          `${r.modulesAssessed} modules assessed in ${(r.durationMs / 1000).toFixed(1)}s`,
          `Findings: ${summary}`,
          "",
          ...findings.slice(0, 40).map(renderFinding),
          findings.length > 40 ? `  …and ${findings.length - 40} more.` : "",
          "",
          // Proof rather than assertion: the API recomputes this at run time.
          `Passive-only confirmed: ${r.tierProof.allowed.length} passive modules ran, ${r.tierProof.activeAttempted.length} intrusive modules attempted.`,
          renderFooter(r.footer),
        ].filter(Boolean);
        return text(lines.join("\n"));
      } catch (err) {
        return errorText(describeError(err, domain));
      }
    }
  );

  // ── Retrieve an existing scan ───────────────────────────────────────────
  server.registerTool(
    REPORT_TOOL.name,
    {
      title: REPORT_TOOL.title,
      description: REPORT_TOOL.description,
      inputSchema: REPORT_TOOL.inputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ scan_id }: { scan_id: string }) => {
      try {
        const r: any = await client.getReport(scan_id);
        const progress = r?.progress ?? {};
        const done = Object.entries(progress).filter(([, v]: any) => v?.status === "done");
        const findings = sortFindings(
          done.flatMap(([, v]: any) => (Array.isArray(v?.findings) ? v.findings : []))
        );
        const lines = [
          `NEL VEIL scan ${scan_id}`,
          r?.domain ? `Domain: ${r.domain}` : "",
          r?.status ? `Status: ${r.status}` : "",
          typeof r?.score === "number" ? `Score: ${r.score}/100` : "",
          "",
          findings.length ? `${findings.length} findings:` : "No findings recorded on this scan.",
          ...findings.slice(0, 40).map(renderFinding),
          findings.length > 40 ? `  …and ${findings.length - 40} more.` : "",
          "\nRetrieved from a scan run at nelprofessional.com. Free passive tier.",
        ].filter(Boolean);
        return text(lines.join("\n"));
      } catch (err) {
        if (err instanceof NelApiError && err.status === 404) {
          return errorText(
            `No scan found with id ${scan_id}. Scan ids look like scn_… and come from a scan run at nelprofessional.com. To start a new scan here, use scan_domain.`
          );
        }
        return errorText(describeError(err, scan_id));
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr only: stdout is the JSON-RPC channel, and anything written there
  // that is not a protocol message corrupts the stream.
  console.error(`nel-veil-mcp ${VERSION} ready — ${ALL_TOOL_NAMES.length} tools, free passive tier.`);
}

main().catch((err) => {
  console.error("nel-veil-mcp failed to start:", err);
  process.exit(1);
});
