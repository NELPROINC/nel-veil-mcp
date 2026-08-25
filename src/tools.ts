/**
 * Tool definitions — and the descriptions ARE the product.
 *
 * An agent picks a tool by reading its description, and a registry indexes the
 * same text. So each one is written answer-first: the first sentence states the
 * question the tool answers in the words someone would actually ask it ("can
 * this domain be impersonated?"), not the internal mechanism. Then what it
 * checks, then what it returns, then when NOT to use it.
 *
 * The "when not to use" line is load-bearing rather than padding. The common
 * failure in a multi-tool server is an agent picking the broad tool for a narrow
 * question — burning a full scan to answer "is DMARC set up?" — so each narrow
 * tool names its neighbour, and the broad one says when it is overkill.
 *
 * Every description states passive-and-free explicitly. That is honest about the
 * capability boundary, and it stops an agent promising a user something this
 * server cannot do.
 */
import { z } from "zod";

const domainArg = {
  domain: z
    .string()
    .min(1)
    .max(253)
    .describe(
      "The domain to check, e.g. example.com. Bare domains work best; a full URL or a www. prefix is accepted and normalised. Do not pass an IP address, an email address, or a private/internal hostname — those are refused."
    ),
};

/**
 * The shapes are exported with their CONCRETE types, not as a wide
 * Record<string, ZodTypeAny>. The SDK infers a tool handler's argument type from
 * the shape it is given, so widening the type here erases `domain: string` at
 * the registration site and the handler silently loses its typing.
 */
export type DomainShape = typeof domainArg;
export type ScanIdShape = { scan_id: z.ZodString };

export interface ToolDef<S extends Record<string, z.ZodTypeAny> = DomainShape> {
  name: string;
  title: string;
  description: string;
  inputSchema: S;
  /** Which /api/v1/mcp/check/:name this maps to. Absent for non-check tools. */
  check?: string;
}

const PASSIVE_NOTE =
  "This is a free, passive check: it reads public DNS records and public HTTP responses only. It sends no intrusive traffic, runs no exploits, and needs no permission from the domain owner.";

export const CHECK_TOOLS: ToolDef<DomainShape>[] = [
  {
    name: "check_email_spoofing",
    title: "Check if a domain can be email-spoofed",
    check: "email_spoofing",
    description:
      "Answers: can someone send email that appears to come from this domain? " +
      "Checks the published SPF, DKIM and DMARC DNS records — whether DMARC exists, whether its policy actually blocks spoofed mail (p=none only monitors, it does not stop anything), whether SPF is present and not overly permissive, and whether the records are syntactically valid. " +
      "Returns a 0-100 score plus specific findings, each tied to the record it came from, so the exact problem can be quoted. " +
      PASSIVE_NOTE +
      " Use this for any question about email spoofing, phishing impersonation, DMARC/SPF/DKIM setup, or whether an email domain is protected. For a broader picture covering TLS, headers and exposed files too, use scan_domain instead.",
    inputSchema: domainArg,
  },
  {
    name: "check_tls",
    title: "Check a domain's HTTPS/TLS configuration",
    check: "tls",
    description:
      "Answers: is this domain's HTTPS set up correctly, and is the certificate about to cause an outage? " +
      "Checks the TLS certificate and connection: whether the certificate is valid for the hostname, who issued it, how many days remain until expiry, and whether the negotiated protocol version and configuration are current rather than deprecated. " +
      "Returns a 0-100 score plus findings, including expiry dates that can be acted on. " +
      PASSIVE_NOTE +
      " Use this for certificate expiry, HTTPS misconfiguration, or general SSL health. It does not check HTTP security headers — use check_security_headers for those.",
    inputSchema: domainArg,
  },
  {
    name: "check_security_headers",
    title: "Check a domain's HTTP security headers",
    check: "security_headers",
    description:
      "Answers: does this site send the HTTP response headers that protect visitors in the browser? " +
      "Checks for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options / frame-ancestors, Referrer-Policy and Permissions-Policy — whether each is present and whether its value is actually protective rather than nominal. " +
      "Returns a 0-100 score plus a finding per header explaining what a missing or weak value exposes. " +
      PASSIVE_NOTE +
      " Use this for clickjacking, XSS mitigation, CSP or HSTS questions. It does not check the TLS certificate itself — use check_tls for that.",
    inputSchema: domainArg,
  },
  {
    name: "check_exposed_files",
    title: "Check a domain for publicly exposed sensitive files",
    check: "exposed_files",
    description:
      "Answers: is this domain publicly serving files it should not be? " +
      "Requests a small, fixed list of well-known sensitive paths — things like .env, .git/config, backup archives and exposed configuration — and reports which return real content rather than a 404. " +
      "Returns a 0-100 score plus a finding per exposed path. " +
      "This is a passive, free check: it performs ordinary GET requests for a fixed list of public URLs, exactly as any web crawler would. It does not enumerate, brute-force or fuzz paths, and downloads nothing beyond what is needed to confirm exposure. " +
      "Use this for leaked secrets, exposed configuration, or accidentally published files. It does not discover subdomains or scan ports.",
    inputSchema: domainArg,
  },
  {
    name: "check_subdomain_takeover",
    title: "Check a domain for subdomain-takeover risk",
    check: "subdomain_takeover",
    description:
      "Answers: does this domain have DNS records pointing at services someone else could claim? " +
      "Inspects published DNS records for dangling CNAMEs — entries still pointing at a de-provisioned cloud or SaaS host (an unclaimed bucket, an expired app instance) that an attacker could register and then serve content from a hostname users already trust. " +
      "Returns a 0-100 score plus a finding per at-risk record, naming the record and the service it points to. " +
      PASSIVE_NOTE +
      " It reads DNS only and never attempts to claim anything. Use this for dangling DNS, abandoned cloud resources, or subdomain hijacking risk.",
    inputSchema: domainArg,
  },
];

export const SCAN_TOOL: ToolDef<DomainShape> = {
  name: "scan_domain",
  title: "Run a full passive security posture scan of a domain",
  description:
    "Answers: what is this domain's overall security posture? " +
    "Runs every passive NEL VEIL module in one pass — DNS, email authentication (SPF/DKIM/DMARC), TLS, HTTP security headers, cookies, CORS, exposed files, subdomain-takeover risk, technology fingerprinting, breach exposure, domain reputation, cloud misconfiguration and JavaScript supply chain — and returns findings from all of them with a per-module score. " +
    "Use this when the question is broad: how secure is this domain, review this vendor, what should we fix first. For a single specific question prefer the narrower tool — check_email_spoofing, check_tls, check_security_headers, check_exposed_files or check_subdomain_takeover — which is faster and easier to read. " +
    "This is a free, passive scan built entirely from public information: public DNS records and ordinary HTTP requests. It performs NO port scanning, NO endpoint enumeration and NO exploit testing, so it needs no permission from the domain owner and is safe to run against a third party being evaluated. " +
    "Active scanning (port scans, API probing, proof-of-concept exploit checks) is deliberately not available through this MCP server; it requires proving control of the domain and runs only at nelprofessional.com.",
  inputSchema: domainArg,
};

export const REPORT_TOOL: ToolDef<ScanIdShape> = {
  name: "get_scan_report",
  title: "Retrieve a previously run NEL VEIL scan by its id",
  description:
    "Answers: what did an earlier NEL VEIL scan find? " +
    "Fetches the stored results of a scan already run at nelprofessional.com, by its scan id (the scn_... identifier shown on the scan page and in its shareable report link). " +
    "Returns the saved findings and score for that scan. " +
    "Use this to pull a scan someone already ran on the website into the conversation — to summarise it, compare it against a later scan, or turn it into a remediation plan. " +
    "It cannot start a new scan: use scan_domain for that. It only reads scans that exist and are publicly retrievable by id.",
  inputSchema: {
    scan_id: z
      .string()
      .min(3)
      .max(128)
      .describe("The scan identifier, e.g. scn_1a2b3c..., from a nelprofessional.com scan page or report link."),
  },
};

export const ALL_TOOL_NAMES: string[] = [SCAN_TOOL, ...CHECK_TOOLS, REPORT_TOOL].map((t) => t.name);
