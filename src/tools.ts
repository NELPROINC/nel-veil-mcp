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
      "The domain to check, e.g. example.com. Bare domains work best; a full URL, a www. prefix, or an address with a userinfo part are all accepted and normalised to the bare hostname. A PUBLIC IP address is also accepted, so an origin server can be checked directly. What is refused: a private or reserved address (127.0.0.1, 10.x, 192.168.x, 169.254.169.254 and the rest), a name with no TLD such as localhost, and an IPv6 literal."
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

/**
 * The honest shared note.
 *
 * It used to say "reads public DNS records and public HTTP responses only. It
 * sends no intrusive traffic" and was attached to EVERY tool. That was not true
 * of all of them, and an inaccurate safety claim on a security product is the
 * worst kind of copy error: it is the sentence a user relies on when deciding
 * whether they are allowed to point this at someone else's domain.
 *
 * So this note now says only what is true of every tool that carries it, and the
 * two tools that do more than this carry their own, longer disclosure instead.
 */
const PASSIVE_NOTE =
  "This is a free check that uses public information: DNS records and ordinary HTTP requests. It does no port scanning and no exploit testing.";

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
      "Answers: is this domain's HTTPS certificate valid, trusted, and about to expire? " +
      "Makes ONE ordinary TLS handshake to port 443 — the same thing a browser does when it loads the site — and reports what the server presents: the certificate issuer and subject, the validity window and how many days remain, the subject alternative names, and the protocol and cipher that were negotiated. " +
      "It flags an expired certificate, one expiring within 14 or 30 days, a self-signed certificate, an untrusted chain, a certificate that does not cover the hostname, and a connection negotiated over deprecated TLS 1.0 or 1.1. " +
      "It is free and genuinely passive: NEL makes the one connection itself, no third party is asked to test the target, and it does no port scanning and no exploit testing. " +
      "WHAT IT CANNOT TELL YOU: a single handshake shows what the server chose for THAT connection, not everything it would accept. It does not enumerate supported cipher suites, does not produce a letter grade, and does not test for Heartbleed, POODLE, DROWN or RC4 support. Those need the deep TLS assessment, which is an active check and runs only at nelprofessional.com after you prove you control the domain. " +
      "It does not check HTTP security headers — use check_security_headers for those.",
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
      "How it works, stated plainly: it makes ordinary GET requests for a small FIXED list of well-known paths. It does not brute-force, fuzz, or enumerate — the list never grows and never adapts to what it finds. Note that these are paths an ordinary crawler would not request (.env, .git/config), so the requests are recognisable in a target's logs as a security check rather than routine crawling. " +
      PASSIVE_NOTE +
      " Use this for leaked secrets, exposed configuration, or accidentally published files. It does not discover subdomains.",
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
      "How it works, stated plainly: it resolves a small fixed list of common subdomain names (www, mail, dev, staging and similar) and, for any that resolve to a known cloud or SaaS host, makes one ordinary HTTPS GET to check for that provider's unclaimed-resource page. So it is not DNS-only — it does send a small number of HTTP requests to subdomains of the target. It never registers, claims, or modifies anything. " +
      PASSIVE_NOTE +
      " Use this for dangling DNS, abandoned cloud resources, or subdomain hijacking risk.",
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
    "It is free. What it actually sends, stated plainly, because \"passive\" means different things to different people. It performs NO port scanning and NO exploit testing. It DOES: request a fixed list of well-known paths, including common admin panels such as /phpmyadmin/ and /manager/html, to report whether they are publicly reachable; resolve a small fixed list of common subdomain names and make one HTTPS request to any that point at a known cloud host; and make one ordinary TLS handshake to port 443 to read the certificate. " +
    "None of that is intrusive in the sense of attacking anything, and all of it is information the domain publishes — but it is more than a crawler does, and it is recognisable in the target's logs as a security scan. Prefer running it against a domain you own or are authorised to assess. " +
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

/**
 * The compliance pair.
 *
 * These exist because "is this domain secure?" and "does this domain look
 * aligned with the law that applies to us?" are different questions, and an
 * agent asked the second one should not have to invent a mapping from findings
 * to statutes. The API does that mapping against a register of 102 frameworks
 * and, crucially, reports COVERAGE — so an agent can say "not assessed" instead
 * of implying a clean bill of health from checks that never ran.
 *
 * The catalogue tool is separate and cheap on purpose: an agent needs the ids
 * before it can filter, and fetching them should not cost a scan.
 */
export type ComplianceShape = {
  domain: z.ZodString;
  frameworks: z.ZodOptional<z.ZodArray<z.ZodString>>;
  region: z.ZodOptional<z.ZodEnum<["canada", "united_states", "eu_eea", "united_kingdom", "asia_pacific", "africa", "global"]>>;
};

export const FRAMEWORKS_TOOL: ToolDef<Record<string, never>> = {
  name: "list_compliance_frameworks",
  title: "List the compliance frameworks NEL VEIL can assess a domain against",
  description:
    "Answers: which laws, regulations and standards can this tool report on, and which can it not? " +
    "Returns the full register — 102 frameworks across Canada, the United States, the EU/EEA, the United Kingdom, Asia-Pacific, Africa and global standards (ISO 27001, SOC 2, PCI DSS, NIST CSF and others) — grouped by region, each with its id, jurisdiction, regulator and subject area. " +
    "Each entry says whether it is externally ASSESSABLE. Around a quarter are not: an anti-money-laundering regime, a consumer-protection statute, a criminal offences provision or a securities disclosure rule imposes no technical safeguard an external scan could ever evidence, and the entry says so in words rather than being quietly scored. " +
    "Use it to find the id to pass to check_compliance, or to answer 'can you check us against <law>?' honestly. " +
    "It runs no scan, costs nothing and takes no domain. For an actual assessment use check_compliance.",
  inputSchema: {},
};

export const COMPLIANCE_TOOL: ToolDef<ComplianceShape> = {
  name: "check_compliance",
  title: "Assess a domain's readiness signals against compliance frameworks",
  description:
    "Answers: what do this domain's public-facing security signals suggest about its alignment with the laws and standards that apply to it? " +
    "Runs one passive scan and maps the findings onto a register of 102 frameworks — GDPR, UK GDPR, PIPEDA, CCPA/CPRA and the US state privacy acts, NIS2, DORA, the EU AI Act, PIPL, APPI, POPIA, ISO 27001, SOC 2, PCI DSS, NIST CSF and more — returning a per-framework readiness score with the specific provision each finding bears on. " +
    "READ THE COVERAGE FIELD BEFORE RELAYING A SCORE. Every framework reports how many of the scan categories it relies on were actually observed, as \"9/16\". A framework whose relevant checks did not run has a NULL score and the tier \"Not assessed\", with a reason — it is not clean, it is unknown. A clean result over fewer than half a framework's categories is reported as \"Partial\" rather than \"Strong\". A framework with no externally observable duty is \"Not assessable\" and is never scored. " +
    "Optionally narrow with `frameworks` (ids from list_compliance_frameworks) or `region`. " +
    "THESE ARE NOT AUDIT RESULTS, NOT A CERTIFICATION AND NOT LEGAL ADVICE. They are indicative readiness signals from public-surface evidence, and every framework also carries a note on what it requires that no external scan can see — consent records, impact assessments, retention schedules, vendor agreements, board governance. Say so when you relay them. " +
    "It is free and passive, with the same disclosure as scan_domain: no port scanning and no exploit testing, but it does request well-known paths, resolve common subdomains and read the TLS certificate directly. Prefer a domain you own or are authorised to assess.",
  inputSchema: {
    domain: domainArg.domain,
    frameworks: z
      .array(z.string().min(1).max(64))
      .optional()
      .describe("Optional framework ids to restrict the assessment to, e.g. [\"gdpr\", \"uk_gdpr\", \"iso27001\"]. Get valid ids from list_compliance_frameworks. An unknown id is reported as an error rather than silently ignored."),
    region: z
      .enum(["canada", "united_states", "eu_eea", "united_kingdom", "asia_pacific", "africa", "global"])
      .optional()
      .describe("Optional region to restrict the assessment to. Combines with `frameworks` if both are given."),
  },
};

export const ALL_TOOL_NAMES: string[] = [SCAN_TOOL, ...CHECK_TOOLS, REPORT_TOOL, FRAMEWORKS_TOOL, COMPLIANCE_TOOL].map((t) => t.name);
