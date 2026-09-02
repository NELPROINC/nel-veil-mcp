/**
 * The NEL VEIL API client.
 *
 * Deliberately tiny, and deliberately dumb: it holds no scanning logic, no tier
 * logic, and no notion of what is or is not allowed. Every one of those
 * decisions is made server-side, where it cannot be edited by whoever installed
 * this package. An MCP server runs on the user's own machine — treating anything
 * it enforces locally as a security control would be a mistake.
 *
 * It also sends NO identity: no API key, no email, no fingerprint. That is not
 * an omission, it is the point. The free surface is rate-limited per IP, and
 * supplying an email is what moves a caller off the strict anonymous path onto a
 * per-address allowance. Sending none keeps every user on the tightest limit and
 * means this package never collects a personal detail it has no need for.
 */

export interface NelClientOptions {
  /** Override for local development. Defaults to production. */
  baseUrl?: string;
  timeoutMs?: number;
}

export const DEFAULT_BASE_URL = "https://api.nelprofessional.com";
const DEFAULT_TIMEOUT_MS = 60_000;

export class NelApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string
  ) {
    super(message);
    this.name = "NelApiError";
  }
}

export class NelClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(opts: NelClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? process.env.NEL_API_URL ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          accept: "application/json",
          // Attributable, and versioned, so NEL can see MCP traffic distinctly
          // in its own logs without identifying the person behind it.
          "user-agent": "nel-veil-mcp",
          ...(init?.body ? { "content-type": "application/json" } : {}),
          ...(init?.headers ?? {}),
        },
      });

      const text = await res.text();
      let body: any;
      try {
        body = text ? JSON.parse(text) : {};
      } catch {
        body = { error: text.slice(0, 200) };
      }

      if (!res.ok) {
        // 429 is the common one and deserves an actionable message rather than a
        // stack trace: the caller is not broken, they are early.
        if (res.status === 429) {
          throw new NelApiError(
            "Rate limit reached for this network. The free tier allows a limited number of checks per minute — wait about a minute and try again.",
            429,
            "RATE_LIMITED"
          );
        }
        if (res.status === 404) {
          throw new NelApiError(
            body?.error ?? "Not found. This check may not be available.",
            404,
            body?.code
          );
        }
        throw new NelApiError(
          body?.error ?? body?.message ?? `Request failed (HTTP ${res.status})`,
          res.status,
          body?.code
        );
      }
      return body as T;
    } catch (err: any) {
      if (err instanceof NelApiError) throw err;
      if (err?.name === "AbortError") {
        throw new NelApiError("The check timed out. The target may be slow or unreachable.", 504);
      }
      throw new NelApiError(`Could not reach the NEL VEIL API: ${err?.message ?? err}`, 502);
    } finally {
      clearTimeout(timer);
    }
  }

  listChecks() {
    return this.request<{ checks: string[]; tier: string; footer: Footer }>("/api/v1/mcp/checks");
  }

  runCheck(check: string, domain: string) {
    return this.request<CheckResponse>(
      `/api/v1/mcp/check/${encodeURIComponent(check)}?domain=${encodeURIComponent(domain)}`
    );
  }

  runScan(domain: string) {
    return this.request<ScanResponse>("/api/v1/mcp/scan", {
      method: "POST",
      body: JSON.stringify({ domain }),
    });
  }

  getReport(scanId: string) {
    return this.request<unknown>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
  }

  listFrameworks() {
    return this.request<FrameworksResponse>("/api/v1/mcp/frameworks");
  }

  runCompliance(body: { domain: string; frameworks?: string[]; region?: string }) {
    return this.request<ComplianceResponse>("/api/v1/mcp/compliance", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }
}

export interface Footer {
  tier: string;
  note: string;
  learnMore: string;
}

export interface Finding {
  code?: string;
  title?: string;
  severity?: string;
  description?: string;
  evidence?: unknown;
  [k: string]: unknown;
}

export interface CheckResponse {
  check: string;
  module: string;
  domain: string;
  status: string;
  score: number;
  findings: Finding[];
  footer: Footer;
}

export interface ScanResponse {
  domain: string;
  durationMs: number;
  modulesAssessed: number;
  modules: Array<{ module: string; status: string; score: number; findingCount: number }>;
  findings: Finding[];
  tierProof: { requested: string[]; allowed: string[]; activeAttempted: string[] };
  footer: Footer;
}

export interface CatalogFramework {
  id: string;
  name: string;
  fullName: string;
  jurisdiction: string;
  region: string;
  regionLabel: string;
  area: string;
  priority: string;
  authority: string;
  /** false = no technical duty an external scan could evidence; never scored. */
  assessable: boolean;
  observableCategories: string[];
  notAssessable: string;
}

export interface FrameworksResponse {
  total: number;
  assessable: number;
  regions: Array<{ region: string; label: string; frameworks: CatalogFramework[] }>;
  footer: Footer;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  jurisdiction: string;
  region: string;
  area: string;
  priority: string;
  /** null when the scan produced no evidence for this framework. */
  score: number | null;
  tier: string;
  /** "9/16" — how many of the categories this framework relies on were observed. */
  coverage: string;
  unobserved: string[];
  mappedFindingCount: number;
  reason: string | null;
  notAssessable: string;
}

export interface ComplianceResponse {
  domain: string;
  durationMs: number;
  modulesAssessed: number;
  observedCategories: string[];
  stats: { total: number; assessed: number; notAssessed: number; notAssessable: number };
  frameworks: ComplianceFramework[];
  findings: Array<{ code: string; title: string; severity: string; impact: string; frameworks: string[] }>;
  tierProof: { requested: string[]; allowed: string[]; activeAttempted: string[] };
  footer: Footer;
}
