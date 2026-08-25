# NEL VEIL MCP — free passive security scanning for AI agents

Ask your agent *"can someone spoof email from stripe.com?"* and get a real answer in about ten seconds.

NEL VEIL MCP gives any MCP-compatible agent seven tools for checking a domain's public security posture: email spoofing (DMARC/SPF/DKIM), TLS and certificate expiry, HTTP security headers, publicly exposed files, and subdomain-takeover risk.

**Free. No API key. No signup.**

---

## Install

**Claude Code** — one command:

```bash
claude mcp add nel-veil -- npx -y nel-veil-mcp
```

**Any MCP client** — add this to your config file:

```json
{
  "mcpServers": {
    "nel-veil": {
      "command": "npx",
      "args": ["-y", "nel-veil-mcp"]
    }
  }
}
```

**Run it directly**, to check it works:

```bash
npx -y nel-veil-mcp
```

It should print `nel-veil-mcp 0.1.0 ready — 7 tools, free passive tier.` and then wait for JSON-RPC on stdin. That is correct; it is a stdio server, not a CLI.

Requires Node 18 or newer.

---

## 30 seconds: is your domain spoofable?

After installing, ask your agent:

> Check if example.com can be email-spoofed.

It calls `check_email_spoofing` and answers with something like:

```
Check if a domain can be email-spoofed — example.com
Score: 45/100 (done)

3 findings:
  [HIGH] No DMARC record found — anyone can send mail as this domain
  [MEDIUM] SPF record uses ~all (softfail) rather than -all
  [INFO] No DKIM selector found at common names

Free passive check — public information only, no intrusive probing.
```

A DMARC policy of `p=none` is the one people are most often surprised by: it looks configured, monitors everything, and blocks nothing.

---

## Tools

| Tool | Answers |
|---|---|
| `check_email_spoofing` | Can someone send email that appears to come from this domain? (DMARC/SPF/DKIM) |
| `check_tls` | Is HTTPS set up correctly, and when does the certificate expire? |
| `check_security_headers` | Does this site send the headers that protect visitors in the browser? |
| `check_exposed_files` | Is this domain publicly serving files it should not be? |
| `check_subdomain_takeover` | Are there DNS records pointing at services someone else could claim? |
| `scan_domain` | Everything above at once — full passive posture scan with a per-module score. |
| `get_scan_report` | Retrieve a scan already run at nelprofessional.com, by its `scn_…` id. |

Each returns a 0–100 score plus specific findings you can act on.

---

## What this does and does not do

**It is passive.** Every check is built from information the domain already publishes: public DNS records and ordinary HTTP requests, the same things any web crawler sees. It is safe to run against a domain you do not own — a vendor you are evaluating, a partner, an acquisition target.

**It is not a penetration test.** There is no port scanning, no endpoint enumeration, no brute forcing, and no exploit testing here. Those are *active* techniques: they send traffic a target would reasonably call intrusive, and running them against someone else's infrastructure without permission is not something an open MCP server should make easy.

So active scanning is deliberately absent from this package rather than gated behind a key. NEL VEIL does offer it — at [nelprofessional.com](https://www.nelprofessional.com), after you have proved you control the domain via a DNS TXT record. That is the right place for it, because a human proves ownership once and NEL can stand behind the result.

**Rate limits.** The free tier is limited per IP address: 10 single checks per minute, and 3 full scans per minute. If you hit it, wait a minute. There is no key to buy your way past it here.

**Privacy.** This package sends no API key, no email address, and no identifier of any kind. It transmits the domain you asked about and nothing else.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `NEL_API_URL` | `https://api.nelprofessional.com` | Point at a self-hosted NEL backend. Only needed for local development. |

---

## Development

```bash
npm install
npm run build
node scripts/mcp-smoke.mjs example.com
```

`scripts/mcp-smoke.mjs` launches the built server exactly as `npx` would, performs the MCP handshake, lists the tools and calls one for real — so it catches transport and schema problems that a unit test would not.

---

## About NEL VEIL

NEL VEIL is the security scanner behind [NEL Professional](https://www.nelprofessional.com), a marketplace connecting organisations with verified cybersecurity professionals. The same passive modules that power this MCP server power the scans on the site.

Full documentation: [nelprofessional.com/mcp](https://www.nelprofessional.com/mcp)

## Licence

MIT
