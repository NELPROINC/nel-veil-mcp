# NEL VEIL MCP — free domain security checks for AI agents

Ask your agent *"can someone spoof email from example.com?"* and get a real answer in about ten seconds.

NEL VEIL MCP gives any MCP-compatible agent **seven tools** for checking a domain's public security posture: email spoofing (DMARC/SPF/DKIM), TLS weaknesses, HTTP security headers, publicly exposed files, subdomain-takeover risk, a combined scan, and retrieval of an earlier scan.

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

It prints a ready line **to stderr** — something like `nel-veil-mcp 0.1.2 ready — 7 tools, free passive tier.` — and then waits for JSON-RPC on stdin. That is correct: it is a stdio server, not a CLI, and stdout carries the protocol, so nothing else is ever written there.

Requires Node 18 or newer.

---

## 30 seconds: is your domain spoofable?

After installing, ask your agent:

> Check if example.com can be email-spoofed.

It calls `check_email_spoofing`. Real output for `example.com` at the time of writing:

```
Check if a domain can be email-spoofed — example.com
Score: 100/100 (done)

2 findings:
  [LOW] DMARC has no reporting address (rua/ruf), you have no visibility into spoofing
  [LOW] DKIM key may be 1024-bit (weak), 2048-bit recommended

Free passive check — public information only, no intrusive probing. Active scanning
(ports, API probing, exploit demonstrations) requires verified domain ownership and
runs only at nelprofessional.com.
More: https://www.nelprofessional.com/mcp
```

That domain is in good shape. The finding people are most often surprised by is a DMARC policy of `p=none` — it looks configured, monitors everything, and blocks nothing.

---

## Tools

| Tool | Answers |
|---|---|
| `check_email_spoofing` | Can someone send email that appears to come from this domain? (DMARC/SPF/DKIM) |
| `check_tls` | Does this domain's TLS have known weaknesses? (Qualys SSL Labs grade — see the note below) |
| `check_security_headers` | Does this site send the headers that protect visitors in the browser? |
| `check_exposed_files` | Is this domain publicly serving files it should not be? |
| `check_subdomain_takeover` | Are there DNS records pointing at services someone else could claim? |
| `scan_domain` | All of the above at once, with a per-module score. |
| `get_scan_report` | Retrieve a scan already run at nelprofessional.com, by its `scn_…` id. |

Each returns a 0–100 score plus specific findings you can act on.

---

## What this sends — stated plainly

Being precise here matters more than sounding safe, because this is the paragraph you rely on when deciding whether you may point a tool at someone else's domain.

**No tool here does port scanning or exploit testing.** Those are genuinely intrusive, they need the domain owner's permission, and they are deliberately not exposed over MCP at all.

**But "passive" is not the same as "invisible", and two tools do more than read public records:**

- **`check_tls` is not passive.** It queries **Qualys SSL Labs**, which performs its own *active* TLS assessment of the target from Qualys's infrastructure (reusing a recent cached result when Qualys has one). NEL sends no probe itself, but running this does cause the target to be actively tested by a third party. It returns the SSL Labs grade and known problems — Heartbleed, POODLE, RC4, deprecated protocols, weak forward secrecy, certificate chain issues. It does **not** report certificate expiry, issuer, or hostname validity.
- **`check_subdomain_takeover` is not DNS-only.** It resolves a small fixed list of common subdomain names and makes one HTTPS request to any that point at a known cloud host. It never claims or modifies anything.
- **`check_exposed_files`** requests a small fixed list of well-known paths (`.env`, `.git/config` and similar). It never brute-forces or fuzzes — the list does not grow or adapt — but these are paths a crawler would not request, so they are recognisable in a target's logs as a security check.
- **`scan_domain`** runs all of the above, and additionally checks whether common admin panels (`/phpmyadmin/`, `/manager/html`) are publicly reachable.

Everything above is information the domain publishes. None of it attacks anything. But it is more than ordinary crawling, so prefer running it against a domain you own or are authorised to assess.

Active scanning — port exposure, API probing, proof-of-concept checks — lives at [nelprofessional.com](https://www.nelprofessional.com), behind DNS-TXT proof that you control the domain. That is the right place for it, because a human proves ownership once and NEL can stand behind the result.

**Rate limits.** Ten single checks and three full scans per minute, per IP address. If you hit it, wait a minute.

**Privacy.** This package sends no API key, no email address, and no account identifier. Each request carries the domain you asked about and a `nel-veil-mcp` user-agent. Note that, like any HTTP service, NEL sees the IP the request came from — it is what the rate limit is keyed on.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `NEL_API_URL` | `https://api.nelprofessional.com` | Point at a self-hosted NEL backend. Only needed for local development. |

---

## Development

These steps need the **git repository**, not the published npm package — the tarball ships only `dist/`, so `src/` and `scripts/` are not in it.

```bash
npm install
npm run build
node scripts/mcp-smoke.mjs example.com
```

`scripts/mcp-smoke.mjs` launches the built server exactly as `npx` would, performs the MCP handshake, lists the tools and calls one for real — so it catches transport and schema problems a unit test would not.

---

## About NEL VEIL

NEL VEIL is the security scanner behind [NEL Professional](https://www.nelprofessional.com), a marketplace connecting organisations with verified cybersecurity professionals. The same modules that power this MCP server power the scans on the site.

Full documentation: [nelprofessional.com/mcp](https://www.nelprofessional.com/mcp)

---

## License

MIT — see [LICENSE](LICENSE).
