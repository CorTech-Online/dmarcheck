// Agent Skills discovery index — Cloudflare RFC v0.2.0.
// https://github.com/cloudflare/agent-skills-discovery-rfc
//
// Lists discoverable skills for AI agents. We expose one skill, `scan_domain`,
// in two formats: a prose SKILL.md (the format isitagentready.com itself uses)
// and a pointer at our OpenAPI 3.1 doc for machine-readable detail.
//
// The index is built lazily because Web Crypto digests are async and Workers
// don't allow top-level await. Cached per Worker instance after the first
// request.

import { MCP_SERVER_CARD } from "../mcp/handler.js";
import { CANONICAL_ORIGIN } from "./catalog.js";
import { OPENAPI_JSON } from "./openapi.js";

export const SCAN_DOMAIN_SKILL_MD = `# scan_domain

Run a DNS-only email security scan on a domain. Returns DMARC, SPF, DKIM,
BIMI, MTA-STS, and MX analysis with a letter grade and a list of issues.

No authentication required. The endpoint is rate-limited to 10 requests per
IP per 60 seconds.

## How to call

\`\`\`
GET https://dmarc.mx/api/check?domain=<domain>[&selectors=<sel1>,<sel2>]
Accept: application/json
\`\`\`

- \`domain\` — required. Lowercased; \`[a-z0-9.-]\` only.
- \`selectors\` — optional. Comma-separated DKIM selectors to probe.
  Restricted to \`[A-Za-z0-9._-]\`. Defaults to a small built-in list.

## Response shape

JSON. The \`score\` block carries \`grade\` (S/A+/A/B/C/D/F) and \`issues\`.
Each protocol block reports \`status\` (\`pass\` | \`warn\` | \`fail\` | \`info\`).
The full schema lives in the OpenAPI document at
\`https://dmarc.mx/openapi.json\` (component \`ScanResult\`).

## Streaming variant

Use \`GET /api/check/stream?domain=<domain>\` with
\`Accept: text/event-stream\` to receive per-protocol events as they
complete instead of waiting for the full scan.

## Bulk variant (Pro)

\`POST /api/bulk-scan\` with a bearer API key scans up to ${"`BULK_TOTAL_CAP`"} domains
per request. See the OpenAPI doc for the request/response shape.

## Errors

- \`400\` — invalid domain or selectors.
- \`429\` — rate limit exceeded. The response carries \`X-RateLimit-Reset\`
  (absolute epoch seconds — the Unix time at which the current window ends).
  Wait until \`X-RateLimit-Reset\` minus the current time before retrying.
- \`5xx\` — transient. Retry with exponential backoff.

## Examples

\`\`\`bash
curl -H 'Accept: application/json' 'https://dmarc.mx/api/check?domain=dmarc.mx'
\`\`\`

## MCP variant

The same scan is also available as an MCP tool via the streamable-HTTP
transport at \`https://dmarc.mx/mcp\`. Each POST is a complete JSON-RPC 2.0
exchange; the server is stateless. Supported methods: \`initialize\`,
\`tools/list\`, \`tools/call\` (tool: \`scan_domain\`).
Server card at \`https://dmarc.mx/.well-known/mcp/server-card.json\`.

## Related

- API catalog: \`https://dmarc.mx/.well-known/api-catalog\` (RFC 9727)
- OpenAPI 3.1: \`https://dmarc.mx/openapi.json\`
- Human docs: \`https://dmarc.mx/docs/api\`
`;

const SKILLS_SCHEMA_URL =
  "https://raw.githubusercontent.com/cloudflare/agent-skills-discovery-rfc/main/schemas/v0.2.0/index.json";

interface SkillEntry {
  name: string;
  type: string;
  description: string;
  url: string;
  sha256: string;
}

interface SkillsIndex {
  $schema: string;
  skills: SkillEntry[];
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const cache = new Map<string, string>();

export async function getAgentSkillsIndexJson(
  origin: string = CANONICAL_ORIGIN,
): Promise<string> {
  const cached = cache.get(origin);
  if (cached) return cached;

  const [skillSha, openapiSha, mcpCardSha] = await Promise.all([
    sha256Hex(SCAN_DOMAIN_SKILL_MD),
    sha256Hex(OPENAPI_JSON),
    sha256Hex(MCP_SERVER_CARD),
  ]);

  const index: SkillsIndex = {
    $schema: SKILLS_SCHEMA_URL,
    skills: [
      {
        name: "scan_domain",
        type: "markdown",
        description:
          "Run a DNS-only DMARC/SPF/DKIM/BIMI/MTA-STS scan and return a graded report.",
        url: `${origin}/.well-known/agent-skills/scan-domain/SKILL.md`,
        sha256: skillSha,
      },
      {
        name: "scan_domain",
        type: "openapi",
        description:
          "OpenAPI 3.1 description of the scan API and related endpoints.",
        url: `${origin}/openapi.json`,
        sha256: openapiSha,
      },
      {
        name: "scan_domain",
        type: "mcp",
        description:
          "MCP streamable-HTTP tool — call scan_domain via JSON-RPC 2.0 at POST /mcp. This url serves the MCP server card (the POST transport lives at /mcp).",
        url: `${origin}/.well-known/mcp/server-card.json`,
        sha256: mcpCardSha,
      },
    ],
  };

  const json = JSON.stringify(index);
  cache.set(origin, json);
  return json;
}

// Test-only escape hatch — clears memoized indexes between cases.
export function _resetAgentSkillsCache(): void {
  cache.clear();
}
