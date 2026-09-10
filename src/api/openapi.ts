import { CANONICAL_ORIGIN } from "./catalog.js";

// OpenAPI 3.1 service description for the dmarcheck public API.
// Kept in a single static object so it's trivial to diff when the surface
// changes. Schemas mirror `src/analyzers/types.ts` closely but do NOT import
// from it — OpenAPI schemas need to stay stable across TypeScript refactors.

const statusEnum = {
  type: "string",
  enum: ["pass", "warn", "fail", "info"],
} as const;

const validation = {
  type: "object",
  required: ["status", "message"],
  properties: {
    status: statusEnum,
    message: { type: "string" },
    learnAnchor: {
      type: "string",
      description:
        'Site-relative link to the learn-page section explaining how to fix this finding (e.g. "/learn/spf#lookup-limit"). Present only on a curated set of findings.',
    },
  },
} as const;

const validations = {
  type: "array",
  items: { $ref: "#/components/schemas/Validation" },
} as const;

// The four headers rateLimitHeaders() (src/rate-limit.ts) actually emits.
// rateLimitMiddleware attaches these to both the successful response and the
// 429 it returns on block, so every route it guards documents the same set —
// there is no Retry-After header (see #709).
const rateLimitResponseHeaders = {
  "X-RateLimit-Limit": {
    description: "Requests allowed in the current window.",
    schema: { type: "integer" },
  },
  "X-RateLimit-Remaining": {
    description: "Requests remaining in the current window.",
    schema: { type: "integer" },
  },
  "X-RateLimit-Window": {
    description: 'Window length, e.g. "60s".',
    schema: { type: "string" },
  },
  "X-RateLimit-Reset": {
    description:
      "Absolute epoch seconds at which the current window resets. Compute the wait as this value minus the current time.",
    schema: { type: "integer" },
  },
} as const;

export const OPENAPI_DOCUMENT = {
  openapi: "3.1.0",
  info: {
    title: "dmarcheck API",
    version: "1.0.0",
    summary:
      "DNS email-security scanner (DMARC, SPF, DKIM, BIMI, MTA-STS, MX, security.txt, TLS-RPT, DNSSEC, DANE).",
    description:
      "Public, unauthenticated API that grades a domain's email-security DNS posture. Rate-limited to 10 requests per minute per IP.",
    license: { name: "MIT", identifier: "MIT" },
    contact: { url: "https://github.com/schmug/dmarcheck" },
  },
  servers: [{ url: CANONICAL_ORIGIN, description: "Production" }],
  paths: {
    "/api/check": {
      get: {
        summary: "Scan a domain's email-security posture",
        description:
          "Runs all analyzers (DMARC, SPF, DKIM, BIMI, MTA-STS, MX, security.txt, TLS-RPT, DNSSEC, DANE) in parallel and returns a graded result. Results are cached for a short period.",
        operationId: "scanDomain",
        parameters: [
          {
            name: "domain",
            in: "query",
            required: true,
            description: "Domain to scan, lowercase, `[a-z0-9.-]` only.",
            schema: {
              type: "string",
              pattern: "^[a-z0-9.-]+$",
              maxLength: 253,
            },
            example: "dmarc.mx",
          },
          {
            name: "selectors",
            in: "query",
            required: false,
            description:
              "Comma-separated DKIM selectors to probe in addition to the built-in defaults.",
            schema: { type: "string", pattern: "^[A-Za-z0-9._,-]+$" },
            example: "google,selector1",
          },
          {
            name: "format",
            in: "query",
            required: false,
            description:
              "Force `json` or `csv`. Omit to get the JSON response.",
            schema: { type: "string", enum: ["json", "csv"] },
          },
        ],
        responses: {
          "200": {
            description: "Scan completed",
            headers: {
              "X-Cache": {
                description:
                  "`HIT` when the response was served from the SSE cache.",
                schema: { type: "string", enum: ["HIT"] },
              },
              ...rateLimitResponseHeaders,
            },
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ScanResult" },
              },
              "text/csv": {
                schema: {
                  type: "string",
                  description: "CSV export (UTF-8 BOM)",
                },
              },
            },
          },
          "400": {
            description: "Missing or invalid domain parameter",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "429": {
            description: "Rate limit exceeded (10 req/min per IP)",
            headers: rateLimitResponseHeaders,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
        },
      },
    },
    "/api/bulk-scan": {
      post: {
        summary: "Bulk scan up to 100 domains (Pro)",
        description:
          "Bearer-authenticated, Pro-only. The first 30 domains are scanned synchronously in batches of 10; the rest are added to the watchlist and picked up by the next nightly cron. Each entry is normalized via the same rules as `/api/check`; invalid entries are reported per-row rather than rejecting the whole batch.",
        operationId: "bulkScanDomains",
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["domains"],
                properties: {
                  domains: {
                    type: "array",
                    minItems: 1,
                    maxItems: 100,
                    items: { type: "string", maxLength: 253 },
                  },
                },
              },
              example: { domains: ["example.com", "another.org"] },
            },
          },
        },
        responses: {
          "200": {
            description: "Bulk scan dispatched",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/BulkScanResponse" },
              },
            },
          },
          "400": {
            description:
              "Malformed body, non-string entries, or `domains.length > 100`",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "401": {
            description: "Bearer token missing or invalid",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "402": {
            description: "Bearer is on the Free plan; upgrade required",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "429": {
            description: "Rate limit exceeded",
            headers: rateLimitResponseHeaders,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
        },
      },
    },
    "/api/domain/{name}/history": {
      get: {
        summary: "Scan history for a watched domain (Pro)",
        description:
          "Bearer-authenticated, Pro-only. Returns the most recent scan_history rows for a domain the bearer's user watches. 404 (not 403) if the bearer doesn't own the domain — existence is not revealed. Returns the same shape the dashboard history view consumes.",
        operationId: "getDomainHistory",
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: "name",
            in: "path",
            required: true,
            description: "Watched domain, lowercase, `[a-z0-9.-]` only.",
            schema: {
              type: "string",
              pattern: "^[a-z0-9.-]+$",
              maxLength: 253,
            },
            example: "example.com",
          },
          {
            name: "limit",
            in: "query",
            required: false,
            description:
              "How many scan records to return. Clamped to [1, 100]; defaults to 30. Non-integer values fall back to 30.",
            schema: {
              type: "integer",
              minimum: 1,
              maximum: 100,
              default: 30,
            },
          },
        ],
        responses: {
          "200": {
            description: "Scan history for the requested domain",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/DomainHistoryResponse" },
              },
            },
          },
          "400": {
            description: "Missing or invalid domain parameter",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "401": {
            description: "Bearer token missing or invalid",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "402": {
            description: "Bearer is on the Free plan; upgrade required",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "404": {
            description: "Bearer does not own a domain with this name",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
          "429": {
            description: "Rate limit exceeded",
            headers: rateLimitResponseHeaders,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
        },
      },
    },
    "/api/check/stream": {
      get: {
        summary: "Stream scan results as Server-Sent Events",
        description:
          "Emits a `protocol` event for each analyzer as it completes, then a `done` event with header/footer HTML fragments. Used by the web UI for progressive rendering.",
        operationId: "scanDomainStream",
        parameters: [
          {
            name: "domain",
            in: "query",
            required: true,
            schema: { type: "string", pattern: "^[a-z0-9.-]+$" },
          },
          {
            name: "selectors",
            in: "query",
            required: false,
            schema: { type: "string" },
          },
        ],
        responses: {
          "200": {
            description: "SSE stream",
            content: {
              "text/event-stream": {
                schema: {
                  type: "string",
                  description:
                    "Events: `protocol` (per-analyzer HTML fragment) and `done` (final header/footer HTML).",
                },
              },
            },
          },
        },
      },
    },
    "/check": {
      get: {
        summary: "Human-facing scan endpoint (multi-format)",
        description:
          "Same scan as `/api/check` but content-negotiated. Defaults to HTML; returns JSON with `Accept: application/json`, CSV with `format=csv`, and markdown with `Accept: text/markdown`.",
        operationId: "scanDomainNegotiated",
        parameters: [
          {
            name: "domain",
            in: "query",
            required: true,
            schema: { type: "string", pattern: "^[a-z0-9.-]+$" },
          },
          {
            name: "selectors",
            in: "query",
            required: false,
            schema: { type: "string" },
          },
          {
            name: "format",
            in: "query",
            required: false,
            schema: { type: "string", enum: ["json", "csv", "md"] },
          },
        ],
        responses: {
          "200": {
            description: "Scan result in the negotiated format",
            content: {
              "text/html": { schema: { type: "string" } },
              "application/json": {
                schema: { $ref: "#/components/schemas/ScanResult" },
              },
              "text/csv": { schema: { type: "string" } },
              "text/markdown": { schema: { type: "string" } },
            },
          },
        },
      },
    },
    "/badge": {
      get: {
        summary: "Embeddable email-security grade badge (SVG)",
        description:
          "Returns a shields.io-style SVG badge with the domain's current grade. Cached aggressively (1h max-age + 24h stale-while-revalidate) so a badge embedded in a README does not trigger a scan per viewer. Always returns SVG — invalid input renders an `invalid` badge with a 400 status; scan errors render an `error` badge with a 200 status so README embeds never break.",
        operationId: "gradeBadge",
        parameters: [
          {
            name: "domain",
            in: "query",
            required: true,
            description: "Domain to scan, lowercase, `[a-z0-9.-]` only.",
            schema: {
              type: "string",
              pattern: "^[a-z0-9.-]+$",
              maxLength: 253,
            },
            example: "dmarc.mx",
          },
        ],
        responses: {
          "200": {
            description: "SVG badge",
            content: {
              "image/svg+xml": {
                schema: { type: "string", format: "binary" },
              },
            },
          },
          "400": {
            description: "Invalid input (rendered as an SVG `invalid` badge)",
            content: {
              "image/svg+xml": {
                schema: { type: "string", format: "binary" },
              },
            },
          },
          "429": {
            description:
              "Rate limit exceeded (rendered as an SVG `rate limited` badge)",
            headers: rateLimitResponseHeaders,
            content: {
              "image/svg+xml": {
                schema: { type: "string", format: "binary" },
              },
            },
          },
        },
      },
    },
    "/health": {
      get: {
        summary: "Liveness probe",
        operationId: "health",
        responses: {
          "200": {
            description: "Service healthy",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["status", "timestamp"],
                  properties: {
                    status: { type: "string", enum: ["ok"] },
                    timestamp: { type: "string", format: "date-time" },
                  },
                },
              },
            },
          },
        },
      },
    },
    "/mcp": {
      post: {
        summary: "MCP streamable-HTTP transport (JSON-RPC 2.0)",
        description:
          "Stateless MCP endpoint. Each POST is a complete JSON-RPC 2.0 exchange. Implements the `scan_domain` tool — equivalent to `GET /api/check` but wrapped in the Model Context Protocol (2025-03-26). Rate-limited to 10 req/IP/60s. Discover via `/.well-known/mcp/server-card.json`.",
        operationId: "mcpRpc",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["jsonrpc", "method"],
                properties: {
                  jsonrpc: { type: "string", enum: ["2.0"] },
                  id: {
                    oneOf: [
                      { type: "string" },
                      { type: "number" },
                      { type: "null" },
                    ],
                  },
                  method: { type: "string" },
                  params: { type: "object" },
                },
              },
              examples: {
                initialize: {
                  summary: "Initialize handshake",
                  value: {
                    jsonrpc: "2.0",
                    id: 1,
                    method: "initialize",
                    params: {
                      protocolVersion: "2025-03-26",
                      clientInfo: { name: "my-agent", version: "1.0" },
                    },
                  },
                },
                toolsList: {
                  summary: "List available tools",
                  value: { jsonrpc: "2.0", id: 2, method: "tools/list" },
                },
                scanDomain: {
                  summary: "Call scan_domain tool",
                  value: {
                    jsonrpc: "2.0",
                    id: 3,
                    method: "tools/call",
                    params: {
                      name: "scan_domain",
                      arguments: { domain: "dmarc.mx" },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description:
              "JSON-RPC 2.0 response (always 200; errors use the JSON-RPC `error` field)",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["jsonrpc", "id"],
                  properties: {
                    jsonrpc: { type: "string", enum: ["2.0"] },
                    id: {
                      oneOf: [
                        { type: "string" },
                        { type: "number" },
                        { type: "null" },
                      ],
                    },
                    result: { type: "object" },
                    error: {
                      type: "object",
                      required: ["code", "message"],
                      properties: {
                        code: { type: "integer" },
                        message: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
          "204": {
            description:
              "Notification acknowledged (no JSON-RPC `id` — no response body per spec)",
          },
          "429": {
            description: "Rate limit exceeded (10 req/min per IP)",
            headers: rateLimitResponseHeaders,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Error" },
              },
            },
          },
        },
      },
    },
    "/.well-known/api-catalog": {
      get: {
        summary: "RFC 9727 API catalog",
        operationId: "apiCatalog",
        responses: {
          "200": {
            description: "Linkset describing this API",
            content: {
              "application/linkset+json": {
                schema: {
                  type: "object",
                  required: ["linkset"],
                  properties: {
                    linkset: { type: "array", items: { type: "object" } },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "dmk_<32-hex>",
        description:
          "API key generated at /dashboard/settings/api-keys. Sent as `Authorization: Bearer dmk_…`.",
      },
    },
    schemas: {
      Status: statusEnum,
      Validation: validation,
      Error: {
        type: "object",
        required: ["error"],
        properties: { error: { type: "string" } },
      },
      BulkScanResultEntry: {
        type: "object",
        required: ["domain", "status"],
        properties: {
          domain: { type: "string" },
          status: {
            type: "string",
            enum: ["scanned", "queued", "error", "invalid"],
          },
          grade: { type: "string" },
          error: { type: "string" },
        },
      },
      BulkScanResponse: {
        type: "object",
        required: ["accepted", "rejected", "results"],
        properties: {
          accepted: { type: "integer" },
          rejected: { type: "integer" },
          results: {
            type: "array",
            items: { $ref: "#/components/schemas/BulkScanResultEntry" },
          },
        },
      },
      DomainHistoryScan: {
        type: "object",
        required: ["scanned_at", "grade", "protocols"],
        properties: {
          scanned_at: {
            type: "integer",
            description: "Unix epoch seconds when the scan ran.",
          },
          grade: { type: "string" },
          protocols: {
            type: "object",
            // Per-row history persists pre-#40 rows that don't carry a
            // security_txt status. Leave it out of `required` so older
            // history payloads still validate; new scans include it.
            required: ["dmarc", "spf", "dkim", "bimi", "mta_sts"],
            additionalProperties: false,
            properties: {
              dmarc: {
                oneOf: [
                  { $ref: "#/components/schemas/Status" },
                  { type: "null" },
                ],
              },
              spf: {
                oneOf: [
                  { $ref: "#/components/schemas/Status" },
                  { type: "null" },
                ],
              },
              dkim: {
                oneOf: [
                  { $ref: "#/components/schemas/Status" },
                  { type: "null" },
                ],
              },
              bimi: {
                oneOf: [
                  { $ref: "#/components/schemas/Status" },
                  { type: "null" },
                ],
              },
              mta_sts: {
                oneOf: [
                  { $ref: "#/components/schemas/Status" },
                  { type: "null" },
                ],
              },
              security_txt: {
                oneOf: [
                  { $ref: "#/components/schemas/Status" },
                  { type: "null" },
                ],
              },
            },
          },
        },
      },
      DomainHistoryResponse: {
        type: "object",
        required: ["domain", "scans"],
        properties: {
          domain: { type: "string" },
          scans: {
            type: "array",
            items: { $ref: "#/components/schemas/DomainHistoryScan" },
          },
        },
      },
      DmarcResult: {
        type: "object",
        required: ["status", "record", "tags", "validations"],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          record: { type: ["string", "null"] },
          tags: {
            type: ["object", "null"],
            additionalProperties: { type: "string" },
          },
          validations,
        },
      },
      SpfIncludeNode: {
        type: "object",
        required: ["domain", "record", "mechanisms", "includes"],
        properties: {
          domain: { type: "string" },
          record: { type: ["string", "null"] },
          mechanisms: { type: "array", items: { type: "string" } },
          includes: {
            type: "array",
            items: { $ref: "#/components/schemas/SpfIncludeNode" },
          },
        },
      },
      SpfResult: {
        type: "object",
        required: [
          "status",
          "record",
          "lookups_used",
          "lookup_limit",
          "include_tree",
          "validations",
        ],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          record: { type: ["string", "null"] },
          lookups_used: { type: "integer" },
          lookup_limit: { type: "integer" },
          include_tree: {
            oneOf: [
              { $ref: "#/components/schemas/SpfIncludeNode" },
              { type: "null" },
            ],
          },
          validations,
        },
      },
      DkimSelectorResult: {
        type: "object",
        required: ["found"],
        properties: {
          found: { type: "boolean" },
          key_type: { type: "string" },
          key_bits: { type: "integer" },
          testing: { type: "boolean" },
          revoked: { type: "boolean" },
        },
      },
      DkimResult: {
        type: "object",
        required: ["status", "selectors", "validations"],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          selectors: {
            type: "object",
            additionalProperties: {
              $ref: "#/components/schemas/DkimSelectorResult",
            },
          },
          validations,
        },
      },
      BimiResult: {
        type: "object",
        required: ["status", "record", "tags", "validations"],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          record: { type: ["string", "null"] },
          tags: {
            type: ["object", "null"],
            additionalProperties: { type: "string" },
          },
          validations,
        },
      },
      MtaStsPolicy: {
        type: "object",
        required: ["version", "mode", "mx", "max_age"],
        properties: {
          version: { type: "string" },
          mode: { type: "string" },
          mx: { type: "array", items: { type: "string" } },
          max_age: { type: "integer" },
        },
      },
      MtaStsResult: {
        type: "object",
        required: ["status", "dns_record", "policy", "validations"],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          dns_record: { type: ["string", "null"] },
          policy: {
            oneOf: [
              { $ref: "#/components/schemas/MtaStsPolicy" },
              { type: "null" },
            ],
          },
          validations,
        },
      },
      SecurityTxtFields: {
        type: "object",
        required: [
          "contact",
          "expires",
          "encryption",
          "policy",
          "acknowledgments",
          "preferred_languages",
          "canonical",
          "hiring",
        ],
        properties: {
          contact: { type: "array", items: { type: "string" } },
          expires: { type: ["string", "null"] },
          encryption: { type: "array", items: { type: "string" } },
          policy: { type: "array", items: { type: "string" } },
          acknowledgments: { type: "array", items: { type: "string" } },
          preferred_languages: { type: ["string", "null"] },
          canonical: { type: "array", items: { type: "string" } },
          hiring: { type: "array", items: { type: "string" } },
        },
      },
      SecurityTxtResult: {
        type: "object",
        required: ["status", "source_url", "signed", "fields", "validations"],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          source_url: { type: ["string", "null"] },
          signed: { type: "boolean" },
          fields: {
            oneOf: [
              { $ref: "#/components/schemas/SecurityTxtFields" },
              { type: "null" },
            ],
          },
          validations,
        },
      },
      EmailProvider: {
        type: "object",
        required: ["name", "category"],
        properties: {
          name: { type: "string" },
          category: {
            type: "string",
            enum: ["security-gateway", "email-platform", "hosting"],
          },
        },
      },
      MxRecord: {
        type: "object",
        required: ["priority", "exchange"],
        properties: {
          priority: { type: "integer" },
          exchange: { type: "string" },
          provider: { $ref: "#/components/schemas/EmailProvider" },
        },
      },
      MxResult: {
        type: "object",
        required: ["status", "records", "providers", "validations"],
        properties: {
          status: { $ref: "#/components/schemas/Status" },
          records: {
            type: "array",
            items: { $ref: "#/components/schemas/MxRecord" },
          },
          providers: {
            type: "array",
            items: { $ref: "#/components/schemas/EmailProvider" },
          },
          validations,
        },
      },
      ScanSummary: {
        type: "object",
        required: [
          "mx_records",
          "mx_providers",
          "dmarc_policy",
          "spf_result",
          "spf_lookups",
          "dkim_selectors_found",
          "bimi_enabled",
          "mta_sts_mode",
        ],
        properties: {
          mx_records: { type: "integer" },
          mx_providers: { type: "array", items: { type: "string" } },
          dmarc_policy: { type: ["string", "null"] },
          spf_result: { $ref: "#/components/schemas/Status" },
          spf_lookups: { type: "string" },
          dkim_selectors_found: { type: "integer" },
          bimi_enabled: { type: "boolean" },
          mta_sts_mode: { type: ["string", "null"] },
        },
      },
      ScoringFactor: {
        type: "object",
        required: ["protocol", "label", "effect"],
        properties: {
          protocol: {
            type: "string",
            enum: ["dmarc", "spf", "dkim", "bimi", "mta_sts"],
          },
          label: { type: "string" },
          effect: { type: "number" },
        },
      },
      Recommendation: {
        type: "object",
        required: ["priority", "protocol", "title", "description", "impact"],
        properties: {
          priority: { type: "integer", enum: [1, 2, 3] },
          protocol: {
            type: "string",
            enum: ["dmarc", "spf", "dkim", "bimi", "mta_sts"],
          },
          title: { type: "string" },
          description: { type: "string" },
          impact: { type: "string" },
        },
      },
      GradeBreakdown: {
        type: "object",
        required: [
          "grade",
          "tier",
          "tierReason",
          "modifier",
          "modifierLabel",
          "factors",
          "recommendations",
          "protocolSummaries",
        ],
        properties: {
          grade: { type: "string" },
          tier: { type: "string" },
          tierReason: { type: "string" },
          modifier: { type: "number" },
          modifierLabel: { type: "string" },
          factors: {
            type: "array",
            items: { $ref: "#/components/schemas/ScoringFactor" },
          },
          recommendations: {
            type: "array",
            items: { $ref: "#/components/schemas/Recommendation" },
          },
          protocolSummaries: {
            type: "object",
            additionalProperties: {
              type: "object",
              required: ["status", "summary"],
              properties: {
                status: { $ref: "#/components/schemas/Status" },
                summary: { type: "string" },
              },
            },
          },
        },
      },
      ScanResult: {
        type: "object",
        required: [
          "domain",
          "timestamp",
          "grade",
          "breakdown",
          "summary",
          "protocols",
        ],
        properties: {
          domain: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
          grade: { type: "string" },
          breakdown: { $ref: "#/components/schemas/GradeBreakdown" },
          summary: { $ref: "#/components/schemas/ScanSummary" },
          protocols: {
            type: "object",
            required: [
              "mx",
              "dmarc",
              "spf",
              "dkim",
              "bimi",
              "mta_sts",
              "security_txt",
            ],
            properties: {
              mx: { $ref: "#/components/schemas/MxResult" },
              dmarc: { $ref: "#/components/schemas/DmarcResult" },
              spf: { $ref: "#/components/schemas/SpfResult" },
              dkim: { $ref: "#/components/schemas/DkimResult" },
              bimi: { $ref: "#/components/schemas/BimiResult" },
              mta_sts: { $ref: "#/components/schemas/MtaStsResult" },
              security_txt: { $ref: "#/components/schemas/SecurityTxtResult" },
            },
          },
        },
      },
    },
  },
} as const;

export const OPENAPI_JSON = JSON.stringify(OPENAPI_DOCUMENT);
