import * as Sentry from "@sentry/cloudflare";
import { type Context, Hono } from "hono";
import { cors } from "hono/cors";
import { csrf } from "hono/csrf";
import { streamSSE } from "hono/streaming";
import { sweepWorkosRetries } from "./account/workos-retry.js";
import { dispatchPendingAlerts } from "./alerts/dispatcher.js";
import { validateUnsubscribeToken } from "./alerts/unsubscribe.js";
import type {
  BimiResult,
  DaneResult,
  DkimResult,
  DmarcResult,
  DnsblResult,
  DnssecResult,
  MtaStsResult,
  MxResult,
  ScanResult,
  SecurityTxtResult,
  SpfResult,
  TlsRptResult,
} from "./analyzers/types.js";
import {
  getAgentSkillsIndexJson,
  SCAN_DOMAIN_SKILL_MD,
} from "./api/agent-skills.js";
import { isValidGrade, renderBadgeSvg } from "./api/badge.js";
import {
  BULK_IN_BAND_CAP,
  isCapExceeded,
  processBulkScan,
} from "./api/bulk-scan.js";
import {
  AGENT_CARD_JSON,
  API_CATALOG_JSON,
  CANONICAL_ORIGIN,
} from "./api/catalog.js";
import { clampHistoryLimit, fetchDomainHistory } from "./api/history.js";
import { LLMS_TXT } from "./api/llms-txt.js";
import { OPENAPI_JSON } from "./api/openapi.js";
import { accessJwtMiddleware } from "./auth/access-jwt.js";
import { type BearerIdentity, resolveBearer } from "./auth/api-key.js";
import { authRoutes } from "./auth/routes.js";
import { stripeWebhookRoutes } from "./billing/routes.js";
import { getCachedScan, setCachedScan } from "./cache.js";
import { runDueRescans } from "./cron/rescan.js";
import { generateCsv } from "./csv.js";
import { dashboardRoutes } from "./dashboard/routes.js";
import { getDomainByUserAndName } from "./db/domains.js";
import { recordScan } from "./db/scans.js";
import { getPlanForUser } from "./db/subscriptions.js";
import {
  getMaxDomainsOverrideForUser,
  setEmailAlertsEnabled,
} from "./db/users.js";
import type { Env } from "./env.js";
import {
  handleInboundEmail,
  putPending,
  reserveLiveToken,
  streamInboxResult,
} from "./inbox/store.js";
import { generateToken, isValidToken } from "./inbox/tokens.js";
import { handleMcpRequest, MCP_SERVER_CARD } from "./mcp/handler.js";
import type { ProtocolId, ProtocolResult } from "./orchestrator.js";
import { scan, scanStreaming } from "./orchestrator.js";
import {
  checkRateLimit,
  getRateLimitConfig,
  type RateLimitResult,
  rateLimitHeaders,
} from "./rate-limit.js";
import { staticRoutes } from "./routes/static.js";
import { scrubSentryEvent } from "./sentry-scrub.js";
import { normalizeDomain } from "./shared/domain.js";
import { watchlistCapFor } from "./shared/limits.js";
import { parseScoringConfig } from "./shared/scoring-config.js";
import {
  renderApiDocs,
  renderBimiCard,
  renderDaneCard,
  renderDkimCard,
  renderDmarcCard,
  renderDnsblCard,
  renderDnssecCard,
  renderError,
  renderLandingPage,
  renderMtaStsCard,
  renderMxCard,
  renderReport,
  renderReportFooter,
  renderReportHeader,
  renderScoreBreakdown,
  renderScoringRubric,
  renderSecurityTxtCard,
  renderSpfCard,
  renderStreamingLoading,
  renderTlsRptCard,
} from "./views/html.js";
import { renderInboxScanPage, renderInboxVerdict } from "./views/inbox.js";
import {
  renderLearnBimi,
  renderLearnDane,
  renderLearnDkim,
  renderLearnDmarc,
  renderLearnDnssec,
  renderLearnHub,
  renderLearnMtaSts,
  renderLearnSecurityTxt,
  renderLearnSpf,
  renderLearnTlsRpt,
} from "./views/learn.js";
import { renderPrivacyPage } from "./views/legal.js";
import {
  renderApiDocsMarkdown,
  renderErrorMarkdown,
  renderLandingMarkdown,
  renderLearnHubMarkdown,
  renderMxHubMarkdown,
  renderMxProviderMarkdown,
  renderPricingMarkdown,
  renderPrivacyMarkdown,
  renderReportMarkdown,
  renderScoringRubricMarkdown,
} from "./views/markdown.js";
import { renderMxHub, renderMxProviderPage } from "./views/mx.js";
import { renderPricingPage } from "./views/pricing.js";
import { fireBulkScanWebhooks } from "./webhooks/triggers.js";

// Durable Object class for the atomic rate limiter (GHSA-v7qc-7qh8-h69g).
// Must be re-exported from the Worker entry module so the `RATE_LIMITER`
// binding in wrangler.toml can resolve its `class_name`.
export { RateLimiterDO } from "./rate-limit-do.js";

// The Hono app is exported for tests (which call `app.request(...)`).
// Runtime Workers use the Sentry-wrapped default export below, which adds
// cron (`scheduled`) alongside `fetch`.
export const app = new Hono<{ Bindings: Env }>();

// Set Sentry scope context for every request
app.use("*", async (c, next) => {
  const scope = Sentry.getCurrentScope();
  const domain = c.req.query("domain")?.trim().toLowerCase() || undefined;
  const format =
    c.req.query("format") ||
    (c.req.header("Accept")?.includes("application/json") ? "json" : "html");
  const selectors = c.req.query("selectors") || undefined;

  // Raw user input (not normalizeDomain) — shows what was actually typed, even for rejected requests
  if (domain) scope.setTag("domain", domain);
  scope.setTag("format", format);
  scope.setTag("path", c.req.path);
  scope.setContext("request", {
    selectors,
    method: c.req.method,
    path: c.req.path,
  });
  scope.setUser({
    ip_address: c.req.header("CF-Connecting-IP") || undefined,
  });

  await next();
});

// Cloudflare Access JWT enforcement for `*.workers.dev` preview-branch
// deploys. No-ops on the production custom domain (dmarc.mx). See
// src/auth/access-jwt.ts for the protected-host predicate and fail-CLOSED
// posture when ACCESS_AUD / ACCESS_TEAM_DOMAIN are missing.
app.use("*", accessJwtMiddleware());

// HSTS: 2 years + includeSubDomains. The 2-year max-age satisfies the
// hstspreload.org submission requirement, but `preload` is intentionally
// omitted — adding it is a one-way commitment that locks every current and
// future subdomain (including any short-lived `*.workers.dev` previews
// proxied behind a custom domain) into HTTPS forever. Submit to the preload
// list as a separate, deliberate change once we're confident.

// Content types that should be hidden from search engines. HTML is the opposite:
// it's the whole point of the site and must stay crawlable. Images/CSS/JS are
// skipped because noindex on subresources is a no-op for how Googlebot renders
// pages. XML (sitemap) and text/plain (robots.txt) need to stay crawlable.
const NOINDEX_CONTENT_TYPES = [
  "application/json",
  "application/manifest+json",
  "application/linkset+json",
  "application/openapi+json",
  "text/csv",
  "text/event-stream",
  "text/markdown",
];

// Link header (RFC 8288) pointing agents to discovery resources.
// Attached to HTML responses only — JSON/CSV/SSE consumers are already
// using the API directly.
const AGENT_DISCOVERY_LINK_HEADER = [
  '</.well-known/api-catalog>; rel="api-catalog"; type="application/linkset+json"',
  '</.well-known/agent-skills/index.json>; rel="https://agentskills.io/rel/index"; type="application/json"',
  // DNS-AID agent metadata contract — the rel URI is the tracked IETF draft.
  '</.well-known/agent.json>; rel="https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid"; type="application/json"',
  '</openapi.json>; rel="service-desc"; type="application/openapi+json"',
  '</docs/api>; rel="service-doc"; type="text/html"',
  '</health>; rel="status"',
].join(", ");

// Origins permitted to embed the HTML report in an iframe. Anything not listed
// here (including subdomains) is blocked by the `frame-ancestors` directive
// below. X-Frame-Options is intentionally NOT set — older browsers honor it
// over `frame-ancestors`, which would defeat this allowlist.
const EMBED_ALLOWED_ORIGINS = ["https://cortech.online"];

// Paths that skip Cloudflare Web Analytics beacon injection. Dashboard and
// auth pages can expose user-specific URL patterns (e.g. domain names in
// the path); we deliberately keep those out of analytics even though the
// beacon itself is cookieless.
const ANALYTICS_SKIP_PATH_PREFIXES = ["/dashboard", "/auth", "/webhooks"];

// Cloudflare Web Analytics tokens are 32-char lowercase hex. Guard against
// a misconfigured env var injecting arbitrary strings into HTML.
const CF_ANALYTICS_TOKEN_RE = /^[a-f0-9]{32}$/;

app.use("*", async (c, next) => {
  await next();
  c.res.headers.set("X-Content-Type-Options", "nosniff");
  c.res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  c.res.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  c.res.headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains",
  );

  const contentType = c.res.headers.get("content-type") ?? "";
  const isHtml = contentType.includes("text/html");
  if (isHtml) {
    const frameAncestors = ["'self'", ...EMBED_ALLOWED_ORIGINS].join(" ");
    // Per-request nonce eliminates 'unsafe-inline' from script-src. Scripts
    // with a matching nonce attribute execute; all others are blocked.
    const nonce = btoa(
      String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))),
    );
    c.res.headers.set(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors ${frameAncestors}`,
    );
    if (!c.res.headers.has("Link")) {
      c.res.headers.set("Link", AGENT_DISCOVERY_LINK_HEADER);
    }
    // Short edge cache so Cloudflare can absorb landing/scoring/report traffic
    // without hitting the Worker on every request. Browsers still revalidate.
    if (!c.res.headers.has("Cache-Control")) {
      c.res.headers.set(
        "Cache-Control",
        "public, max-age=0, s-maxage=300, stale-while-revalidate=600",
      );
    }

    // Inject nonce into all <script> tags (excluding JSON-LD data blocks which
    // are not executable JS and don't fall under script-src).  Combine with the
    // optional Cloudflare Analytics beacon injection to avoid reading the body
    // twice — HTML responses are buffered strings, never true streams.
    const token = (c.env as Env | undefined)?.CF_ANALYTICS_TOKEN;
    const path = c.req.path;
    const isAnalyticsEligible =
      token &&
      CF_ANALYTICS_TOKEN_RE.test(token) &&
      !ANALYTICS_SKIP_PATH_PREFIXES.some((p) => path.startsWith(p));
    let body = (await c.res.text()).replace(
      /<script(?!\s+type=["']application\/ld\+json)/g,
      `<script nonce="${nonce}"`,
    );
    if (isAnalyticsEligible) {
      const beacon = `<script defer nonce="${nonce}" src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token":"${token}"}'></script>`;
      body = body.replace("</body>", `${beacon}</body>`);
    }
    c.res = new Response(body, {
      status: c.res.status,
      statusText: c.res.statusText,
      headers: c.res.headers,
    });
  } else {
    // `frame-ancestors` does not inherit from `default-src`, so it must be
    // declared explicitly to keep JSON/CSV/SSE responses unframable.
    c.res.headers.set(
      "Content-Security-Policy",
      "default-src 'none'; frame-ancestors 'none'",
    );
  }

  // Keep the JSON API, CSV exports, the SSE stream, and the PWA manifest out
  // of Google's index. These showed up in Search Console as "Crawled - currently
  // not indexed" noise — no reason to spend crawl budget on them.
  if (NOINDEX_CONTENT_TYPES.some((t) => contentType.includes(t))) {
    c.res.headers.set("X-Robots-Tag", "noindex");
  }
});

// Safety net: capture any unhandled errors that bypass route catch blocks
app.onError((err, c) => {
  Sentry.captureException(err);
  const message = err instanceof Error ? err.message : "Internal error";
  const wantsJson =
    c.req.header("Accept")?.includes("application/json") ||
    c.req.query("format") === "json";
  if (wantsJson) {
    return c.json({ error: message }, 500);
  }
  return c.html(renderError(message), 500);
});

app.use("/api/*", cors());

// Auth routes (public) — login, WorkOS callback, logout
// Logout is state-changing, so it gets the same Origin/CSRF check as
// /dashboard/* even though it lives outside that path prefix.
app.use("/auth/logout", csrf());
app.route("/auth", authRoutes);

// Dashboard routes (auth enforced inside dashboardRoutes via requireAuth)
app.use("/dashboard/*", csrf());
app.route("/dashboard", dashboardRoutes);

// Local-only dashboard fixture preview. Lets a developer eyeball every
// scenario (current / fire / allGreen / firstRun / free / zero) without
// going through WorkOS. Self-gated on the absence of WORKOS_API_KEY:
// production always has it set, `wrangler dev` (without a .dev.vars file)
// does not. If a self-host operator does set up local secrets, they can
// still hit the route via .dev.vars omission of this single key.
app.get("/_dev/dashboard", async (c) => {
  const apiKey = (c.env as { WORKOS_API_KEY?: string } | undefined)
    ?.WORKOS_API_KEY;
  if (apiKey && apiKey.length > 0) return c.text("Not Found", 404);
  const {
    renderDashboardFixture,
    renderDashboardFixtureIndex,
    DASHBOARD_FIXTURE_NAMES,
  } = await import("./views/dashboard.js");
  const fixture = c.req.query("fixture");
  if (!fixture) return c.html(renderDashboardFixtureIndex());
  if (!DASHBOARD_FIXTURE_NAMES.includes(fixture as never)) {
    return c.text(
      `Unknown fixture. Pick one of: ${DASHBOARD_FIXTURE_NAMES.join(", ")}`,
      404,
    );
  }
  return c.html(renderDashboardFixture(fixture as never));
});

// Stripe webhook (public — signature-verified). Self-gates on
// isBillingEnabled so self-host deploys without Stripe env still boot.
app.route("/webhooks", stripeWebhookRoutes);

// Static assets, health check, and crawler-facing infrastructure (#661).
app.route("/", staticRoutes);

function markdownResponse(c: Context, body: string, status = 200) {
  return c.body(body, status as 200, {
    "Content-Type": "text/markdown; charset=utf-8",
  });
}

// Returns true when the client explicitly asked for markdown (via `?format=md`
// or an `Accept` header that lists `text/markdown` before `text/html`). HTML
// stays the default for browsers that send wildcards like `*/*`.
function wantsMarkdown(c: Context): boolean {
  const format = c.req.query("format");
  if (format === "md" || format === "markdown") return true;
  const accept = c.req.header("Accept");
  if (!accept) return false;
  const types = accept.toLowerCase().split(",");
  const mdIndex = types.findIndex((t) => t.trim().startsWith("text/markdown"));
  if (mdIndex === -1) return false;
  const htmlIndex = types.findIndex((t) => t.trim().startsWith("text/html"));
  // Agents that send `Accept: text/markdown` (and nothing else, or markdown
  // first) get markdown. Browsers that prefer HTML keep getting HTML.
  return htmlIndex === -1 || mdIndex < htmlIndex;
}

function getClientIp(c: Context): string {
  const cfIp = c.req.header("CF-Connecting-IP");
  if (cfIp) return cfIp;

  return "unknown";
}

// Resolves rate-limit identity + config for a request. Pro-authed bearers
// lift to the per-user bucket (60/hour). Everyone else — anonymous callers,
// bearers whose subscription isn't active, free-plan bearers — falls through
// to the per-IP anon bucket (10/60s). Free-authed keeps on IP on purpose: a
// free bearer hitting from two IPs gets two anon buckets, which matches what
// anonymous scanners already see and avoids making a free account worse than
// no account. Bearer identity is stashed on context so downstream handlers
// (/api/check scan-history persistence) can read it without re-verifying.
export async function resolveRateLimitScope(c: Context): Promise<{
  identity: string;
  config: ReturnType<typeof getRateLimitConfig>;
}> {
  const bearer = await resolveBearer(c);
  if (bearer) {
    c.set("bearer" as never, bearer);
    const db = (c.env as { DB?: D1Database }).DB;
    if (db) {
      const plan = await getPlanForUser(db, bearer.userId);
      if (plan === "pro") {
        return {
          identity: `user:${bearer.userId}`,
          config: getRateLimitConfig("pro"),
        };
      }
    }
  }
  return {
    identity: `ip:${getClientIp(c)}`,
    config: getRateLimitConfig("free"),
  };
}

type RateLimitBlockedResponder = (
  c: Context,
  result: RateLimitResult,
  headers: Record<string, string>,
) => Response | Promise<Response>;

export function rateLimitMiddleware(
  onBlocked: RateLimitBlockedResponder,
  // Optional per-route weight resolver (issue #619). Omitted → every request
  // costs 1 token, the historical behavior. Bulk-scan uses this to charge
  // proportional to its in-band scan count instead of counting as one request.
  weightFn?: (c: Context) => Promise<number>,
) {
  return async (c: Context, next: () => Promise<void>) => {
    const { identity, config } = await resolveRateLimitScope(c);
    const weight = weightFn ? await weightFn(c) : 1;
    // The Durable Object RPC is awaited end-to-end, so the counter is durably
    // updated before the decision is used — no deferred write to drain.
    // `c.env` is always present at runtime; the optional chain keeps the
    // limiter working in lightweight unit tests that call `app.request(path)`
    // without an env (falls back to the in-memory limiter).
    const result = await checkRateLimit(
      identity,
      config,
      c.env?.RATE_LIMITER,
      weight,
    );

    const headers = rateLimitHeaders(result);

    if (!result.allowed) {
      return onBlocked(c, result, headers);
    }

    await next();
    // ⚡ Bolt Optimization: Use for...in instead of Object.entries() on hot paths.
    // Avoids allocating an array of key-value tuples for headers on every request,
    // reducing GC pressure for high-traffic middleware.
    for (const key in headers) {
      c.res.headers.set(key, headers[key]);
    }
  };
}

function blockedMessage(result: RateLimitResult): string {
  const waitSec = Math.max(1, result.resetAt - Math.floor(Date.now() / 1000));
  return `Rate limit exceeded. Try again in ${waitSec} seconds.`;
}

// Rate-limit weight for /api/bulk-scan (issue #619): the number of distinct
// valid domains in the request body, capped at BULK_IN_BAND_CAP — mirrors the
// normalize+dedupe step `processBulkScan` runs before dispatching in-band
// scans, without its DB-backed watchlist-cap lookup, so the charge is known
// before the expensive work runs. `c.req.json()` is cached by Hono, so the
// handler's own body parse below reuses this same parse rather than
// re-reading the request stream. Malformed/absent bodies fall back to the
// default weight of 1 — the handler's own validation still rejects them.
async function bulkScanWeight(c: Context): Promise<number> {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return 1;
  }
  const rawDomains = (body as { domains?: unknown })?.domains;
  if (!Array.isArray(rawDomains)) return 1;
  const distinct = new Set<string>();
  for (const d of rawDomains) {
    if (typeof d !== "string") continue;
    const trimmed = d.trim();
    if (!trimmed) continue;
    const normalized = normalizeDomain(trimmed);
    if (normalized) distinct.add(normalized);
  }
  return Math.min(Math.max(distinct.size, 1), BULK_IN_BAND_CAP);
}

// Rate limit scan endpoints (not the landing page)
app.use(
  "/check",
  rateLimitMiddleware((c, result, headers) => {
    const format = c.req.query("format");
    const wantsJson =
      format === "json" || c.req.header("Accept")?.includes("application/json");

    if (wantsJson || format === "csv") {
      return c.json(
        { error: blockedMessage(result) },
        { status: 429, headers },
      );
    }
    return c.html(
      renderError(
        "Rate limit exceeded. Please wait a minute before scanning again.",
      ),
      { status: 429, headers },
    );
  }),
);

app.use(
  "/check/score",
  rateLimitMiddleware((_c, _result, headers) =>
    _c.html(
      renderError(
        "Rate limit exceeded. Please wait a minute before scanning again.",
      ),
      { status: 429, headers },
    ),
  ),
);

// Test-email address issuance (issue #417). Minting a token is also minting a
// routable address, so it gets the same per-identity limiter as a scan.
app.use(
  "/check/email",
  rateLimitMiddleware((_c, _result, headers) =>
    _c.html(
      renderError(
        "Rate limit exceeded. Please wait a minute before requesting another test address.",
      ),
      { status: 429, headers },
    ),
  ),
);

app.use(
  "/api/check",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// Bulk scan also runs N analyzers in-band per request — same rate-limit
// posture as /api/check (Pro bearer → user bucket; everyone else → IP), but
// charged proportionally to the in-band scan count rather than 1 token per
// request (issue #619), since a 30-domain request fans out ~30x the outbound
// DNS/fetch of a single scan.
app.use(
  "/api/bulk-scan",
  rateLimitMiddleware(
    (c, result, headers) =>
      c.json({ error: blockedMessage(result) }, { status: 429, headers }),
    bulkScanWeight,
  ),
);

// Per-domain API endpoints (currently only /api/domain/:name/history). Path
// prefix instead of exact-match so future per-domain endpoints inherit the
// same limiter without re-wiring. Hono matches `/api/domain/*` after the
// exact-match routes above, so /api/check and /api/bulk-scan aren't affected.
// This middleware is what populates `c.get("bearer")` via resolveRateLimitScope.
app.use(
  "/api/domain/*",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// The SSE streaming endpoint fans out ~50 DNS lookups per request and is
// bypassed by the `/api/check` middleware above (Hono matches exact paths).
// Give it its own limiter so it cannot be used as a DNS amplification vector.
app.use(
  "/api/check/stream",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// Inbox result SSE stream (issue #417). Polls KV (no DNS fan-out), but give it
// its own limiter so it can't be opened en masse on one identity.
app.use(
  "/api/check/email/stream",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// Badge endpoint runs a full scan on cache miss, so it gets the same
// per-IP limiter as /api/check. Cloudflare edge caches the SVG response
// (1h max-age), so README-embedded badges collapse to a small number of
// origin hits regardless of view volume.
app.use(
  "/badge",
  rateLimitMiddleware((c, _result, headers) =>
    // Even rate-limit responses must be SVG so embeds don't render a JSON
    // blob in place of the badge. "rate limited" is a fallback grade.
    c.body(renderBadgeSvg({ grade: "rate limited", color: "#737373" }), {
      status: 429,
      headers: { ...headers, "Content-Type": "image/svg+xml; charset=utf-8" },
    }),
  ),
);

// MCP endpoint runs a full scan on cache miss — same per-IP budget as /api/check.
app.use(
  "/mcp",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

const protocolRenderers: Record<
  ProtocolId,
  (result: ProtocolResult) => string
> = {
  mx: (r) => renderMxCard(r as MxResult),
  dmarc: (r) => renderDmarcCard(r as DmarcResult),
  spf: (r) => renderSpfCard(r as SpfResult),
  dkim: (r) => renderDkimCard(r as DkimResult),
  bimi: (r) => renderBimiCard(r as BimiResult),
  mta_sts: (r) => renderMtaStsCard(r as MtaStsResult),
  security_txt: (r) => renderSecurityTxtCard(r as SecurityTxtResult),
  tls_rpt: (r) => renderTlsRptCard(r as TlsRptResult),
  dnssec: (r) => renderDnssecCard(r as DnssecResult),
  dane: (r) => renderDaneCard(r as DaneResult),
  dnsbl: (r) => renderDnsblCard(r as DnsblResult),
};

// Single chokepoint for env-derived scan inputs: the scoring rubric override
// and the optional Spamhaus DQS key (#587). Threading the key here (rather than
// at each route) keeps it on every scan path that warms the shared cache, so
// the DNSBL result is consistent regardless of which route ran the scan. The
// key is passed only to the analyzer's outbound query — never logged or cached.
function envScan(
  c: Context<{ Bindings: Env }>,
  domain: string,
  selectors: string[] = [],
): Promise<ScanResult> {
  return scan(
    domain,
    selectors,
    parseScoringConfig(c.env?.SCORING_CONFIG),
    undefined,
    c.env?.DNSBL_DQS_KEY,
  );
}

function tagScanResult(result: ScanResult): void {
  const scope = Sentry.getCurrentScope();
  scope.setTag("grade", result.grade);
  scope.setTag("dmarc.status", result.protocols.dmarc.status);
  scope.setTag("spf.status", result.protocols.spf.status);
  scope.setTag("dkim.status", result.protocols.dkim.status);
  scope.setTag("bimi.status", result.protocols.bimi.status);
  scope.setTag("mta_sts.status", result.protocols.mta_sts.status);
  // Optional access — older cached scans (pre-#40) may not include
  // security_txt. Drop the tag rather than crash the SSE replay.
  if (result.protocols.security_txt) {
    scope.setTag("security_txt.status", result.protocols.security_txt.status);
  }
}

app.get("/api/check/stream", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    return c.json({ error: "Missing or invalid domain parameter" }, 400);
  }

  const selectors = parseSelectors(c.req.query("selectors"));
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;

  return streamSSE(c, async (stream) => {
    Sentry.addBreadcrumb({
      category: "scan.start",
      message: domain,
      data: { domain, selectors },
      level: "info",
    });
    const cached = await getCachedScan(domain, selectors);
    Sentry.addBreadcrumb({
      category: cached ? "cache.hit" : "cache.miss",
      message: domain,
      data: { domain },
      level: "info",
    });

    if (cached) {
      tagScanResult(cached);
      // Derive the replay set from `protocolRenderers` keys, not a hand-listed
      // literal. `protocolRenderers` is `Record<ProtocolId, …>`, so adding a
      // protocol to the union forces a renderer key, which is iterated here —
      // no protocol can be silently dropped from the cache-hit path (#455).
      // Object insertion order matches the previous literal, so `done` still
      // comes last with no duplicate or reordered events.
      const protocolIds = Object.keys(protocolRenderers) as ProtocolId[];
      for (const id of protocolIds) {
        const protocolResult = cached.protocols[id];
        // Older cached scans (pre-#40) may lack security_txt; skip rather
        // than crashing the replay. Fresh scans always populate it.
        if (!protocolResult) continue;
        const html = protocolRenderers[id](protocolResult);
        await stream.writeSSE({
          event: "protocol",
          data: JSON.stringify({ id, html }),
        });
      }
      await stream.writeSSE({
        event: "done",
        data: JSON.stringify({
          grade: cached.grade,
          headerHtml: renderReportHeader(cached),
          footerHtml: renderReportFooter(cached),
        }),
      });

      // Mirror GET /api/check: persist on cache hit too so bearer scans of
      // watched domains update scan_history even within the 5-minute TTL.
      if (bearer) {
        persistBearerScanIfWatched(c, bearer.userId, domain, cached);
      }
      return;
    }

    const protocolWrites: Promise<unknown>[] = [];
    const result = await scanStreaming(
      domain,
      selectors,
      (id: ProtocolId, protocolResult: ProtocolResult) => {
        const html = protocolRenderers[id](protocolResult);
        const pending = stream.writeSSE({
          event: "protocol",
          data: JSON.stringify({ id, html }),
        });
        if (pending) protocolWrites.push(pending);
      },
      parseScoringConfig(c.env?.SCORING_CONFIG),
      undefined,
      c.env?.DNSBL_DQS_KEY,
    );
    await Promise.all(protocolWrites);

    tagScanResult(result);
    const pendingCacheWrite = setCachedScan(domain, selectors, result);
    if (pendingCacheWrite) {
      c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
    }

    if (bearer) {
      persistBearerScanIfWatched(c, bearer.userId, domain, result);
    }

    await stream.writeSSE({
      event: "done",
      data: JSON.stringify({
        grade: result.grade,
        headerHtml: renderReportHeader(result),
        footerHtml: renderReportFooter(result),
      }),
    });
  });
});

// Stream the verdict for a test-email token (issue #417). Mirrors
// /api/check/stream: emits a "waiting" state, polls KV server-side, pushes the
// parsed verdict when the message lands, then closes. An unknown/expired token
// yields a clean "closed" event — never a 500.
app.get("/api/check/email/stream", async (c) => {
  const token = c.req.query("token");
  if (!token || !isValidToken(token)) {
    return c.json({ error: "Missing or invalid token parameter" }, 400);
  }
  const kv = c.env?.INBOX_TOKENS;
  return streamSSE(c, async (stream) => {
    if (!kv) {
      await stream.writeSSE({
        event: "closed",
        data: JSON.stringify({ status: "unavailable" }),
      });
      return;
    }
    await streamInboxResult(stream, kv, token, {
      renderCard: renderInboxVerdict,
      rateLimiterNamespace: c.env?.RATE_LIMITER,
    });
  });
});

// Embeddable email-security badge for READMEs and dashboards. Always
// returns a 200 SVG (even for invalid input or scan errors) so a badge
// embed never renders as a broken image — error states are encoded into
// the badge text instead.
app.get("/badge", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  const svgHeaders = (): Record<string, string> => ({
    "Content-Type": "image/svg+xml; charset=utf-8",
    // 1h browser, 1h edge, generous SWR. Badges live on README pages —
    // they need to render fast and stay fresh-ish without re-scanning per
    // viewer. The scan itself is also cached for 5 minutes inside getCachedScan,
    // but that's a different layer; this header controls what GitHub
    // (and downstream image proxies like camo) see.
    "Cache-Control":
      "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
    // GitHub's image proxy (camo) won't show user-supplied SVGs unless
    // the response is a clean SVG with no embedded scripts. Our generator
    // emits no <script>, but reinforce with CSP.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
  });

  if (!domain) {
    return c.body(renderBadgeSvg({ grade: "invalid", color: "#737373" }), 400, {
      ...svgHeaders(),
    });
  }

  try {
    const cached = await getCachedScan(domain, []);
    const result = cached ?? (await envScan(c, domain, []));
    if (!cached) {
      const pendingCacheWrite = setCachedScan(domain, [], result);
      if (pendingCacheWrite) {
        c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
      }
    }
    const grade = isValidGrade(result.grade) ? result.grade : "unknown";
    return c.body(renderBadgeSvg({ grade }), 200, svgHeaders());
  } catch (err) {
    Sentry.captureException(err);
    return c.body(renderBadgeSvg({ grade: "error", color: "#737373" }), 200, {
      ...svgHeaders(),
      // Shorter cache on errors so a transient DNS failure doesn't lock
      // a domain into the error badge for an hour.
      "Cache-Control": "public, max-age=60",
    });
  }
});

// RFC 9727 API catalog — agents discover this via the Link header on HTML
// pages or by fetching a well-known URI directly.
app.get("/.well-known/api-catalog", (c) => {
  return c.body(API_CATALOG_JSON, 200, {
    "Content-Type": "application/linkset+json",
    "Cache-Control": "public, max-age=3600",
  });
});

// Agent Skills discovery index — Cloudflare RFC v0.2.0.
// https://github.com/cloudflare/agent-skills-discovery-rfc
app.get("/.well-known/agent-skills/index.json", async (c) => {
  const json = await getAgentSkillsIndexJson();
  return c.body(json, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/.well-known/agent-skills/scan-domain/SKILL.md", (c) => {
  return c.body(SCAN_DOMAIN_SKILL_MD, 200, {
    "Content-Type": "text/markdown; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

// DNS-AID agent metadata contract — draft-mozleywilliams-dnsop-dnsaid.
// Publishes the scan_domain capability at the HTTP layer; the matching DNS
// SVCB/TXT records under _agents.dmarc.mx are owner zone-admin work (#461).
app.get("/.well-known/agent.json", (c) => {
  return c.body(AGENT_CARD_JSON, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

// Remote MCP server — streamable-HTTP transport (POST only; stateless).
// Agents discover this endpoint via /.well-known/mcp/server-card.json and
// the agent-skills index.
app.post("/mcp", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      },
      400,
    );
  }
  return handleMcpRequest(body, {
    executionCtx: c.executionCtx,
    scoringConfig: parseScoringConfig(c.env?.SCORING_CONFIG),
    dnsblKey: c.env?.DNSBL_DQS_KEY,
  });
});

// SEP-1649 MCP server card — minimal shape, served before the RFC finalises.
app.get("/.well-known/mcp/server-card.json", (c) => {
  return c.body(MCP_SERVER_CARD, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/openapi.json", (c) => {
  return c.body(OPENAPI_JSON, 200, {
    "Content-Type": "application/openapi+json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/docs/api", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderApiDocsMarkdown());
  return c.html(renderApiDocs());
});

// llmstxt.org — vendor-neutral pointer to the canonical markdown URLs LLM
// clients should pull instead of scraping rendered HTML. See src/api/llms-txt.ts.
app.get("/llms.txt", (c) => {
  return c.body(LLMS_TXT, 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderLandingMarkdown());
  return c.html(renderLandingPage());
});

app.get("/scoring", (c) => {
  if (wantsMarkdown(c))
    return markdownResponse(
      c,
      renderScoringRubricMarkdown(parseScoringConfig(c.env?.SCORING_CONFIG)),
    );
  return c.html(renderScoringRubric(parseScoringConfig(c.env?.SCORING_CONFIG)));
});

app.get("/learn", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderLearnHubMarkdown());
  return c.html(renderLearnHub());
});
app.get("/learn/dmarc", (c) => c.html(renderLearnDmarc()));
app.get("/learn/spf", (c) => c.html(renderLearnSpf()));
app.get("/learn/dkim", (c) => c.html(renderLearnDkim()));
app.get("/learn/bimi", (c) => c.html(renderLearnBimi()));
app.get("/learn/mta-sts", (c) => c.html(renderLearnMtaSts()));
app.get("/learn/security-txt", (c) => c.html(renderLearnSecurityTxt()));
app.get("/learn/tls-rpt", (c) => c.html(renderLearnTlsRpt()));
app.get("/learn/dnssec", (c) => c.html(renderLearnDnssec()));
app.get("/learn/dane", (c) => c.html(renderLearnDane()));

app.get("/mx", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderMxHubMarkdown());
  return c.html(renderMxHub());
});
app.get("/mx/:slug", (c) => {
  const slug = c.req.param("slug");
  if (wantsMarkdown(c)) {
    const md = renderMxProviderMarkdown(slug);
    if (!md) return c.notFound();
    return markdownResponse(c, md);
  }
  const html = renderMxProviderPage(slug);
  if (!html) return c.notFound();
  return c.html(html);
});

app.get("/pricing", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderPricingMarkdown());
  return c.html(renderPricingPage());
});
app.get("/legal/privacy", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderPrivacyMarkdown());
  return c.html(renderPrivacyPage());
});

app.get("/api/check", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    return c.json({ error: "Missing or invalid domain parameter" }, 400);
  }

  const selectors = parseSelectors(c.req.query("selectors"));
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;

  try {
    Sentry.addBreadcrumb({
      category: "scan.start",
      message: domain,
      data: { domain, selectors },
      level: "info",
    });
    const cached = await getCachedScan(domain, selectors);
    Sentry.addBreadcrumb({
      category: cached ? "cache.hit" : "cache.miss",
      message: domain,
      data: { domain },
      level: "info",
    });
    const result = cached ?? (await envScan(c, domain, selectors));
    tagScanResult(result);
    if (!cached) {
      const pendingCacheWrite = setCachedScan(domain, selectors, result);
      if (pendingCacheWrite) {
        c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
      }
    }

    // Persist to scan_history only when the bearer's user already watches
    // this domain — mirrors the dashboard "Scan Now" contract and avoids
    // silently growing the watchlist on ad-hoc API requests.
    if (bearer) {
      persistBearerScanIfWatched(c, bearer.userId, domain, result);
    }

    if (c.req.query("format") === "csv") {
      return c.body(generateCsv(result), 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${domain}-email-security.csv"`,
        ...(cached ? { "X-Cache": "HIT" } : {}),
      });
    }
    if (cached) {
      return c.json(result, { headers: { "X-Cache": "HIT" } });
    }
    return c.json(result);
  } catch (err) {
    Sentry.captureException(err);
    const message = err instanceof Error ? err.message : "Internal error";
    return c.json({ error: message }, 500);
  }
});

// Bulk scan — Pro-only, bearer-authenticated. Up to BULK_TOTAL_CAP submitted;
// the first BULK_IN_BAND_CAP are scanned synchronously in batches and the
// rest are queued by inserting `domains` rows for the next cron pickup. Per-
// entry results let the caller distinguish scanned/queued/invalid/error.
app.post("/api/bulk-scan", async (c) => {
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;
  if (!bearer) {
    return c.json(
      {
        error:
          "Bearer token required. Generate one at /dashboard/settings/api-keys.",
      },
      401,
    );
  }
  const db = (c.env as { DB?: D1Database }).DB;
  if (!db) {
    return c.json({ error: "Database not configured" }, 500);
  }
  const [plan, override] = await Promise.all([
    getPlanForUser(db, bearer.userId),
    getMaxDomainsOverrideForUser(db, bearer.userId),
  ]);
  if (plan !== "pro") {
    return c.json(
      {
        error: "Bulk scan requires a Pro plan.",
        upgrade: `${CANONICAL_ORIGIN}/dashboard/billing/subscribe`,
      },
      402,
    );
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  const rawDomains = (body as { domains?: unknown })?.domains;
  if (!Array.isArray(rawDomains)) {
    return c.json({ error: "Body must be { domains: string[] }" }, 400);
  }
  if (!rawDomains.every((d): d is string => typeof d === "string")) {
    return c.json({ error: "All domains must be strings" }, 400);
  }

  const outcome = await processBulkScan({
    db,
    userId: bearer.userId,
    rawDomains,
    watchlistCap: watchlistCapFor(plan, override),
    scoringConfig: parseScoringConfig(c.env?.SCORING_CONFIG),
    dnsblKey: c.env?.DNSBL_DQS_KEY,
  });
  if (isCapExceeded(outcome)) {
    return c.json(
      {
        error: `Too many domains: ${outcome.submitted} > ${outcome.cap}`,
        cap: outcome.cap,
        in_band_cap: BULK_IN_BAND_CAP,
      },
      400,
    );
  }
  c.executionCtx.waitUntil(
    fireBulkScanWebhooks(db, bearer.userId, outcome.results, "bulk_api"),
  );
  return c.json(outcome);
});

// Scan history for a watched domain — Pro-only, bearer-authenticated. Thin
// wrapper around the same `getScanHistoryWithProtocols` helper the dashboard
// uses (src/dashboard/routes.ts `/dashboard/domain/:domain/history`), so the
// HTML view and the JSON API return the same rows. Check order is deliberate:
// auth → plan → domain validation → ownership. The ownership check must run
// after the plan check, otherwise a free-tier bearer could probe which
// domains belong to a pro user. It must also not echo anything about the
// domain on 404 — existence is not revealed.
app.get("/api/domain/:name/history", async (c) => {
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;
  if (!bearer) {
    return c.json(
      {
        error:
          "Bearer token required. Generate one at /dashboard/settings/api-keys.",
      },
      401,
    );
  }
  const db = (c.env as { DB?: D1Database }).DB;
  if (!db) {
    return c.json({ error: "Database not configured" }, 500);
  }
  const plan = await getPlanForUser(db, bearer.userId);
  if (plan !== "pro") {
    return c.json(
      {
        error: "Scan history requires a Pro plan.",
        upgrade: `${CANONICAL_ORIGIN}/dashboard/billing/subscribe`,
      },
      402,
    );
  }
  const domain = normalizeDomain(c.req.param("name"));
  if (!domain) {
    return c.json({ error: "Missing or invalid domain parameter" }, 400);
  }
  const limit = clampHistoryLimit(c.req.query("limit"));
  const resp = await fetchDomainHistory(db, bearer.userId, domain, limit);
  if (!resp) {
    return c.json({ error: "Domain not found" }, 404);
  }
  return c.json(resp);
});

// Fire-and-forget: look up the (user, domain) pair and record a scan_history
// row if the user watches this domain. The orchestrator result structure is
// the same shape consumed by dashboard "Scan Now".
function persistBearerScanIfWatched(
  c: Context,
  userId: string,
  domain: string,
  result: {
    grade: string;
    breakdown: { factors: unknown };
    protocols: unknown;
  },
): void {
  const db = (c.env as { DB?: D1Database }).DB;
  if (!db) return;
  const task = (async () => {
    const owned = await getDomainByUserAndName(db, userId, domain);
    if (!owned) return;
    await recordScan(db, {
      domainId: owned.id,
      grade: result.grade,
      scoreFactors: result.breakdown.factors,
      protocolResults: result.protocols,
    });
  })();
  c.executionCtx.waitUntil(task.catch(() => {}));
}

// Issue a one-time test-email address (issue #417). Rate-limited by the
// middleware above; additionally capped per identity on simultaneously-live
// tokens, enforced atomically via the RATE_LIMITER Durable Object (#618). ALL
// dynamic content is escaped by renderInboxScanPage.
app.get("/check/email", async (c) => {
  const kv = c.env?.INBOX_TOKENS;
  if (!kv) {
    return c.html(
      renderError("Test-email scanning isn't configured on this deployment."),
      503,
    );
  }

  // Reuse the rate-limit identity for the live-token cap. The middleware above
  // has already resolved + stashed any bearer; fall back to the client IP.
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;
  const identity = bearer ? `user:${bearer.userId}` : `ip:${getClientIp(c)}`;

  const token = generateToken();
  let reserved = false;
  try {
    reserved = await reserveLiveToken(
      kv,
      identity,
      token,
      undefined,
      c.env?.RATE_LIMITER,
    );
    if (reserved) {
      await putPending(kv, token);
    }
  } catch (err) {
    Sentry.captureException(err);
    return c.html(
      renderError("Couldn't allocate a test address. Please try again."),
      500,
    );
  }

  if (!reserved) {
    return c.html(
      renderError(
        "You have too many active test addresses. Wait for them to expire (30 minutes) before requesting another.",
      ),
      429,
    );
  }

  return c.html(renderInboxScanPage(token));
});

app.get("/check/score", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    return c.html(renderError("Please provide a valid domain name."), 400);
  }

  const selectors = parseSelectors(c.req.query("selectors"));

  try {
    Sentry.addBreadcrumb({
      category: "scan.start",
      message: domain,
      data: { domain, selectors },
      level: "info",
    });
    const result = await envScan(c, domain, selectors);
    tagScanResult(result);
    return c.html(renderScoreBreakdown(result));
  } catch (err) {
    Sentry.captureException(err);
    const message = err instanceof Error ? err.message : "Internal error";
    return c.html(renderError(message), 500);
  }
});

app.get("/check", async (c) => {
  const format = c.req.query("format");
  const wantsJson =
    format === "json" || c.req.header("Accept")?.includes("application/json");
  const wantsCsv = format === "csv";
  const wantsMd = !wantsJson && !wantsCsv && wantsMarkdown(c);

  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    // API clients still get a structured error. Browsers get a 302 to `/` so
    // Google doesn't report `/check` (bare) as a crawl error — the human intent
    // of landing on `/check` with no query is "I want to scan something".
    if (wantsJson) {
      return c.json({ error: "Missing or invalid domain parameter" }, 400);
    }
    if (wantsCsv) {
      return c.body("error,Missing or invalid domain parameter\n", 400, {
        "Content-Type": "text/csv; charset=utf-8",
      });
    }
    if (wantsMd) {
      return markdownResponse(
        c,
        renderErrorMarkdown("Missing or invalid domain parameter"),
        400,
      );
    }
    return c.redirect("/", 302);
  }

  const selectors = parseSelectors(c.req.query("selectors"));

  if (wantsMd) {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const cached = await getCachedScan(domain, selectors);
      const result = cached ?? (await envScan(c, domain, selectors));
      tagScanResult(result);
      if (!cached) {
        const pendingCacheWrite = setCachedScan(domain, selectors, result);
        if (pendingCacheWrite) {
          c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
        }
      }
      return markdownResponse(c, renderReportMarkdown(result));
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return markdownResponse(c, renderErrorMarkdown(message), 500);
    }
  }

  if (wantsJson) {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const result = await envScan(c, domain, selectors);
      tagScanResult(result);
      return c.json(result);
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return c.json({ error: message }, 500);
    }
  }

  if (wantsCsv) {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const result = await envScan(c, domain, selectors);
      tagScanResult(result);
      return c.body(generateCsv(result), 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${domain}-email-security.csv"`,
      });
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return c.json({ error: message }, 500);
    }
  }

  // Fetch from loading page or noscript fallback — do the actual scan
  if (c.req.header("X-Scan-Fetch") === "1" || c.req.query("_direct") === "1") {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const cached = await getCachedScan(domain, selectors);
      Sentry.addBreadcrumb({
        category: cached ? "cache.hit" : "cache.miss",
        message: domain,
        data: { domain },
        level: "info",
      });
      const result = cached ?? (await envScan(c, domain, selectors));
      tagScanResult(result);
      if (!cached) {
        const pendingCacheWrite = setCachedScan(domain, selectors, result);
        if (pendingCacheWrite) {
          c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
        }
      }
      return c.html(renderReport(result));
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return c.html(renderError(message), 500);
    }
  }

  // Default: return streaming loading page with skeleton cards, JS opens SSE.
  // Pass the sanitized selectors (re-joined from parseSelectors) rather than
  // the raw query string so the loader only ever sees validated characters.
  return c.html(renderStreamingLoading(domain, selectors.join(",")));
});

// Re-exported so long-standing callers (and tests) that import from
// `src/index.js` keep working. Canonical location: src/shared/domain.ts.
export { normalizeDomain };

// DKIM selector charset per RFC 6376 §3.1: sub-domain syntax, which is
// letters / digits / hyphens, with dot-separated labels. We also allow
// underscores since some providers use them in practice. Anything else
// is dropped silently — an invalid selector cannot match a real DKIM key.
const VALID_SELECTOR = /^[A-Za-z0-9._-]+$/;

// DoS guard (GHSA-6fqp-4vhc-59mf): every custom selector becomes one concurrent
// DNS lookup in analyzeDkim, so an unbounded attacker-supplied list is a DNS
// amplification vector charged against a single rate-limit token. Bound both
// the per-item length (RFC 1035 label limit) and the count. 16 custom selectors
// is generous given ~37 built-in COMMON_SELECTORS. parseSelectorsFromArray in
// src/mcp/handler.ts mirrors these limits for the MCP path.
export const MAX_SELECTOR_LENGTH = 63;
export const MAX_SELECTORS = 16;

export function parseSelectors(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(
      (s) =>
        s.length > 0 &&
        s.length <= MAX_SELECTOR_LENGTH &&
        VALID_SELECTOR.test(s),
    )
    .slice(0, MAX_SELECTORS);
}

// Cron handler — runs nightly per the `[triggers] crons` entry in wrangler.toml.
// Rescans domains whose cadence has come due (monthly or weekly), persists
// results, and records grade_drop / protocol_regression alerts. Fails soft
// when DB is unbound so self-host deploys without D1 don't fault.
async function scheduled(
  _controller: ScheduledController,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  if (!env.DB) return;
  const work = (async () => {
    const rescanResult = await runDueRescans({
      db: env.DB,
      now: Math.floor(Date.now() / 1000),
      scoringConfig: parseScoringConfig(env.SCORING_CONFIG),
      dnsblKey: env.DNSBL_DQS_KEY,
    });
    const scope = Sentry.getCurrentScope();
    scope.setTag("cron.scanned", String(rescanResult.scanned));
    scope.setTag("cron.alerts", String(rescanResult.alerts));
    scope.setTag("cron.errors", String(rescanResult.errors));
    // #700 — due domains deferred to the next run by the per-invocation
    // ceiling or the resolver circuit breaker. Persistently non-zero means the
    // portfolio has outgrown one invocation's outbound subrequest allowance.
    scope.setTag("cron.skipped", String(rescanResult.skipped));

    // Dispatch runs unconditionally — alerts from prior cron runs may still
    // be pending if the EMAIL binding was absent or failed previously.
    const dispatchResult = await dispatchPendingAlerts(env);
    scope.setTag("cron.emails_sent", String(dispatchResult.sent));
    scope.setTag("cron.emails_skipped", String(dispatchResult.skipped));
    scope.setTag("cron.emails_errors", String(dispatchResult.errors));

    // Retry any WorkOS identity deletions that failed during account deletion.
    const workosResult = await sweepWorkosRetries(env.DB, env.WORKOS_API_KEY);
    scope.setTag("cron.workos_retried", String(workosResult.retried));
    scope.setTag("cron.workos_cleared", String(workosResult.cleared));
    scope.setTag("cron.workos_given_up", String(workosResult.givenUp));
  })().catch((err) => {
    Sentry.captureException(err);
  });
  ctx.waitUntil(work);
}

// Public unsubscribe endpoint reached from email links. The token is the
// authentication — no session cookie required. Invalid / tampered tokens
// return a 400. Successful unsubscribe flips users.email_alerts_enabled to 0
// and renders a confirmation page.
app.get("/alerts/unsubscribe", async (c) => {
  const token = c.req.query("token");
  if (!token) {
    return c.html(renderError("Missing unsubscribe token."), 400);
  }
  const userId = await validateUnsubscribeToken(token, c.env.SESSION_SECRET);
  if (!userId) {
    return c.html(renderError("Invalid or expired unsubscribe link."), 400);
  }
  await setEmailAlertsEnabled(c.env.DB, userId, false);
  return c.html(
    `<!doctype html><html><head><meta charset="utf-8"><title>Unsubscribed</title></head><body style="font-family:system-ui;padding:32px;max-width:520px;margin:0 auto;line-height:1.5"><h1>Unsubscribed</h1><p>You will no longer receive grade-drop alerts from dmarc.mx.</p><p>You can re-enable alerts any time from <a href="/dashboard/settings">dashboard settings</a>.</p></body></html>`,
  );
});

const handler: ExportedHandler<Env> = {
  fetch: app.fetch.bind(app),
  scheduled,
  // Email Worker entry point for the `inbox@dmarc.mx` subaddressing rule (#417).
  // Reads the authentication verdict from the inbound message's headers and
  // stores it under the address token. Unknown/expired tokens and a message off
  // our subdomain are silent no-ops (handled in handleInboundEmail). Errors are
  // swallowed + reported so a transient KV failure never bounces legitimate
  // test mail.
  async email(message, env) {
    try {
      await handleInboundEmail(message, env.INBOX_TOKENS);
    } catch (err) {
      Sentry.captureException(err);
    }
  },
};

export default Sentry.withSentry<Env>(
  (env) => ({
    dsn: env?.SENTRY_DSN ?? "",
    tracesSampler: (samplingContext: { parentSampled?: boolean }) => {
      if (samplingContext.parentSampled !== undefined)
        return samplingContext.parentSampled;
      return 0.3;
    },
    // Registered on both hooks: beforeSend only covers error events, and the
    // SDK attaches request headers to transaction events too.
    beforeSend: scrubSentryEvent,
    beforeSendTransaction: scrubSentryEvent,
  }),
  handler,
);
