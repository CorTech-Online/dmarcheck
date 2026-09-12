// The four `Env` members below come from wrangler.toml bindings
// (`[[d1_databases]]`, `[[durable_objects.bindings]]`, `[[send_email]]`,
// `[[kv_namespaces]]`) and are picked from `GeneratedBindings` — the ambient
// interface `npm run types` (wrangler types --include-runtime=false
// --env-interface=GeneratedBindings) writes to worker-configuration.d.ts,
// included in tsconfig.json's `include`. Renaming or removing one of those
// bindings and regenerating drops it from `GeneratedBindings`, which fails
// `npm run typecheck` here instead of only failing at runtime on the
// deployed Worker. Everything else in this interface is a secret provisioned
// out-of-band via `wrangler secret put`, or a `[vars]` value — neither is
// covered by `wrangler types` in a form worth generating (vars would come
// back as literal types pinned to their current committed value), so those
// members stay hand-written.
type ConfigBindings = Pick<
  GeneratedBindings,
  "DB" | "RATE_LIMITER" | "EMAIL" | "INBOX_TOKENS"
>;

export interface Env {
  DB: ConfigBindings["DB"];
  // Atomic per-identity rate-limit counter (GHSA-v7qc-7qh8-h69g). Optional so
  // self-host deploys without the binding fall back to the in-memory limiter
  // (see checkRateLimit in src/rate-limit.ts); the hosted dmarc.mx worker has
  // it wired in wrangler.toml.
  RATE_LIMITER?: ConfigBindings["RATE_LIMITER"];
  WORKOS_CLIENT_ID: string;
  WORKOS_CLIENT_SECRET: string;
  WORKOS_REDIRECT_URI: string;
  // WorkOS Management API key (Bearer), distinct from the OAuth client
  // secret. Used to delete the WorkOS identity record on account deletion
  // (issue #550). Optional: self-host deploys without it skip the WorkOS
  // delete step. Also doubles as the "is this the hosted prod worker"
  // sentinel that gates the /_dev/dashboard fixture route in src/index.ts.
  WORKOS_API_KEY?: string;
  SESSION_SECRET: string;
  SENTRY_DSN?: string;
  // Cloudflare Email Sending binding. Optional so self-host deploys without
  // a verified sender still boot; the dispatcher no-ops when absent.
  EMAIL?: ConfigBindings["EMAIL"];
  // Short-lived KV store for inbound test-email scanning (issue #417). Keyed
  // by capability token: a pending reservation on issuance, overwritten with
  // the parsed authentication verdict when the Email Worker `email()` handler
  // receives the message. Both records carry a 30-min `expirationTtl`. Optional
  // so self-host deploys without the namespace (and the Node test pool) still
  // boot — the /check/email route and SSE stream degrade gracefully when it is
  // absent. This is the repo's first KV namespace; the SSE *scan* cache
  // (src/cache.ts) uses the Cache API, not KV.
  INBOX_TOKENS?: ConfigBindings["INBOX_TOKENS"];
  // Stripe billing (Phase 3 M2). All three must be present for billing to
  // activate; isBillingEnabled() in src/billing/feature-flag.ts gates paid
  // code paths so self-hosters without Stripe keys still get a working
  // free-tier deploy.
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_ID_PRO?: string;
  // Cloudflare Web Analytics token. Optional: when unset, the beacon script
  // is not injected. Set this on the hosted deploy (wrangler secret) to turn
  // on analytics. The token itself is non-secret (ends up in public HTML)
  // but lives here so self-host forks don't accidentally ship data to the
  // hosted tier's dashboard.
  CF_ANALYTICS_TOKEN?: string;
  // Self-host scoring rubric override (issue #25). A single JSON string of
  // ScoringConfig knobs (see src/shared/scoring-config.ts). Absent/invalid →
  // the shipped default rubric, so hosted dmarc.mx and config-less self-hosts
  // are unaffected. Parsed per request via parseScoringConfig().
  SCORING_CONFIG?: string;
  // Optional Spamhaus DQS (Data Query Service) key enabling the DNSBL/IP-
  // reputation analyzer (issue #587). Absent → the analyzer is a clean no-op,
  // so self-host deploys and the test pool are unaffected; set it (as a
  // wrangler secret) on the hosted deploy to turn the check on. NEVER logged,
  // returned, or written into a cache key — it is embedded only in the
  // outbound DQS query name (see queryDnsbl in src/dns/client.ts).
  DNSBL_DQS_KEY?: string;
  // Cloudflare Access enforcement on `*.workers.dev` preview-branch deploys.
  // Both must be set together — the middleware fail-CLOSEDs (503) on a
  // workers.dev hostname when either is missing. The production custom
  // domain (`dmarc.mx`) is not affected by these vars.
  ACCESS_AUD?: string;
  ACCESS_TEAM_DOMAIN?: string;
}
