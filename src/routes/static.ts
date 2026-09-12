import { Hono } from "hono";
import { listIndexableScanDomains } from "../shared/indexable-domains.js";
import { CSS_PATH, JS_PATH } from "../views/assets.js";
import {
  APPLE_TOUCH_ICON_BASE64,
  FAVICON_ICO_BASE64,
  FAVICON_SVG,
  ICON_192_BASE64,
  ICON_512_BASE64,
  OG_IMAGE_PNG_BASE64,
  webManifest,
} from "../views/favicon.js";
import { LEARN_MODIFIED } from "../views/learn.js";
import { MX_MODIFIED } from "../views/mx.js";
import { JS } from "../views/scripts.js";
import { CSS } from "../views/styles.js";

// Static assets, health check, and crawler-facing infrastructure — mounted at
// "/" by src/index.ts. No auth, no rate limiting, no user-input validation:
// every handler here returns a fixed or precomputed body, which is why this
// group can live outside the CODEOWNERS-gated wiring file (#661).
export const staticRoutes = new Hono();

staticRoutes.get("/logo.svg", (c) => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 512 512">
  <title>dmarcheck</title>
  <rect width="512" height="512" rx="64" fill="#0a0a0a"/>
  <text x="256" y="310" font-family="monospace" font-size="220" fill="#f97316" text-anchor="middle">@</text>
  <circle cx="210" cy="210" r="28" fill="white"/>
  <circle cx="302" cy="210" r="28" fill="white"/>
  <circle cx="216" cy="218" r="14" fill="#0a0a0f"/>
  <circle cx="308" cy="218" r="14" fill="#0a0a0f"/>
  <rect x="196" y="380" width="20" height="40" rx="8" fill="#ea580c"/>
  <rect x="246" y="380" width="20" height="32" rx="8" fill="#ea580c"/>
  <rect x="296" y="380" width="20" height="40" rx="8" fill="#ea580c"/>
</svg>`;
  return c.body(svg, 200, {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/og-image.svg", (c) => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#0a0a0f"/>
  <!-- Creature -->
  <text x="340" y="310" font-family="monospace" font-size="180" fill="#f97316" text-anchor="middle">@</text>
  <circle cx="300" cy="220" r="22" fill="white"/>
  <circle cx="375" cy="220" r="22" fill="white"/>
  <circle cx="305" cy="226" r="11" fill="#0a0a0f"/>
  <circle cx="380" cy="226" r="11" fill="#0a0a0f"/>
  <rect x="290" y="370" width="16" height="32" rx="6" fill="#ea580c"/>
  <rect x="330" y="370" width="16" height="26" rx="6" fill="#ea580c"/>
  <rect x="370" y="370" width="16" height="32" rx="6" fill="#ea580c"/>
  <!-- Wordmark -->
  <text x="500" y="300" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-weight="800" font-size="72">
    <tspan fill="#e4e4e7">dmar</tspan><tspan fill="#f97316">check</tspan>
  </text>
  <!-- Tagline -->
  <text x="500" y="350" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="24" fill="#71717a">DNS Email Security Analyzer</text>
  <!-- BIMI badge -->
  <text x="500" y="400" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="18" fill="#f97316">Meet DMarcus — your email security sidekick</text>
</svg>`;
  return c.body(svg, 200, {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/og-image.png", (c) => {
  const buf = Uint8Array.from(atob(OG_IMAGE_PNG_BASE64), (ch) =>
    ch.charCodeAt(0),
  );
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

// Content-hashed static assets with immutable caching
staticRoutes.get(CSS_PATH, (c) => {
  return c.body(CSS, 200, {
    "Content-Type": "text/css; charset=utf-8",
    "Cache-Control": "public, max-age=31536000, immutable",
  });
});

staticRoutes.get(JS_PATH, (c) => {
  return c.body(JS, 200, {
    "Content-Type": "application/javascript; charset=utf-8",
    "Cache-Control": "public, max-age=31536000, immutable",
  });
});

staticRoutes.get("/favicon.svg", (c) => {
  return c.body(FAVICON_SVG, 200, {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/manifest.webmanifest", (c) => {
  return c.body(webManifest(), 200, {
    "Content-Type": "application/manifest+json",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/favicon.ico", (c) => {
  const buf = Uint8Array.from(atob(FAVICON_ICO_BASE64), (ch) =>
    ch.charCodeAt(0),
  );
  return c.body(buf, 200, {
    "Content-Type": "image/x-icon",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/apple-touch-icon.png", (c) => {
  const buf = Uint8Array.from(atob(APPLE_TOUCH_ICON_BASE64), (ch) =>
    ch.charCodeAt(0),
  );
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/icon-192.png", (c) => {
  const buf = Uint8Array.from(atob(ICON_192_BASE64), (ch) => ch.charCodeAt(0));
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/icon-512.png", (c) => {
  const buf = Uint8Array.from(atob(ICON_512_BASE64), (ch) => ch.charCodeAt(0));
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

staticRoutes.get("/health", (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Crawl guidance for search engines. Block the API namespace (Google was
// logging `/api/check?domain=dmarc.mx` as "Crawled - currently not indexed"
// noise) and CSV export URLs (each crawl triggers a full live DNS scan; the
// X-Robots-Tag: noindex on text/csv stops indexing but not crawling, #521),
// and point to the sitemap. `/*format=csv` uses only Google-supported
// wildcards and cannot match plain /check?domain=X pages because `=` is
// rejected by normalizeDomain.
staticRoutes.get("/robots.txt", (c) => {
  const body = `User-agent: *
Allow: /
Disallow: /api/
Disallow: /*format=csv
Sitemap: https://dmarc.mx/sitemap.xml
`;
  return c.body(body, 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=86400",
  });
});

// No dedicated JSON-LD dateModified source exists for these pages (unlike
// /learn and /mx below) — this is the sitemap's own honestly-scoped
// constant for everything that isn't /learn/* or /mx/*, set to this file's
// own last content-affecting change (#672). Bump it when materially editing
// any of the pages below.
const OTHER_STATIC_LASTMOD = "2026-08-06";

// Static URLs worth reinforcing to search engines. The /check entries are
// generated from the curated allowlist in src/shared/indexable-domains.ts —
// every domain listed there is also marked indexable on its scan page, so
// the sitemap and the per-page robots meta stay in sync.
//
// `lastmod` is required on every entry (not optional) so that adding a new
// URL without picking a source fails `npm run typecheck` instead of
// silently inheriting a default.
const STATIC_SITEMAP_URLS: Array<{
  loc: string;
  priority: string;
  lastmod: string;
}> = [
  { loc: "https://dmarc.mx/", priority: "1.0", lastmod: OTHER_STATIC_LASTMOD },
  {
    loc: "https://dmarc.mx/pricing",
    priority: "0.9",
    lastmod: OTHER_STATIC_LASTMOD,
  },
  {
    loc: "https://dmarc.mx/scoring",
    priority: "0.8",
    lastmod: OTHER_STATIC_LASTMOD,
  },
  {
    loc: "https://dmarc.mx/legal/privacy",
    priority: "0.3",
    lastmod: OTHER_STATIC_LASTMOD,
  },
  { loc: "https://dmarc.mx/learn", priority: "0.7", lastmod: LEARN_MODIFIED },
  {
    loc: "https://dmarc.mx/learn/dmarc",
    priority: "0.8",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/spf",
    priority: "0.8",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/dkim",
    priority: "0.7",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/bimi",
    priority: "0.6",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/mta-sts",
    priority: "0.7",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/security-txt",
    priority: "0.6",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/tls-rpt",
    priority: "0.6",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/dnssec",
    priority: "0.7",
    lastmod: LEARN_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/learn/dane",
    priority: "0.6",
    lastmod: LEARN_MODIFIED,
  },
  { loc: "https://dmarc.mx/mx", priority: "0.7", lastmod: MX_MODIFIED },
  {
    loc: "https://dmarc.mx/mx/outlook",
    priority: "0.8",
    lastmod: MX_MODIFIED,
  },
  { loc: "https://dmarc.mx/mx/google", priority: "0.8", lastmod: MX_MODIFIED },
  {
    loc: "https://dmarc.mx/mx/mimecast",
    priority: "0.7",
    lastmod: MX_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/mx/proofpoint",
    priority: "0.7",
    lastmod: MX_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/mx/fastmail",
    priority: "0.6",
    lastmod: MX_MODIFIED,
  },
  { loc: "https://dmarc.mx/mx/zoho", priority: "0.6", lastmod: MX_MODIFIED },
  {
    loc: "https://dmarc.mx/mx/amazon-ses",
    priority: "0.6",
    lastmod: MX_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/mx/cloudflare",
    priority: "0.6",
    lastmod: MX_MODIFIED,
  },
  {
    loc: "https://dmarc.mx/llms.txt",
    priority: "0.2",
    lastmod: OTHER_STATIC_LASTMOD,
  },
];

// The 49 curated /check?domain=… pages have no meaningful per-URL modified
// date (they're generated per scan) — omit <lastmod> for them rather than
// synthesising a fake one.
function renderSitemapUrl({
  loc,
  priority,
  lastmod,
}: {
  loc: string;
  priority: string;
  lastmod?: string;
}): string {
  const lastmodTag = lastmod ? `<lastmod>${lastmod}</lastmod>` : "";
  return `  <url><loc>${loc}</loc>${lastmodTag}<priority>${priority}</priority></url>`;
}

staticRoutes.get("/sitemap.xml", (c) => {
  const scanUrls = listIndexableScanDomains().map((domain) => ({
    loc: `https://dmarc.mx/check?domain=${encodeURIComponent(domain)}`,
    priority: "0.6",
  }));
  const urls = [...STATIC_SITEMAP_URLS, ...scanUrls]
    .map(renderSitemapUrl)
    .join("\n");
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`;
  return c.body(body, 200, {
    "Content-Type": "application/xml; charset=utf-8",
    "Cache-Control": "public, max-age=86400",
  });
});
