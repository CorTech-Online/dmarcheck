import { beforeEach, describe, expect, it, vi } from "vitest";
import { COMMON_SELECTORS } from "../src/analyzers/dkim.js";
import {
  app,
  MAX_SELECTOR_LENGTH,
  MAX_SELECTORS,
  normalizeDomain,
  parseSelectors,
} from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";
import { LEARN_MODIFIED, LEARN_SIBLINGS } from "../src/views/learn.js";
import { MX_MODIFIED } from "../src/views/mx.js";

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn(),
}));

vi.mock("../src/orchestrator.js", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("../src/orchestrator.js")>();
  return {
    ...original,
    scanStreaming: vi.fn(original.scanStreaming),
  };
});

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

// Rate limit is 10 req/IP/60s and all app.request() calls in this file share
// the synthetic "unknown" IP. Wipe the in-memory bucket between tests so
// ordering-dependent 429s don't mask unrelated regressions.
beforeEach(() => {
  _memoryStore.clear();
});

describe("normalizeDomain", () => {
  it("returns null for undefined input", () => {
    expect(normalizeDomain(undefined)).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(normalizeDomain("")).toBeNull();
  });

  it("returns null for whitespace-only input", () => {
    expect(normalizeDomain("   ")).toBeNull();
  });

  it("returns null for input without a dot", () => {
    expect(normalizeDomain("localhost")).toBeNull();
  });

  it("returns null for input with spaces", () => {
    expect(normalizeDomain("example .com")).toBeNull();
  });

  it("returns null for domain exceeding 253 characters (RFC 1035)", () => {
    const longDomain = `${"a".repeat(250)}.com`;
    expect(normalizeDomain(longDomain)).toBeNull();
  });

  it("strips https:// prefix", () => {
    expect(normalizeDomain("https://example.com")).toBe("example.com");
  });

  it("strips http:// prefix", () => {
    expect(normalizeDomain("http://example.com")).toBe("example.com");
  });

  it("strips path after domain", () => {
    expect(normalizeDomain("example.com/path/to/page")).toBe("example.com");
  });

  it("strips query string after domain", () => {
    expect(normalizeDomain("example.com?q=test")).toBe("example.com");
  });

  it("strips trailing dot", () => {
    expect(normalizeDomain("example.com.")).toBe("example.com");
  });

  it("lowercases domain", () => {
    expect(normalizeDomain("Example.COM")).toBe("example.com");
  });

  it("handles full URL with protocol, path, and query", () => {
    expect(normalizeDomain("https://Example.COM/path?q=1")).toBe("example.com");
  });

  it("trims leading and trailing whitespace", () => {
    expect(normalizeDomain("  example.com  ")).toBe("example.com");
  });
});

describe("parseSelectors", () => {
  it("returns empty array for undefined", () => {
    expect(parseSelectors(undefined)).toEqual([]);
  });

  it("returns empty array for empty string", () => {
    expect(parseSelectors("")).toEqual([]);
  });

  it("splits comma-separated values", () => {
    expect(parseSelectors("google,selector1,s2")).toEqual([
      "google",
      "selector1",
      "s2",
    ]);
  });

  it("trims whitespace from selectors", () => {
    expect(parseSelectors("google , selector1 , s2")).toEqual([
      "google",
      "selector1",
      "s2",
    ]);
  });

  it("filters out empty strings from extra commas", () => {
    expect(parseSelectors("google,,selector1,")).toEqual([
      "google",
      "selector1",
    ]);
  });

  it("returns single selector", () => {
    expect(parseSelectors("google")).toEqual(["google"]);
  });

  // f27 / GHSA-6fqp-4vhc-59mf — attacker-controlled selector lists must not
  // fan out into one DNS lookup each with no ceiling.
  it("caps the number of selectors at MAX_SELECTORS", () => {
    const many = Array.from({ length: 500 }, (_, i) => `s${i}`).join(",");
    const result = parseSelectors(many);
    expect(result.length).toBe(MAX_SELECTORS);
    expect(result[0]).toBe("s0"); // keeps the first N, deterministically
  });

  it("drops selectors longer than MAX_SELECTOR_LENGTH", () => {
    const tooLong = "a".repeat(MAX_SELECTOR_LENGTH + 1);
    const ok = "b".repeat(MAX_SELECTOR_LENGTH);
    expect(parseSelectors(`${tooLong},${ok},google`)).toEqual([ok, "google"]);
  });
});

describe("normalizeDomain — extended edge cases", () => {
  it("strips port number", () => {
    expect(normalizeDomain("example.com:8080")).toBe("example.com");
  });

  it("strips port from full URL", () => {
    expect(normalizeDomain("https://example.com:443/path")).toBe("example.com");
  });

  it("converts IDN to Punycode", () => {
    expect(normalizeDomain("münchen.de")).toBe("xn--mnchen-3ya.de");
  });

  it("strips userinfo", () => {
    expect(normalizeDomain("user:pass@example.com")).toBe("example.com");
  });

  it("returns null for IPv6 address", () => {
    expect(normalizeDomain("[::1]")).toBeNull();
  });

  it("handles IDN with protocol and path", () => {
    expect(normalizeDomain("https://münchen.de/path")).toBe(
      "xn--mnchen-3ya.de",
    );
  });
});

describe("normalizeDomain — XSS payload rejection", () => {
  // These inputs were the XSS vectors before the fix: `encodeURIComponent`
  // preserves single quotes, and the URL constructor accepts them in hostnames.
  // normalizeDomain must now reject them at the boundary.
  it("rejects single quote in hostname", () => {
    expect(normalizeDomain("example.com';alert(1);'")).toBeNull();
  });

  it("rejects double quote in hostname", () => {
    expect(normalizeDomain('example.com";alert(1);"')).toBeNull();
  });

  it("rejects angle brackets in hostname", () => {
    expect(normalizeDomain("example.com<script>")).toBeNull();
  });

  it("rejects backtick in hostname", () => {
    expect(normalizeDomain("example.com`alert(1)`")).toBeNull();
  });

  it("rejects underscore in hostname (not valid per RFC 1035)", () => {
    expect(normalizeDomain("foo_bar.example.com")).toBeNull();
  });

  it("accepts plain ASCII hostnames", () => {
    expect(normalizeDomain("example.com")).toBe("example.com");
    expect(normalizeDomain("sub.example.co.uk")).toBe("sub.example.co.uk");
    expect(normalizeDomain("a-b.example.com")).toBe("a-b.example.com");
  });

  it("accepts numeric subdomain labels (not confused with IPv4 literals)", () => {
    // Numeric labels in a longer hostname must still be accepted — anchored
    // IPv4 rejection below must not over-fire on legitimate domains like
    // `123.example.com` or `1.2.3.4.example.com`.
    expect(normalizeDomain("123.example.com")).toBe("123.example.com");
    expect(normalizeDomain("1.2.3.4.example.com")).toBe("1.2.3.4.example.com");
    expect(normalizeDomain("10.example.com")).toBe("10.example.com");
  });
});

describe("normalizeDomain — IPv4 literal rejection", () => {
  // DMARC/SPF/DKIM/BIMI/MTA-STS records are published in DNS at domain names,
  // not IP addresses — there is no legitimate dmarcheck use case for scanning
  // a bare IPv4 literal. Rejecting them at the boundary also closes a
  // defense-in-depth gap flagged by static analysis around the MTA-STS fetch:
  // the `mta-sts.<domain>` prefix previously happened to shield metadata-
  // service IPs like 169.254.169.254 by accident. Make that rejection explicit.
  //
  // WHATWG URL (used by `new URL(...).hostname` inside normalizeDomain)
  // normalizes hex, integer, and short-form IPv4 inputs into canonical dotted-
  // decimal, so a single anchored regex on the post-URL form catches all of
  // them. `999.999.999.999` throws from the URL constructor and is caught by
  // the fallback branch — it must also be rejected as a dotted-quad form.

  it("rejects AWS/GCP metadata service IPv4 (the original motivation)", () => {
    expect(normalizeDomain("169.254.169.254")).toBeNull();
  });

  it("rejects loopback IPv4", () => {
    expect(normalizeDomain("127.0.0.1")).toBeNull();
  });

  it("rejects RFC 1918 private IPv4 ranges", () => {
    expect(normalizeDomain("192.168.1.1")).toBeNull();
    expect(normalizeDomain("10.0.0.1")).toBeNull();
    expect(normalizeDomain("172.16.0.1")).toBeNull();
  });

  it("rejects public IPv4 literals", () => {
    expect(normalizeDomain("1.1.1.1")).toBeNull();
    expect(normalizeDomain("8.8.8.8")).toBeNull();
  });

  it("rejects boundary IPv4 values", () => {
    expect(normalizeDomain("0.0.0.0")).toBeNull();
    expect(normalizeDomain("255.255.255.255")).toBeNull();
  });

  it("rejects hex-encoded IPv4 (WHATWG URL normalizes to dotted-decimal)", () => {
    // 0xc0a80101 === 192.168.1.1; URL constructor canonicalizes before our check.
    expect(normalizeDomain("0xc0a80101")).toBeNull();
  });

  it("rejects integer-encoded IPv4 (WHATWG URL normalizes to dotted-decimal)", () => {
    // 3232235777 === 192.168.1.1
    expect(normalizeDomain("3232235777")).toBeNull();
  });

  it("rejects short-form IPv4 (WHATWG URL normalizes to dotted-decimal)", () => {
    // `127.1` is normalized to `127.0.0.1` by the URL constructor.
    expect(normalizeDomain("127.1")).toBeNull();
    // `1.2.3` is silently rewritten to `1.2.0.3` (the third component is
    // interpreted as a 16-bit word). Previously this surfaced to the user
    // as a bogus scan of `1.2.0.3` instead of an error.
    expect(normalizeDomain("1.2.3")).toBeNull();
  });

  it("rejects out-of-range dotted-quad forms (caught via fallback path)", () => {
    // `999.999.999.999` throws from the URL constructor and falls through
    // to the manual-parse branch. It must still be rejected as IPv4-shaped.
    expect(normalizeDomain("999.999.999.999")).toBeNull();
  });

  it("rejects IPv4 with http:// prefix", () => {
    expect(normalizeDomain("http://192.168.1.1")).toBeNull();
    expect(normalizeDomain("https://169.254.169.254/path")).toBeNull();
  });
});

describe("parseSelectors — XSS payload rejection", () => {
  it("drops selector containing single quote", () => {
    expect(parseSelectors("x';alert(1);'")).toEqual([]);
  });

  it("drops selector containing angle brackets", () => {
    expect(parseSelectors("<script>")).toEqual([]);
  });

  it("drops selector containing space (rejected by strict charset)", () => {
    expect(parseSelectors("foo bar")).toEqual([]);
  });

  it("keeps valid selectors and drops invalid ones in the same list", () => {
    expect(parseSelectors("google,x';alert(1);',selector1")).toEqual([
      "google",
      "selector1",
    ]);
  });

  it("accepts selectors with dots, underscores, and hyphens", () => {
    expect(parseSelectors("dkim._domainkey,my-selector,s_1")).toEqual([
      "dkim._domainkey",
      "my-selector",
      "s_1",
    ]);
  });
});

describe("GET /check — XSS regression", () => {
  // Full end-to-end check: a pathological domain or selectors query string
  // must not cause attacker-controlled JavaScript tokens to appear in the
  // HTML response.
  it("does not reflect XSS payload from selectors into streaming loader", async () => {
    const res = await app.request(
      "/check?domain=example.com&selectors=x';alert(1);'",
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    // The payload string must not appear verbatim anywhere in the response
    expect(html).not.toContain("alert(1)");
    expect(html).not.toContain("';alert");
  });

  it("does not reflect XSS payload from domain into streaming loader", async () => {
    // A domain with a single quote must be rejected with a 400 — it never
    // reaches renderStreamingLoading, so no injection point.
    const res = await app.request("/check?domain=example.com';alert(2);'");
    // Either rejected as invalid (400) or silently normalized — in both
    // cases, the payload must not appear in the response body.
    const html = await res.text();
    expect(html).not.toContain("alert(2)");
  });

  it("streaming loader emits qs in a data-qs attribute, not a JS literal", async () => {
    const res = await app.request("/check?domain=example.com&selectors=google");
    expect(res.status).toBe(200);
    const html = await res.text();
    // Must contain the new data-qs attribute
    expect(html).toContain('data-qs="domain=example.com&amp;selectors=google"');
    // Must NOT contain the old inline JS literal pattern with the query string
    expect(html).not.toMatch(/var qs = 'domain=/);
  });
});

describe("GET /health", () => {
  it("returns 200 with status ok and a timestamp", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
    expect(typeof body.timestamp).toBe("string");
    // Verify timestamp is a valid ISO 8601 date
    expect(new Date(body.timestamp).toISOString()).toBe(body.timestamp);
  });
});

describe("CSV format routes", () => {
  it("returns 400 for /check?format=csv without domain", async () => {
    const res = await app.request("/check?format=csv");
    expect(res.status).toBe(400);
  });

  it("returns 400 for /api/check?format=csv without domain", async () => {
    const res = await app.request("/api/check?format=csv");
    expect(res.status).toBe(400);
  });

  it("sets strict CSP on CSV responses (non-HTML)", async () => {
    const res = await app.request("/api/check?domain=&format=csv");
    const csp = res.headers.get("Content-Security-Policy");
    expect(csp).toBe("default-src 'none'; frame-ancestors 'none'");
  });
});

describe("security headers", () => {
  it("sets security headers on landing page", async () => {
    const res = await app.request("/");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Referrer-Policy")).toBe(
      "strict-origin-when-cross-origin",
    );
    expect(res.headers.get("Permissions-Policy")).toBe(
      "camera=(), microphone=(), geolocation=()",
    );
  });

  // X-Frame-Options would override `frame-ancestors` in older browsers and
  // defeat the cortech.online embed allowlist, so it must not be sent.
  it("does not set X-Frame-Options on HTML responses", async () => {
    const res = await app.request("/");
    expect(res.headers.get("X-Frame-Options")).toBeNull();
  });

  it("does not set X-Frame-Options on non-HTML responses", async () => {
    const res = await app.request("/api/check?domain=");
    expect(res.headers.get("X-Frame-Options")).toBeNull();
  });

  it("sets nonce-based CSP without unsafe-inline on HTML responses", async () => {
    const res = await app.request("/");
    const csp = res.headers.get("Content-Security-Policy") ?? "";
    expect(csp).toMatch(/script-src 'nonce-[A-Za-z0-9+/]+=*'/);
    expect(csp).toContain("'strict-dynamic'");
    // script-src must not have unsafe-inline; style-src keeps it (CSS has no nonce equiv here)
    const scriptSrc = csp.match(/script-src[^;]*/)?.[0] ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'self' https://cortech.online");
  });

  it("injects nonce attribute into script tags in the HTML body", async () => {
    const res = await app.request("/");
    const csp = res.headers.get("Content-Security-Policy") ?? "";
    const nonceMatch = csp.match(/'nonce-([A-Za-z0-9+/]+=*)'/);
    expect(nonceMatch).not.toBeNull();
    const nonce = nonceMatch?.[1];
    const body = await res.text();
    expect(body).toContain(`<script nonce="${nonce}"`);
  });

  it("does not add nonce to JSON-LD script blocks", async () => {
    const res = await app.request("/check?domain=dmarc.mx");
    const body = await res.text();
    const jsonLdMatch = body.match(/<script type="application\/ld\+json"/g);
    if (jsonLdMatch) {
      for (const tag of jsonLdMatch) {
        expect(tag).not.toContain("nonce=");
      }
    }
  });

  it("allows only cortech.online to embed (no wildcards, exact origin)", async () => {
    const res = await app.request("/");
    const csp = res.headers.get("Content-Security-Policy") ?? "";
    const match = csp.match(/frame-ancestors ([^;]+)/);
    expect(match).not.toBeNull();
    const sources = match?.[1].trim().split(/\s+/) ?? [];
    expect(sources).toEqual(["'self'", "https://cortech.online"]);
  });

  it("sets strict CSP with frame-ancestors 'none' on JSON responses", async () => {
    const res = await app.request("/api/check?domain=");
    const csp = res.headers.get("Content-Security-Policy");
    expect(csp).toBe("default-src 'none'; frame-ancestors 'none'");
  });

  it("sets HSTS with 2-year max-age and includeSubDomains on HTML responses", async () => {
    const res = await app.request("/");
    expect(res.headers.get("Strict-Transport-Security")).toBe(
      "max-age=63072000; includeSubDomains",
    );
  });

  it("sets HSTS on non-HTML responses too", async () => {
    const res = await app.request("/api/check?domain=");
    expect(res.headers.get("Strict-Transport-Security")).toBe(
      "max-age=63072000; includeSubDomains",
    );
  });

  // `preload` is intentionally omitted — submission to hstspreload.org is a
  // separate, deliberate decision that locks every subdomain (including
  // future ones) into HTTPS forever.
  it("does not include the `preload` directive", async () => {
    const res = await app.request("/");
    const hsts = res.headers.get("Strict-Transport-Security") ?? "";
    expect(hsts).not.toContain("preload");
  });

  it("allows same-origin images in CSP", async () => {
    const res = await app.request("/");
    const csp = res.headers.get("Content-Security-Policy");
    expect(csp).toContain("img-src 'self' data:");
  });

  it("allows same-origin manifest in CSP", async () => {
    const res = await app.request("/");
    const csp = res.headers.get("Content-Security-Policy");
    expect(csp).toContain("manifest-src 'self'");
  });
});

describe("favicon and icon routes", () => {
  it("serves adaptive SVG favicon", async () => {
    const res = await app.request("/favicon.svg");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/svg+xml");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=86400");
    const body = await res.text();
    expect(body).toContain("prefers-color-scheme");
    expect(body.length).toBeLessThan(5000);
  });

  it("serves ICO favicon", async () => {
    const res = await app.request("/favicon.ico");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/x-icon");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=86400");
  });

  it("serves apple touch icon", async () => {
    const res = await app.request("/apple-touch-icon.png");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=86400");
  });

  it("serves web manifest with icon entries", async () => {
    const res = await app.request("/manifest.webmanifest");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/manifest+json");
    const body = await res.json();
    expect(body.icons).toHaveLength(2);
    expect(body.icons[0].src).toBe("/icon-192.png");
    expect(body.icons[1].src).toBe("/icon-512.png");
  });

  it("serves 192px icon", async () => {
    const res = await app.request("/icon-192.png");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
  });

  it("serves 512px icon", async () => {
    const res = await app.request("/icon-512.png");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
  });

  it("serves Open Graph PNG", async () => {
    const res = await app.request("/og-image.png");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=86400");
    const body = await res.arrayBuffer();
    expect(body.byteLength).toBeGreaterThan(0);
    const sig = new Uint8Array(body.slice(0, 8));
    expect(Array.from(sig)).toEqual([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ]);
  });

  it("still serves existing logo SVG unchanged", async () => {
    const res = await app.request("/logo.svg");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('viewBox="0 0 512 512"');
    expect(body).toContain('fill="#0a0a0a"');
  });
});

describe("HTML head tags", () => {
  it("includes favicon link tags", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain('rel="icon" href="/favicon.ico"');
    expect(html).toContain('rel="icon" href="/favicon.svg"');
    expect(html).toContain('rel="apple-touch-icon"');
    expect(html).toContain('rel="manifest"');
  });

  it("references external CSS and JS instead of inlining", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain('rel="stylesheet" href="/assets/styles-');
    expect(html).toContain('src="/assets/scripts-');
    expect(html).not.toMatch(/<style>[^<]{500,}<\/style>/);
    expect(html).not.toMatch(/<script>[^<]{500,}<\/script>/);
  });

  it("includes canonical link, theme-color, and twitter:image", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain('<link rel="canonical" href="https://dmarc.mx/">');
    expect(html).toContain('<meta name="theme-color" content="#f97316">');
    expect(html).toContain(
      '<meta name="twitter:image" content="https://dmarc.mx/og-image.png">',
    );
    expect(html).toContain(
      '<meta property="og:url" content="https://dmarc.mx/">',
    );
  });

  it("does not include the old self-pointing preconnect", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).not.toContain('<link rel="preconnect" href="/">');
  });

  it("landing page uses a proper h1 and includes the explainer section", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toMatch(/<h1 class="tagline">[^<]*DMARC[^<]*<\/h1>/);
    expect(html).toContain('<section class="landing-explainer"');
    expect(html).toContain(
      '<h2 id="explainer-heading">What dmarcheck checks</h2>',
    );
    // Keyword targets observed in Search Console: we want these strings on the page
    expect(html).toContain("DKIM");
    expect(html).toContain("MTA-STS");
  });

  it("landing explainer cross-links each protocol to its /learn page", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain('<dt><a href="/learn/dmarc">DMARC</a></dt>');
    expect(html).toContain('<dt><a href="/learn/spf">SPF</a></dt>');
    expect(html).toContain('<dt><a href="/learn/dkim">DKIM</a></dt>');
    expect(html).toContain('<dt><a href="/learn/bimi">BIMI</a></dt>');
    expect(html).toContain('<dt><a href="/learn/mta-sts">MTA-STS</a></dt>');
  });

  it("landing page cites the analyzer's real selector probe count", async () => {
    const res = await app.request("/");
    const html = await res.text();
    // Copy must not hardcode the probe count — it drifted to a stale "38"
    // while COMMON_SELECTORS held 36 entries (#523).
    expect(html).toContain(`${COMMON_SELECTORS.length} common selectors`);
    expect(html).not.toContain("38 common selectors");
  });

  it("landing explainer lists every checked protocol, not just the graded set", async () => {
    const res = await app.request("/");
    const html = await res.text();
    // Copy must not hardcode a protocol count (issue #453).
    expect(html).not.toMatch(/\b(five|5)\s+protocols\b/i);
    // The non-graded protocols must also appear in the inventory.
    expect(html).toContain("<dt>MX</dt>");
    expect(html).toContain(
      '<dt><a href="/learn/security-txt">security.txt</a></dt>',
    );
    expect(html).toContain('<dt><a href="/learn/tls-rpt">TLS-RPT</a></dt>');
    expect(html).toContain("<dt>DNSSEC</dt>");
    expect(html).toContain("<dt>DANE/TLSA</dt>");
    // The lead prose should still surface the SEO keyword targets.
    expect(html).toContain("DMARC");
    expect(html).toContain("MTA-STS");
  });

  it("/scoring heading is count-agnostic and lists every checked protocol", async () => {
    const res = await app.request("/scoring");
    const html = await res.text();
    // Copy must not hardcode a protocol count anywhere on the page
    // (issue #453: keep it from going stale again).
    expect(html).not.toMatch(/\b(five|5)\s+protocols\b/i);
    expect(html).toContain("The protocols we check");
    // Non-graded protocols are present and distinguished from the graded set.
    expect(html).toContain("<h3>MX</h3>");
    expect(html).toContain(
      '<h3><a href="/learn/security-txt">security.txt</a></h3>',
    );
    expect(html).toContain('<h3><a href="/learn/tls-rpt">TLS-RPT</a></h3>');
    expect(html).toContain("<h3>DNSSEC</h3>");
    expect(html).toContain("<h3>DANE/TLSA</h3>");
  });

  it("/scoring cross-links each protocol heading to its /learn page", async () => {
    const res = await app.request("/scoring");
    const html = await res.text();
    expect(html).toContain('<h3><a href="/learn/dmarc">DMARC</a></h3>');
    expect(html).toContain('<h3><a href="/learn/spf">SPF</a></h3>');
    expect(html).toContain('<h3><a href="/learn/dkim">DKIM</a></h3>');
    expect(html).toContain('<h3><a href="/learn/bimi">BIMI</a></h3>');
    expect(html).toContain('<h3><a href="/learn/mta-sts">MTA-STS</a></h3>');
  });

  it("report cards cross-link each protocol to its /learn page", async () => {
    const {
      renderDmarcCard,
      renderSpfCard,
      renderDkimCard,
      renderBimiCard,
      renderMtaStsCard,
    } = await import("../src/views/html.js");
    const empty = { status: "fail" as const, validations: [] };
    expect(renderDmarcCard({ ...empty, record: null, tags: null })).toContain(
      '<div class="card-learn-link"><a href="/learn/dmarc">Learn about DMARC &rarr;</a></div>',
    );
    expect(
      renderSpfCard({
        ...empty,
        record: null,
        lookups_used: 0,
        lookup_limit: 10,
        include_tree: null,
      }),
    ).toContain(
      '<div class="card-learn-link"><a href="/learn/spf">Learn about SPF &rarr;</a></div>',
    );
    expect(renderDkimCard({ ...empty, selectors: {} })).toContain(
      '<div class="card-learn-link"><a href="/learn/dkim">Learn about DKIM &rarr;</a></div>',
    );
    expect(renderBimiCard({ ...empty, record: null, tags: null })).toContain(
      '<div class="card-learn-link"><a href="/learn/bimi">Learn about BIMI &rarr;</a></div>',
    );
    expect(
      renderMtaStsCard({ ...empty, dns_record: null, policy: null }),
    ).toContain(
      '<div class="card-learn-link"><a href="/learn/mta-sts">Learn about MTA-STS &rarr;</a></div>',
    );
  });

  it("landing page embeds WebSite + SoftwareApplication JSON-LD", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain('<script type="application/ld+json">');
    expect(html).toContain('"@type":"WebSite"');
    expect(html).toContain('"@type":"SoftwareApplication"');
    expect(html).toContain("SearchAction");
  });

  it("scoring page has a canonical pointing to /scoring and FAQ JSON-LD", async () => {
    const res = await app.request("/scoring");
    const html = await res.text();
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/scoring">',
    );
    expect(html).toContain('"@type":"FAQPage"');
    expect(html).toContain("What is DMARC?");
  });
});

describe("SEO routes", () => {
  it("serves /robots.txt with sitemap pointer and API disallow", async () => {
    const res = await app.request("/robots.txt");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=86400");
    const body = await res.text();
    expect(body).toContain("User-agent: *");
    expect(body).toContain("Disallow: /api/");
    expect(body).toContain("Sitemap: https://dmarc.mx/sitemap.xml");
  });

  it("disallows CSV export URLs without blocking plain /check pages", async () => {
    const res = await app.request("/robots.txt");
    const body = await res.text();
    expect(body).toContain("Disallow: /*format=csv");
    // Plain /check?domain=X pages are indexed and earning impressions —
    // no rule may match them.
    expect(body).not.toContain("Disallow: /check");
  });

  it("serves /sitemap.xml listing the core URLs", async () => {
    const res = await app.request("/sitemap.xml");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "application/xml; charset=utf-8",
    );
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=86400");
    const body = await res.text();
    expect(body).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(body).toContain(
      '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    );
    expect(body).toContain("<loc>https://dmarc.mx/</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/scoring</loc>");
    expect(body).toContain(
      "<loc>https://dmarc.mx/check?domain=github.com</loc>",
    );
  });

  it("sitemap lists the /learn hub and each protocol learn page", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain("<loc>https://dmarc.mx/learn</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/dmarc</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/spf</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/dkim</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/bimi</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/mta-sts</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/security-txt</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/tls-rpt</loc>");
  });

  it("/robots.txt is NOT marked noindex (must stay crawlable)", async () => {
    const res = await app.request("/robots.txt");
    expect(res.headers.get("X-Robots-Tag")).toBeNull();
  });

  it("/sitemap.xml is NOT marked noindex (must stay crawlable)", async () => {
    const res = await app.request("/sitemap.xml");
    expect(res.headers.get("X-Robots-Tag")).toBeNull();
  });

  it("sitemap includes the curated /check?domain=… allowlist", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    // Spot-check a few representative entries from each category — full
    // round-trip against listIndexableScanDomains() is in the unit tests.
    expect(body).toContain(
      "<loc>https://dmarc.mx/check?domain=gmail.com</loc>",
    );
    expect(body).toContain(
      "<loc>https://dmarc.mx/check?domain=outlook.com</loc>",
    );
    expect(body).toContain(
      "<loc>https://dmarc.mx/check?domain=github.com</loc>",
    );
    expect(body).toContain(
      "<loc>https://dmarc.mx/check?domain=stripe.com</loc>",
    );
    expect(body).toContain("<loc>https://dmarc.mx/check?domain=dmarc.mx</loc>");
  });

  it("sitemap excludes domains not in the allowlist", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).not.toContain("example.com");
  });

  it("stamps each /learn URL's lastmod with LEARN_MODIFIED", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain(
      `<loc>https://dmarc.mx/learn</loc><lastmod>${LEARN_MODIFIED}</lastmod>`,
    );
    expect(body).toContain(
      `<loc>https://dmarc.mx/learn/dmarc</loc><lastmod>${LEARN_MODIFIED}</lastmod>`,
    );
    expect(body).toContain(
      `<loc>https://dmarc.mx/learn/dane</loc><lastmod>${LEARN_MODIFIED}</lastmod>`,
    );
  });

  it("stamps each /mx URL's lastmod with MX_MODIFIED", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain(
      `<loc>https://dmarc.mx/mx</loc><lastmod>${MX_MODIFIED}</lastmod>`,
    );
    expect(body).toContain(
      `<loc>https://dmarc.mx/mx/outlook</loc><lastmod>${MX_MODIFIED}</lastmod>`,
    );
    expect(body).toContain(
      `<loc>https://dmarc.mx/mx/cloudflare</loc><lastmod>${MX_MODIFIED}</lastmod>`,
    );
  });

  it("omits <lastmod> for /check?domain=… scan pages (no real per-domain date)", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain(
      "<loc>https://dmarc.mx/check?domain=github.com</loc><priority>0.6</priority>",
    );
    expect(body).not.toMatch(/check\?domain=github\.com<\/loc><lastmod>/);
  });

  it("does not stamp one lastmod value across every emitted URL", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    const lastmods = new Set(
      [...body.matchAll(/<lastmod>([^<]+)<\/lastmod>/g)].map((m) => m[1]),
    );
    // At least three distinct dates: /learn/*, /mx/*, and everything else.
    expect(lastmods.size).toBeGreaterThanOrEqual(3);
    // No single value can appear on every <url> — some entries (scan pages)
    // must have none at all, and learn/mx must differ from each other.
    const urlCount = [...body.matchAll(/<url>/g)].length;
    const lastmodCount = [...body.matchAll(/<lastmod>/g)].length;
    expect(lastmodCount).toBeLessThan(urlCount);
  });
});

describe("/check meta tags and noindex gating", () => {
  it("emits the free + open-source description for an allowlisted domain", async () => {
    const res = await app.request("/check?domain=github.com");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      'content="Free, open-source DMARC, SPF, DKIM, BIMI, MTA-STS, and more for github.com. See the current grade, records, and fixes. No signup, no email required."',
    );
  });

  it("emits the new title format for the streaming loading page", async () => {
    const res = await app.request("/check?domain=github.com");
    const html = await res.text();
    expect(html).toContain(
      "<title>github.com DMARC report — Free check | dmarcheck</title>",
    );
  });

  it("does NOT mark allowlisted scan pages noindex", async () => {
    const res = await app.request("/check?domain=github.com");
    const html = await res.text();
    expect(html).not.toContain('name="robots" content="noindex,follow"');
  });

  it("marks non-allowlisted scan pages noindex,follow", async () => {
    const res = await app.request("/check?domain=example.com");
    const html = await res.text();
    expect(html).toContain('<meta name="robots" content="noindex,follow">');
  });
});

describe("Learn pages", () => {
  const protocols = [
    { slug: "dmarc", label: "DMARC" },
    { slug: "spf", label: "SPF" },
    { slug: "dkim", label: "DKIM" },
    { slug: "bimi", label: "BIMI" },
    { slug: "mta-sts", label: "MTA-STS" },
    { slug: "security-txt", label: "security.txt" },
    { slug: "tls-rpt", label: "TLS-RPT" },
    { slug: "dnssec", label: "DNSSEC" },
    { slug: "dane", label: "DANE" },
  ];

  it("serves the /learn hub with a CollectionPage + BreadcrumbList", async () => {
    const res = await app.request("/learn");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/learn">',
    );
    expect(html).toContain('<script type="application/ld+json">');
    expect(html).toContain('"@type":"CollectionPage"');
    expect(html).toContain('"@type":"BreadcrumbList"');
    expect(html).toContain(
      '<h1 class="rubric-title">Learn email authentication</h1>',
    );
    // Hub links to each protocol page
    for (const p of protocols) {
      expect(html).toContain(`href="/learn/${p.slug}"`);
    }
  });

  it("hub intro cites the real guide count from LEARN_SIBLINGS", async () => {
    const res = await app.request("/learn");
    const html = await res.text();
    // Copy must not hardcode the guide count — the same drift the landing
    // page's "five protocols" had (#453). Interpolating the array length
    // keeps the prose honest when a tenth guide lands.
    expect(html).toContain(`${LEARN_SIBLINGS.length} short guides`);
    expect(html).not.toMatch(/\b(nine|ten|eleven|twelve)\s+short guides\b/i);
  });

  for (const p of protocols) {
    it(`serves /learn/${p.slug} with TechArticle + BreadcrumbList JSON-LD`, async () => {
      const res = await app.request(`/learn/${p.slug}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/html");
      const html = await res.text();
      expect(html).toContain(
        `<link rel="canonical" href="https://dmarc.mx/learn/${p.slug}">`,
      );
      expect(html).toContain('<script type="application/ld+json">');
      expect(html).toContain('"@type":"TechArticle"');
      expect(html).toContain('"@type":"BreadcrumbList"');
      // H1 contains a "What is <protocol>?" style headline
      expect(html).toMatch(new RegExp(`<h1[^>]*>[^<]*${p.label}[^<]*</h1>`));
      // CTA form submits to /check so readers can scan their domain
      expect(html).toContain('action="/check"');
      // Cross-links back to the other learn pages (hub-and-spoke)
      expect(html).toContain('href="/learn/');
      // Link to /scoring as the deeper rubric reference
      expect(html).toContain('href="/scoring"');
    });
  }

  it("learn pages stay crawlable (no X-Robots-Tag)", async () => {
    for (const p of protocols) {
      const res = await app.request(`/learn/${p.slug}`);
      expect(res.headers.get("X-Robots-Tag")).toBeNull();
    }
    const hub = await app.request("/learn");
    expect(hub.headers.get("X-Robots-Tag")).toBeNull();
  });

  it("learn pages do NOT reuse the FAQPage schema (avoid cannibalizing /scoring)", async () => {
    // /scoring owns FAQPage; /learn/* should use TechArticle so Google keeps
    // both in the index instead of deduping them.
    const res = await app.request("/learn/dmarc");
    const html = await res.text();
    expect(html).not.toContain('"@type":"FAQPage"');
  });

  it("learn JSON-LD keeps datePublished stable while dateModified moves on edits", async () => {
    // Search engines expect datePublished to be the original publication date
    // and only dateModified to move on edits — bumping datePublished reads as
    // freshness gaming. The learn lane has been materially edited since the
    // 2026-04-11 launch, so the two fields must differ.
    const res = await app.request("/learn/dmarc");
    const html = await res.text();
    const match = html.match(
      /<script type="application\/ld\+json">(.+?)<\/script>/s,
    );
    expect(match).not.toBeNull();
    const graph = JSON.parse(match?.[1] ?? "{}")["@graph"];
    const article = graph.find(
      (node: { "@type": string }) => node["@type"] === "TechArticle",
    );
    expect(article.datePublished).toBe("2026-04-11");
    expect(article.dateModified > article.datePublished).toBe(true);
  });

  it("DMARC learn page explains the core tag vocabulary", async () => {
    const res = await app.request("/learn/dmarc");
    const html = await res.text();
    expect(html).toContain("<code>p</code>");
    expect(html).toContain("<code>rua</code>");
    expect(html).toContain("<code>pct</code>");
  });

  it("SPF learn page calls out the 10 DNS lookup limit", async () => {
    const res = await app.request("/learn/spf");
    const html = await res.text();
    expect(html).toContain("10");
    expect(html).toMatch(/lookup/i);
    expect(html).toContain("permerror");
  });

  it("DKIM learn page mentions 2048-bit key guidance and selectors", async () => {
    const res = await app.request("/learn/dkim");
    const html = await res.text();
    expect(html).toContain("2048");
    expect(html).toMatch(/selector/i);
  });

  it("DKIM learn page explains how to find your selector under a stable anchor", async () => {
    const res = await app.request("/learn/dkim");
    const html = await res.text();
    // The anchor id is a contract: scan-report validations will deep-link to
    // it (#524). Do not rename without checking callers.
    expect(html).toMatch(/<h2[^>]*\bid="find-your-selector"[^>]*>/);
    // Path 1: read the s= tag from a real DKIM-Signature header
    expect(html).toContain("DKIM-Signature");
    expect(html).toContain("<code>s=</code>");
    // Path 2: provider defaults, sourced from the analyzer's probe list
    for (const sel of ["google", "selector1", "selector2"]) {
      expect(COMMON_SELECTORS).toContain(sel);
      expect(html).toContain(`<code>${sel}</code>`);
    }
    // Path 3: the scan CTA cites the analyzer's real probe count
    expect(html).toContain(`${COMMON_SELECTORS.length} common selectors`);
    expect(html).not.toContain("38 common selectors");
  });

  it("DKIM learn page meta description includes selector-finding phrasing", async () => {
    const res = await app.request("/learn/dkim");
    const html = await res.text();
    expect(html).toMatch(
      /<meta name="description" content="[^"]*find your DKIM selector[^"]*"/i,
    );
  });

  it("BIMI learn page mentions VMC and the DMARC requirement", async () => {
    const res = await app.request("/learn/bimi");
    const html = await res.text();
    expect(html).toContain("VMC");
    expect(html).toMatch(/DMARC/);
    expect(html).toContain('href="/learn/dmarc"');
  });

  it("BIMI learn page has a certification section (VMC vs CMC, issuers, cost, troubleshooting)", async () => {
    const res = await app.request("/learn/bimi");
    const html = await res.text();
    // Dedicated H2 targeting the "bimi certification" query cluster
    expect(html).toMatch(/<h2[^>]*>[^<]*BIMI certification[^<]*<\/h2>/);
    // VMC vs CMC comparison: full names and the eligibility difference
    expect(html).toContain("Verified Mark Certificate");
    expect(html).toContain("Common Mark Certificate");
    expect(html).toMatch(/registered trademark/i);
    expect(html).toMatch(/12 months/);
    // Both certificate types require DMARC at enforcement
    expect(html).toContain("<code>pct=100</code>");
    // Issuers
    expect(html).toContain("DigiCert");
    expect(html).toContain("Entrust");
    // Cost guidance stays approximate and dated, never precise vendor pricing
    expect(html).toMatch(/as of 2026/);
    // Troubleshooting subsection for the "logo still not showing" intent
    expect(html).toMatch(/logo still not showing/i);
    expect(html).toMatch(/expired/i);
    expect(html).toContain("Tiny PS");
  });

  it("BIMI learn page title, meta description, and JSON-LD carry certification intent", async () => {
    const res = await app.request("/learn/bimi");
    const html = await res.text();
    expect(html).toMatch(/<title>[^<]*certification[^<]*<\/title>/i);
    expect(html).toMatch(
      /<meta name="description" content="[^"]*certification[^"]*"/i,
    );
    // JSON-LD headline/description stay consistent with the visible page
    const jsonLdMatch = html.match(
      /<script type="application\/ld\+json">(.*?)<\/script>/s,
    );
    if (!jsonLdMatch) throw new Error("JSON-LD script block not found");
    const graph = JSON.parse(jsonLdMatch[1])["@graph"];
    const article = graph.find(
      (n: { "@type": string }) => n["@type"] === "TechArticle",
    );
    expect(article.description).toMatch(/certification/i);
    expect(html).toContain(`<h1 class="rubric-title">${article.headline}</h1>`);
  });

  it("MTA-STS learn page mentions enforce/testing modes and the policy file", async () => {
    const res = await app.request("/learn/mta-sts");
    const html = await res.text();
    expect(html).toContain("mta-sts.txt");
    expect(html).toContain("enforce");
    expect(html).toContain("testing");
  });

  it("security.txt learn page mentions RFC 9116, Contact, and Expires fields", async () => {
    const res = await app.request("/learn/security-txt");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/learn/security-txt">',
    );
    expect(html).toContain("RFC 9116");
    expect(html).toContain("<code>Contact</code>");
    expect(html).toContain("<code>Expires</code>");
    expect(html).toContain(".well-known/security.txt");
  });

  it("TLS-RPT learn page mentions RFC 8460, _smtp._tls, and rua=", async () => {
    const res = await app.request("/learn/tls-rpt");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/learn/tls-rpt">',
    );
    expect(html).toContain("RFC 8460");
    expect(html).toContain("_smtp._tls");
    expect(html).toContain("<code>rua</code>");
    expect(html).toContain("TLSRPTv1");
  });

  it("DNSSEC learn page mentions DS records, the AD flag, and the chain of trust", async () => {
    const res = await app.request("/learn/dnssec");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/learn/dnssec">',
    );
    expect(html).toContain("DS");
    expect(html).toContain("AD");
    expect(html).toMatch(/chain of trust/i);
  });

  it("DANE learn page mentions _25._tcp, TLSA, and the DNSSEC requirement", async () => {
    const res = await app.request("/learn/dane");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/learn/dane">',
    );
    expect(html).toContain("_25._tcp");
    expect(html).toContain("TLSA");
    expect(html).toContain("DNSSEC");
    // DANE is tied to DNSSEC and links back to the DNSSEC learn page
    expect(html).toContain('href="/learn/dnssec"');
  });

  it("sitemap.xml lists /learn/security-txt and /learn/tls-rpt", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain("<loc>https://dmarc.mx/learn/security-txt</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/tls-rpt</loc>");
  });

  it("sitemap.xml lists /learn/dnssec and /learn/dane", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain("<loc>https://dmarc.mx/learn/dnssec</loc>");
    expect(body).toContain("<loc>https://dmarc.mx/learn/dane</loc>");
  });
});

describe("MX provider pages", () => {
  it("mx JSON-LD keeps datePublished stable at the 2026-05-24 launch date", async () => {
    // Search engines expect datePublished to be the original publication date
    // and only dateModified to move on edits — bumping datePublished reads as
    // freshness gaming. The /mx lane has not been materially edited since the
    // 2026-05-24 launch, so the two fields are currently equal; dateModified
    // may move forward on edits but datePublished must never change.
    const res = await app.request("/mx/google");
    const html = await res.text();
    const match = html.match(
      /<script type="application\/ld\+json">(.+?)<\/script>/s,
    );
    expect(match).not.toBeNull();
    const graph = JSON.parse(match?.[1] ?? "{}")["@graph"];
    const article = graph.find(
      (node: { "@type": string }) => node["@type"] === "TechArticle",
    );
    expect(article.datePublished).toBe("2026-05-24");
    expect(article.dateModified >= article.datePublished).toBe(true);
  });
});

describe("bare /check request", () => {
  it("redirects browsers to / when no domain query parameter is supplied", async () => {
    const res = await app.request("/check");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/");
  });

  it("returns 400 JSON to API clients missing the domain parameter", async () => {
    const res = await app.request("/check?format=json");
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("domain");
  });

  it("returns 400 to Accept: application/json clients", async () => {
    const res = await app.request("/check", {
      headers: { Accept: "application/json" },
    });
    expect(res.status).toBe(400);
  });
});

describe("HTML Cache-Control and X-Robots-Tag", () => {
  it("sets a short edge Cache-Control on HTML responses", async () => {
    const res = await app.request("/");
    const cc = res.headers.get("Cache-Control");
    expect(cc).toContain("s-maxage=300");
    expect(cc).toContain("stale-while-revalidate");
  });

  it("does not set X-Robots-Tag on HTML responses", async () => {
    const res = await app.request("/");
    expect(res.headers.get("X-Robots-Tag")).toBeNull();
  });

  it("sets X-Robots-Tag: noindex on the JSON API", async () => {
    const res = await app.request("/api/check?domain=dmarc.mx");
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
  });

  it("sets X-Robots-Tag: noindex on /manifest.webmanifest", async () => {
    const res = await app.request("/manifest.webmanifest");
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
  });

  it("sets X-Robots-Tag: noindex on /health JSON", async () => {
    const res = await app.request("/health");
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
  });
});

describe("static asset routes", () => {
  it("serves CSS with immutable cache header", async () => {
    const { CSS_PATH } = await import("../src/views/assets.js");
    const res = await app.request(CSS_PATH);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/css; charset=utf-8");
    expect(res.headers.get("Cache-Control")).toBe(
      "public, max-age=31536000, immutable",
    );
    const body = await res.text();
    expect(body.length).toBeGreaterThan(1000);
  });

  it("serves JS with immutable cache header", async () => {
    const { JS_PATH } = await import("../src/views/assets.js");
    const res = await app.request(JS_PATH);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "application/javascript; charset=utf-8",
    );
    expect(res.headers.get("Cache-Control")).toBe(
      "public, max-age=31536000, immutable",
    );
    const body = await res.text();
    expect(body.length).toBeGreaterThan(1000);
  });
});

describe("SSE streaming cache", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("replays cached result as SSE events on cache hit", async () => {
    const { getCachedScan } = await import("../src/cache.js");
    const { scanStreaming } = await import("../src/orchestrator.js");
    vi.mocked(getCachedScan).mockResolvedValueOnce({
      domain: "example.com",
      timestamp: "2026-04-02T00:00:00.000Z",
      grade: "A+",
      breakdown: {
        grade: "A+",
        tier: "A",
        tierReason: "All protocols passing",
        modifier: 0,
        modifierLabel: "",
        score: 100,
        maxScore: 100,
        factors: [],
        recommendations: [],
        protocolSummaries: {
          dmarc: { status: "pass", summary: "p=reject" },
          spf: { status: "pass", summary: "pass" },
          dkim: { status: "pass", summary: "1 selector found" },
          bimi: { status: "fail", summary: "No BIMI record" },
          mta_sts: { status: "fail", summary: "No MTA-STS policy" },
        },
      } as unknown as ScanResult,
      summary: {
        mx_records: 1,
        mx_providers: ["Google Workspace"],
        dmarc_policy: "reject",
        spf_result: "pass",
        spf_lookups: "3/10",
        dkim_selectors_found: 1,
        bimi_enabled: false,
        mta_sts_mode: null,
      },
      protocols: {
        mx: { status: "info", records: [], providers: [], validations: [] },
        dmarc: {
          status: "pass",
          record: "v=DMARC1; p=reject",
          tags: { p: "reject" },
          validations: [],
        },
        spf: {
          status: "pass",
          record: "v=spf1 -all",
          lookups_used: 0,
          lookup_limit: 10,
          include_tree: null,
          validations: [],
        },
        dkim: { status: "pass", selectors: {}, validations: [] },
        bimi: { status: "fail", record: null, tags: null, validations: [] },
        mta_sts: {
          status: "fail",
          dns_record: null,
          policy: null,
          validations: [],
        },
      },
    });

    const res = await app.request("/api/check/stream?domain=example.com");
    expect(res.status).toBe(200);

    const text = await res.text();
    // Should contain all 6 protocol events
    expect(text).toContain('event: protocol\ndata: {"id":"mx"');
    expect(text).toContain('event: protocol\ndata: {"id":"dmarc"');
    expect(text).toContain('event: protocol\ndata: {"id":"spf"');
    expect(text).toContain('event: protocol\ndata: {"id":"dkim"');
    expect(text).toContain('event: protocol\ndata: {"id":"bimi"');
    expect(text).toContain('event: protocol\ndata: {"id":"mta_sts"');
    // Should contain done event with grade
    expect(text).toContain("event: done");
    expect(text).toContain('"grade":"A+"');
    // scanStreaming should NOT have been called
    expect(scanStreaming).not.toHaveBeenCalled();
  });
});
