import { beforeEach, describe, expect, it, vi } from "vitest";
import { _resetAgentSkillsCache } from "../src/api/agent-skills.js";
import { app } from "../src/index.js";
import {
  _memoryStore,
  type RateLimitResult,
  rateLimitHeaders,
} from "../src/rate-limit.js";

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn(),
}));

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

beforeEach(() => {
  _memoryStore.clear();
  _resetAgentSkillsCache();
});

describe("Link response header", () => {
  it("advertises the agent-discovery relations on the landing page", async () => {
    const res = await app.request("/");
    const link = res.headers.get("Link");
    expect(link).toBeTruthy();
    expect(link).toContain('rel="api-catalog"');
    expect(link).toContain('rel="service-desc"');
    expect(link).toContain('rel="service-doc"');
    expect(link).toContain('rel="status"');
    expect(link).toContain("</.well-known/api-catalog>");
    expect(link).toContain("</openapi.json>");
    expect(link).toContain("</docs/api>");
    expect(link).toContain("</health>");
    expect(link).toContain("</.well-known/agent-skills/index.json>");
    // DNS-AID agent metadata contract (draft-mozleywilliams-dnsop-dnsaid).
    expect(link).toContain("</.well-known/agent.json>");
    expect(link).toContain("draft-mozleywilliams-dnsop-dnsaid");
  });

  it("sets Link on scoring, learn, and docs pages too", async () => {
    for (const path of ["/scoring", "/learn", "/docs/api"]) {
      const res = await app.request(path);
      expect(
        res.headers.get("Link"),
        `expected Link header on ${path}`,
      ).toContain('rel="api-catalog"');
    }
  });

  it("does not attach a Link header to JSON responses", async () => {
    const res = await app.request("/health");
    expect(res.headers.get("Link")).toBeNull();
  });
});

describe("/.well-known/api-catalog", () => {
  it("returns an RFC 9727 linkset with the expected anchor and relations", async () => {
    const res = await app.request("/.well-known/api-catalog");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/linkset+json");
    const body = (await res.json()) as {
      linkset: Array<{
        anchor: string;
        "service-desc": Array<{ href: string; type: string }>;
        "service-doc": Array<{ href: string; type: string }>;
        status: Array<{ href: string }>;
      }>;
    };
    expect(body.linkset).toHaveLength(4);
    const anchors = body.linkset.map((e) => e.anchor);
    expect(anchors).toContain("https://dmarc.mx/api/check");
    expect(anchors).toContain("https://dmarc.mx/api/bulk-scan");
    expect(anchors).toContain("https://dmarc.mx/api/domain/{name}/history");
    expect(anchors).toContain("https://dmarc.mx/mcp");
    for (const entry of body.linkset) {
      expect(entry["service-desc"][0].href).toBe(
        "https://dmarc.mx/openapi.json",
      );
      expect(entry["service-desc"][0].type).toBe("application/openapi+json");
      expect(entry["service-doc"][0].href).toBe("https://dmarc.mx/docs/api");
      expect(entry.status[0].href).toBe("https://dmarc.mx/health");
    }
  });
});

describe("/.well-known/agent.json", () => {
  it("returns the DNS-AID metadata contract describing scan_domain", async () => {
    const res = await app.request("/.well-known/agent.json");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "application/json; charset=utf-8",
    );
    const body = (await res.json()) as {
      aid_version: string;
      identity: { name: string; url: string; documentation: string };
      connection: { protocol: string; transport: string; endpoint: string };
      auth: { type: string };
      capabilities: {
        supports_streaming: boolean;
        actions: Array<{
          name: string;
          description: string;
          intent: string;
          semantics: string;
        }>;
      };
    };

    // `aid_version` is the key that marks this as a DNS-AID-native document
    // (vs. a Google A2A agent card, which omits it).
    expect(body.aid_version).toBeTruthy();
    expect(body.identity.name).toBe("dmarcheck");
    expect(body.identity.url).toBe("https://dmarc.mx");
    expect(body.identity.documentation).toBe("https://dmarc.mx/docs/api");

    // Connection points at our streamable-HTTP MCP endpoint.
    expect(body.connection.protocol).toBe("mcp");
    expect(body.connection.transport).toBe("streamable-http");
    expect(body.connection.endpoint).toBe("https://dmarc.mx/mcp");

    expect(body.auth.type).toBeTruthy();

    const scan = body.capabilities.actions.find(
      (a) => a.name === "scan_domain",
    );
    expect(scan).toBeDefined();
    expect(scan?.intent).toBe("query");
    expect(scan?.semantics).toBe("read");
    expect(scan?.description).toBeTruthy();
  });
});

describe("/openapi.json", () => {
  it("returns an OpenAPI 3.1 document covering the public endpoints", async () => {
    const res = await app.request("/openapi.json");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "application/openapi+json; charset=utf-8",
    );
    const doc = (await res.json()) as {
      openapi: string;
      paths: Record<string, unknown>;
      components: { schemas: Record<string, unknown> };
    };
    expect(doc.openapi).toBe("3.1.0");
    for (const path of [
      "/api/check",
      "/api/bulk-scan",
      "/api/domain/{name}/history",
      "/api/check/stream",
      "/check",
      "/health",
      "/.well-known/api-catalog",
    ]) {
      expect(doc.paths[path], `expected OpenAPI path ${path}`).toBeDefined();
    }
    expect(doc.components.schemas.ScanResult).toBeDefined();
    expect(doc.components.schemas.DmarcResult).toBeDefined();
    expect(doc.components.schemas.BulkScanResponse).toBeDefined();
    expect(doc.components.schemas.DomainHistoryResponse).toBeDefined();
  });
});

describe("/docs/api", () => {
  it("renders the HTML API docs page by default", async () => {
    const res = await app.request("/docs/api");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/html");
    const body = await res.text();
    expect(body).toContain("dmarcheck API");
    expect(body).toContain("/openapi.json");
  });

  it("returns markdown when Accept: text/markdown is sent", async () => {
    const res = await app.request("/docs/api", {
      headers: { Accept: "text/markdown" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    const body = await res.text();
    expect(body).toContain("# dmarcheck API");
  });
});

describe("markdown content negotiation", () => {
  it("returns markdown for the landing page when requested", async () => {
    const res = await app.request("/", {
      headers: { Accept: "text/markdown" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    const body = await res.text();
    expect(body).toContain("# dmarcheck");
  });

  it("honors ?format=md on the scoring page", async () => {
    const res = await app.request("/scoring?format=md");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    expect(await res.text()).toContain("# dmarcheck scoring rubric");
  });

  it("keeps HTML as the default when Accept lists HTML first", async () => {
    const res = await app.request("/", {
      headers: { Accept: "text/html,application/xhtml+xml" },
    });
    expect(res.headers.get("Content-Type")).toContain("text/html");
  });

  it("returns a 400 markdown error when /check has no domain and Accept: text/markdown", async () => {
    const res = await app.request("/check", {
      headers: { Accept: "text/markdown" },
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    expect(await res.text()).toContain("# Error");
  });

  it("noindexes markdown responses", async () => {
    const res = await app.request("/", {
      headers: { Accept: "text/markdown" },
    });
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
  });
});

describe("/.well-known/agent-skills/index.json", () => {
  it("returns a v0.2.0 skills index with sha256 digests", async () => {
    const res = await app.request("/.well-known/agent-skills/index.json");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "application/json; charset=utf-8",
    );
    const body = (await res.json()) as {
      $schema: string;
      skills: Array<{
        name: string;
        type: string;
        description: string;
        url: string;
        sha256: string;
      }>;
    };
    expect(body.$schema).toContain("agent-skills-discovery-rfc");
    expect(body.skills.length).toBeGreaterThanOrEqual(2);
    const types = body.skills.map((s) => s.type);
    expect(types).toContain("markdown");
    expect(types).toContain("openapi");
    for (const skill of body.skills) {
      expect(skill.name).toBe("scan_domain");
      expect(skill.url).toMatch(/^https:\/\/dmarc\.mx\//);
      expect(skill.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("digest matches the served SKILL.md byte-for-byte", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{ type: string; url: string; sha256: string }>;
    };
    const markdownEntry = index.skills.find((s) => s.type === "markdown");
    expect(markdownEntry).toBeDefined();

    const skillRes = await app.request(
      "/.well-known/agent-skills/scan-domain/SKILL.md",
    );
    expect(skillRes.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    const text = await skillRes.text();
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(text),
    );
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(markdownEntry?.sha256);
  });

  it("openapi entry digest matches /openapi.json byte-for-byte", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{ type: string; url: string; sha256: string }>;
    };
    const openapiEntry = index.skills.find((s) => s.type === "openapi");
    expect(openapiEntry).toBeDefined();

    const openapiRes = await app.request("/openapi.json");
    const text = await openapiRes.text();
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(text),
    );
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(openapiEntry?.sha256);
  });
});

describe("/.well-known/agent-skills/scan-domain/SKILL.md", () => {
  it("renders the scan_domain skill in markdown", async () => {
    const res = await app.request(
      "/.well-known/agent-skills/scan-domain/SKILL.md",
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    const body = await res.text();
    expect(body).toContain("# scan_domain");
    expect(body).toContain("/api/check");
    expect(body).toContain("/openapi.json");
  });

  it("never mentions Retry-After, matching what rateLimitHeaders() actually emits (#709)", async () => {
    const res = await app.request(
      "/.well-known/agent-skills/scan-domain/SKILL.md",
    );
    const body = await res.text();
    expect(body).not.toContain("Retry-After");

    const headers = rateLimitHeaders({
      allowed: false,
      remaining: 0,
      limit: 10,
      windowSec: 60,
      resetAt: 0,
      count: 11,
    } satisfies RateLimitResult);
    expect(Object.keys(headers)).not.toContain("Retry-After");
    expect(headers).toHaveProperty("X-RateLimit-Reset");
  });
});

describe("WebMCP tool registration", () => {
  it("inlines the scan_domain tool definition in the client bundle", async () => {
    // Fetch the hashed JS asset. Follow the CSS_PATH/JS_PATH constants through
    // the landing page response so the test is resilient to content-hash
    // changes.
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    expect(match).toBeTruthy();
    const jsPath = match?.[1];
    expect(jsPath).toBeTruthy();
    const js = await (await app.request(jsPath as string)).text();
    expect(js).toContain("navigator.modelContext");
    expect(js).toContain("scan_domain");
    expect(js).toContain("/api/check");
  });
});
