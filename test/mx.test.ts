import { beforeEach, describe, expect, it, vi } from "vitest";
import { queryMx } from "../src/dns/client.js";

vi.mock("../src/dns/client.js", () => ({
  queryMx: vi.fn(),
}));

const mockQueryMx = vi.mocked(queryMx);

// Import after mock
const { analyzeMx, detectProviders } = await import("../src/analyzers/mx.js");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("detectProviders", () => {
  it("detects Google Workspace from google.com exchange", () => {
    const providers = detectProviders([{ exchange: "aspmx.l.google.com" }]);
    expect(providers).toEqual([
      { name: "Google Workspace", category: "email-platform" },
    ]);
  });

  it("detects Proofpoint from pphosted.com exchange", () => {
    const providers = detectProviders([{ exchange: "mx1.pphosted.com" }]);
    expect(providers).toEqual([
      { name: "Proofpoint", category: "security-gateway" },
    ]);
  });

  it("detects Microsoft 365 from protection.outlook.com exchange", () => {
    const providers = detectProviders([
      { exchange: "example-com.mail.protection.outlook.com" },
    ]);
    expect(providers).toEqual([
      { name: "Microsoft 365", category: "email-platform" },
    ]);
  });

  it("deduplicates providers from multiple MX records", () => {
    const providers = detectProviders([
      { exchange: "mx1.pphosted.com" },
      { exchange: "mx2.pphosted.com" },
    ]);
    expect(providers).toHaveLength(1);
    expect(providers[0].name).toBe("Proofpoint");
  });

  it("detects multiple distinct providers", () => {
    const providers = detectProviders([
      { exchange: "mx1.pphosted.com" },
      { exchange: "aspmx.l.google.com" },
    ]);
    expect(providers).toHaveLength(2);
    expect(providers.map((p) => p.name)).toContain("Proofpoint");
    expect(providers.map((p) => p.name)).toContain("Google Workspace");
  });

  it("returns empty array for unknown exchanges", () => {
    const providers = detectProviders([
      { exchange: "mail.custom-server.example.org" },
    ]);
    expect(providers).toEqual([]);
  });

  it("handles trailing dots in exchange hostnames", () => {
    const providers = detectProviders([{ exchange: "aspmx.l.google.com." }]);
    expect(providers).toEqual([
      { name: "Google Workspace", category: "email-platform" },
    ]);
  });

  it("detects Cloudflare Email Security from cf-emailsecurity.net exchange", () => {
    const providers = detectProviders([
      { exchange: "mxa.global.inbound.cf-emailsecurity.net" },
      { exchange: "mxb.global.inbound.cf-emailsecurity.net" },
    ]);
    expect(providers).toEqual([
      { name: "Cloudflare Email Security", category: "security-gateway" },
    ]);
  });

  it("detects MX Guarddog across all three junkemailfilter TLDs", () => {
    for (const exchange of [
      "mx.junkemailfilter.com",
      "mx.junkemailfilter.net",
      "mx.junkemailfilter.org",
    ]) {
      expect(detectProviders([{ exchange }]), exchange).toEqual([
        { name: "MX Guarddog", category: "security-gateway" },
      ]);
    }
  });

  it("does not report Cloudflare Email Routing as a security gateway", () => {
    // Email Routing (mx.cloudflare.net) is forwarding, not filtering — it must
    // not be confused with Cloudflare Email Security (cf-emailsecurity.net).
    const providers = detectProviders([
      { exchange: "route1.mx.cloudflare.net" },
    ]);
    expect(providers).toEqual([]);
  });
});

describe("analyzeMx", () => {
  it("returns empty result when no MX records exist", async () => {
    mockQueryMx.mockResolvedValue(null);
    const result = await analyzeMx("example.com");
    expect(result.status).toBe("info");
    expect(result.records).toEqual([]);
    expect(result.providers).toEqual([]);
    expect(result.validations).toHaveLength(1);
    expect(result.validations[0].message).toContain("No MX records");
  });

  it("recognizes a Null MX (RFC 7505) as an intentional no-mail posture", async () => {
    mockQueryMx.mockResolvedValue([{ priority: 0, exchange: "." }]);
    const result = await analyzeMx("example.com");
    expect(result.status).toBe("info");
    expect(
      result.validations.some(
        (v) => v.status === "info" && v.message.includes("Null MX"),
      ),
    ).toBe(true);
    // The empty root exchange must not surface as a host named "."
    expect(
      result.records.some((r) => r.exchange === "" || r.exchange === "."),
    ).toBe(false);
  });

  it("sorts records by priority ascending", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 30, exchange: "backup.example.com" },
      { priority: 10, exchange: "primary.example.com" },
      { priority: 20, exchange: "secondary.example.com" },
    ]);
    const result = await analyzeMx("example.com");
    expect(result.records.map((r) => r.priority)).toEqual([10, 20, 30]);
  });

  it("strips trailing dots from exchange hostnames", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 10, exchange: "aspmx.l.google.com." },
    ]);
    const result = await analyzeMx("example.com");
    expect(result.records[0].exchange).toBe("aspmx.l.google.com");
  });

  it("annotates each record with its matched provider", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 10, exchange: "mx1.pphosted.com" },
      { priority: 20, exchange: "mail.custom.org" },
    ]);
    const result = await analyzeMx("example.com");
    expect(result.records[0].provider?.name).toBe("Proofpoint");
    expect(result.records[1].provider).toBeUndefined();
  });

  it("includes detected providers in result", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 10, exchange: "mx1.pphosted.com" },
    ]);
    const result = await analyzeMx("example.com");
    expect(result.providers).toHaveLength(1);
    expect(result.providers[0].name).toBe("Proofpoint");
  });

  it("includes record count in validations", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 10, exchange: "mx1.example.com" },
      { priority: 20, exchange: "mx2.example.com" },
    ]);
    const result = await analyzeMx("example.com");
    expect(result.validations[0].message).toContain("2 MX records");
  });

  it("includes provider names in validations when detected", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 10, exchange: "aspmx.l.google.com" },
    ]);
    const result = await analyzeMx("example.com");
    const providerValidation = result.validations.find((v) =>
      v.message.includes("Detected"),
    );
    expect(providerValidation).toBeDefined();
    expect(providerValidation?.message).toContain("Google Workspace");
  });

  it("always returns status info", async () => {
    mockQueryMx.mockResolvedValue([
      { priority: 10, exchange: "mail.example.com" },
    ]);
    const result = await analyzeMx("example.com");
    expect(result.status).toBe("info");
  });
});
