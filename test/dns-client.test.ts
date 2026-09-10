import { describe, expect, it, vi } from "vitest";

// node:dns is stubbed only so importing the client doesn't reach the network.
// Deliberately NOT a per-Resolver-instance failure model: workerd's Resolver
// is a stateless pass-through with no per-instance query state, so a test
// asserting a per-instance limit would encode a mechanism that does not
// exist (#700).
vi.mock("node:dns", () => ({
  default: {
    promises: {
      Resolver: class {
        setServers() {}
        async resolveMx() {
          return [{ priority: 10, exchange: "mail.example.com" }];
        }
        async resolveTxt() {
          return [["v=spf1 -all"]];
        }
      },
    },
  },
}));

vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

import {
  DnsLookupError,
  parseDnsServers,
  toDnsLookupError,
} from "../src/dns/client.js";

describe("parseDnsServers", () => {
  it("returns null when raw is undefined", () => {
    expect(parseDnsServers(undefined)).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(parseDnsServers("")).toBeNull();
  });

  it("returns null when only whitespace and separators are present", () => {
    expect(parseDnsServers(" , , ")).toBeNull();
  });

  it("returns a single server", () => {
    expect(parseDnsServers("8.8.8.8")).toEqual(["8.8.8.8"]);
  });

  it("splits a comma-separated list", () => {
    expect(parseDnsServers("8.8.8.8,1.1.1.1")).toEqual(["8.8.8.8", "1.1.1.1"]);
  });

  it("trims whitespace around each entry", () => {
    expect(parseDnsServers(" 8.8.8.8 , 1.1.1.1 ")).toEqual([
      "8.8.8.8",
      "1.1.1.1",
    ]);
  });

  it("drops empty entries from trailing/leading commas", () => {
    expect(parseDnsServers(",8.8.8.8,,1.1.1.1,")).toEqual([
      "8.8.8.8",
      "1.1.1.1",
    ]);
  });
});

describe("toDnsLookupError (#700)", () => {
  it("maps EBADQUERY to a DnsLookupError instead of returning null", () => {
    const err = Object.assign(new Error("queryMX EBADQUERY example.com"), {
      code: "EBADQUERY",
    });
    const result = toDnsLookupError(err);
    expect(result).toBeInstanceOf(DnsLookupError);
    expect(result?.code).toBe("EBADQUERY");
  });

  it("maps an arbitrary unrecognized DNS error code to a DnsLookupError", () => {
    const err = Object.assign(new Error("something went wrong"), {
      code: "ECONNREFUSED",
    });
    const result = toDnsLookupError(err);
    expect(result).toBeInstanceOf(DnsLookupError);
    expect(result?.code).toBe("ECONNREFUSED");
  });

  it("still maps ESERVFAIL as before", () => {
    const err = Object.assign(new Error("servfail"), { code: "ESERVFAIL" });
    const result = toDnsLookupError(err);
    expect(result?.code).toBe("ESERVFAIL");
  });

  it("still maps the timeout sentinel error", () => {
    const result = toDnsLookupError(new Error("DNS timeout"));
    expect(result?.code).toBe("DNS_TIMEOUT");
  });

  it("returns null for an error with no code (not a DNS-shaped error)", () => {
    expect(toDnsLookupError(new Error("unexpected"))).toBeNull();
  });
});
