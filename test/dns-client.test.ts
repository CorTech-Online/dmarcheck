import { describe, expect, it, vi } from "vitest";

// #700 — each Resolver instance "dies" (throws EBADQUERY on every subsequent
// call) once it exceeds PER_INSTANCE_LIMIT queries, simulating the c-ares
// handle exhaustion a long cron run hits on a single reused handle. If
// src/dns/client.ts recreates the handle well before this point, no instance
// should ever see a call past its own limit.
const { instanceLog, PER_INSTANCE_LIMIT } = vi.hoisted(() => ({
  instanceLog: [] as number[],
  PER_INSTANCE_LIMIT: 60,
}));

vi.mock("node:dns", () => {
  class Resolver {
    private calls = 0;
    constructor() {
      instanceLog.push(0);
    }
    setServers() {}
    async resolveMx(name: string) {
      this.calls++;
      instanceLog[instanceLog.length - 1] = this.calls;
      if (this.calls > PER_INSTANCE_LIMIT) {
        throw Object.assign(new Error(`queryMX EBADQUERY ${name}`), {
          code: "EBADQUERY",
        });
      }
      return [{ priority: 10, exchange: "mail.example.com" }];
    }
    async resolveTxt() {
      throw Object.assign(new Error("queryTxt ENODATA"), { code: "ENODATA" });
    }
  }
  return { default: { promises: { Resolver } } };
});

vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

import {
  DnsLookupError,
  parseDnsServers,
  queryMx,
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

describe("resolver handle reset under sustained query volume (#700)", () => {
  it("recreates the resolver well before any single handle sees EBADQUERY across 300 sequential MX queries", async () => {
    const TOTAL = 300;
    for (let i = 0; i < TOTAL; i++) {
      const result = await queryMx(`domain-${i}.example`);
      expect(result).toEqual([{ priority: 10, exchange: "mail.example.com" }]);
    }

    // No instance was ever driven past its failure threshold — the reset
    // logic must have swapped in a fresh handle before that happened.
    expect(Math.max(...instanceLog)).toBeLessThanOrEqual(PER_INSTANCE_LIMIT);
    // Proof this isn't vacuous: the reset actually fired multiple times
    // across 300 queries rather than one handle happening to survive.
    expect(instanceLog.length).toBeGreaterThan(1);
  });
});
