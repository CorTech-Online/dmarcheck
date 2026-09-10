import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
  DnsLookupError: class DnsLookupError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.name = "DnsLookupError";
      this.code = code;
    }
  },
}));

import { analyzeDmarc } from "../src/analyzers/dmarc.js";
import { analyzeMx } from "../src/analyzers/mx.js";
import { analyzeSpf } from "../src/analyzers/spf.js";
import { DnsLookupError, queryMx, queryTxt } from "../src/dns/client.js";
import { computeGradeBreakdown } from "../src/shared/scoring.js";

const mockQueryTxt = vi.mocked(queryTxt);
const mockQueryMx = vi.mocked(queryMx);

function makeServfailError(): DnsLookupError {
  return new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)");
}

function makeTimeoutError(): DnsLookupError {
  return new DnsLookupError("DNS_TIMEOUT", "DNS query timed out");
}

// #700 — workerd's node:dns is a DoH client over fetch(); EBADQUERY means the
// outbound subrequest itself failed, so it says nothing about the domain.
function makeBadQueryError(): DnsLookupError {
  return new DnsLookupError(
    "EBADQUERY",
    "DNS query could not be sent (resolver unavailable)",
  );
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeDmarc with DNS lookup errors", () => {
  it("returns warn + lookup_error on SERVFAIL", async () => {
    mockQueryTxt.mockRejectedValue(makeServfailError());
    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("warn");
    expect(result.record).toBeNull();
    expect(result.tags).toBeNull();
    expect(result.lookup_error).toEqual({
      code: "ESERVFAIL",
      message: "DNS server failure (SERVFAIL)",
    });
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("ESERVFAIL"),
      ),
    ).toBe(true);
  });

  it("returns warn + lookup_error on DNS timeout", async () => {
    mockQueryTxt.mockRejectedValue(makeTimeoutError());
    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("warn");
    expect(result.lookup_error?.code).toBe("DNS_TIMEOUT");
  });

  it("returns warn + lookup_error on EBADQUERY, never a scored fail", async () => {
    mockQueryTxt.mockRejectedValue(makeBadQueryError());
    const result = await analyzeDmarc("appstate.edu");
    expect(result.status).toBe("warn");
    expect(result.lookup_error?.code).toBe("EBADQUERY");
  });

  it("re-throws non-DnsLookupError errors", async () => {
    mockQueryTxt.mockRejectedValue(new Error("unexpected error"));
    await expect(analyzeDmarc("example.com")).rejects.toThrow(
      "unexpected error",
    );
  });

  it("still returns fail when record is absent (NXDOMAIN)", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("fail");
    expect(result.lookup_error).toBeUndefined();
  });
});

describe("analyzeSpf with DNS lookup errors", () => {
  it("returns warn + lookup_error on SERVFAIL", async () => {
    mockQueryTxt.mockRejectedValue(makeServfailError());
    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("warn");
    expect(result.record).toBeNull();
    expect(result.lookup_error).toEqual({
      code: "ESERVFAIL",
      message: "DNS server failure (SERVFAIL)",
    });
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("ESERVFAIL"),
      ),
    ).toBe(true);
  });

  it("returns warn + lookup_error on DNS timeout", async () => {
    mockQueryTxt.mockRejectedValue(makeTimeoutError());
    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("warn");
    expect(result.lookup_error?.code).toBe("DNS_TIMEOUT");
  });

  it("returns warn + lookup_error on EBADQUERY, never a scored fail", async () => {
    mockQueryTxt.mockRejectedValue(makeBadQueryError());
    const result = await analyzeSpf("appstate.edu");
    expect(result.status).toBe("warn");
    expect(result.lookup_error?.code).toBe("EBADQUERY");
  });

  it("still returns fail when no SPF record exists", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("fail");
    expect(result.lookup_error).toBeUndefined();
  });
});

describe("analyzeMx with DNS lookup errors", () => {
  it("returns warn + lookup_error on SERVFAIL", async () => {
    mockQueryMx.mockRejectedValue(makeServfailError());
    const result = await analyzeMx("example.com");
    expect(result.status).toBe("warn");
    expect(result.records).toEqual([]);
    expect(result.lookup_error).toEqual({
      code: "ESERVFAIL",
      message: "DNS server failure (SERVFAIL)",
    });
  });

  it("returns warn + lookup_error on EBADQUERY, never a scored fail", async () => {
    mockQueryMx.mockRejectedValue(makeBadQueryError());
    const result = await analyzeMx("appstate.edu");
    expect(result.status).toBe("warn");
    expect(result.records).toEqual([]);
    expect(result.lookup_error?.code).toBe("EBADQUERY");
  });

  it("still returns info with empty records when no MX exists", async () => {
    mockQueryMx.mockResolvedValue(null);
    const result = await analyzeMx("example.com");
    expect(result.status).toBe("info");
    expect(result.lookup_error).toBeUndefined();
  });
});

describe("scoring with DMARC lookup_error", () => {
  const baseProtocols = {
    spf: {
      status: "pass" as const,
      record: "v=spf1 -all",
      lookups_used: 1,
      lookup_limit: 10,
      include_tree: null,
      validations: [],
    },
    dkim: {
      status: "pass" as const,
      selectors: { google: { found: true } },
      validations: [],
    },
    bimi: {
      status: "warn" as const,
      record: null,
      tags: null,
      validations: [],
    },
    mta_sts: {
      status: "warn" as const,
      dns_record: null,
      policy: null,
      validations: [],
    },
  };

  it("returns D grade when DMARC has lookup_error (not false F)", () => {
    const protocols = {
      ...baseProtocols,
      dmarc: {
        status: "warn" as const,
        record: null,
        tags: null,
        lookup_error: {
          code: "ESERVFAIL",
          message: "DNS server failure (SERVFAIL)",
        },
        validations: [
          {
            status: "warn" as const,
            message: "DMARC lookup failed (ESERVFAIL)",
          },
        ],
      },
    };
    const breakdown = computeGradeBreakdown(protocols);
    expect(breakdown.grade).toBe("D");
    expect(breakdown.tierReason).toContain("ESERVFAIL");
  });

  it("returns F when DMARC has no record and no lookup_error", () => {
    const protocols = {
      ...baseProtocols,
      dmarc: {
        status: "fail" as const,
        record: null,
        tags: null,
        validations: [
          { status: "fail" as const, message: "No DMARC record found" },
        ],
      },
    };
    const breakdown = computeGradeBreakdown(protocols);
    expect(breakdown.grade).toBe("F");
  });
});
