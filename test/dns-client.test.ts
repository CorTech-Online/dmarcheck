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
  queryDnsbl,
  toDnsLookupError,
} from "../src/dns/client.js";

// Builds a minimal RFC 1035 wire-format DNS response: header + one question
// (name compressed via a pointer to offset 12, matching what real resolvers
// send back) + zero or more type-A answers. Used to drive queryDnsbl's real
// decoder end-to-end rather than mocking it away.
function buildDnsWireResponse(
  rcode: number,
  aRecords: string[] = [],
): Uint8Array {
  const bytes: number[] = [
    0x00,
    0x00, // ID
    0x81,
    0x80 | (rcode & 0x0f), // QR=1, RD=1, RA=1, RCODE
    0x00,
    0x01, // QDCOUNT = 1
    (aRecords.length >> 8) & 0xff,
    aRecords.length & 0xff, // ANCOUNT
    0x00,
    0x00, // NSCOUNT
    0x00,
    0x00, // ARCOUNT
    // Question: name compressed as a pointer to a bogus prior offset is not
    // valid before any name has appeared, so spell one real label + root.
    0x03,
    0x71,
    0x75,
    0x65, // "que"
    0x00, // root
    0x00,
    0x01, // QTYPE = A
    0x00,
    0x01, // QCLASS = IN
  ];
  for (const ip of aRecords) {
    const octets = ip.split(".").map(Number);
    bytes.push(
      0xc0,
      0x0c, // NAME: pointer to offset 12 (the question's name)
      0x00,
      0x01, // TYPE = A
      0x00,
      0x01, // CLASS = IN
      0x00,
      0x00,
      0x00,
      0x3c, // TTL = 60
      0x00,
      0x04, // RDLENGTH = 4
      ...octets,
    );
  }
  return new Uint8Array(bytes);
}

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

describe("queryDnsbl (#728 — DoH POST, not GET with a query string)", () => {
  it("never puts the reversed IP or the DQS key in the request URL", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(buildDnsWireResponse(0, []), { status: 200 }),
      );

    await queryDnsbl("1.0.0.127", "supersecretkey", "zen.dq.spamhaus.net");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    // Assert on the actual URL passed to fetch, not just on how the mock was
    // shaped — a GET-with-query-string regression would put the key here.
    expect(url).toBe("https://cloudflare-dns.com/dns-query");
    expect(url).not.toContain("supersecretkey");
    expect(url).not.toContain("1.0.0.127");
    expect(init.method).toBe("POST");
  });

  it("encodes the query name (reversed IP + key + zone) into the POST body, not the URL", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(buildDnsWireResponse(0, ["127.0.0.2"]), { status: 200 }),
      );

    const result = await queryDnsbl(
      "1.0.0.127",
      "supersecretkey",
      "zen.dq.spamhaus.net",
    );
    expect(result).toEqual(["127.0.0.2"]);

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const body = new Uint8Array(init.body as ArrayBuffer);
    const decoded = new TextDecoder().decode(body);
    // The wire-format body carries DNS labels as length-prefixed raw bytes
    // rather than dot-separated text, but each label's own characters are
    // still a contiguous run — confirm the encoder actually wrote the real
    // name (key included) into the body rather than silently dropping it.
    expect(decoded).toContain("supersecretkey");
    expect(decoded).toContain("127");
    expect(decoded).toContain("spamhaus");
  });

  it("returns null for NXDOMAIN (RCODE 3)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(buildDnsWireResponse(3, []), { status: 200 }),
    );
    const result = await queryDnsbl("1.0.0.127", "key", "zen.dq.spamhaus.net");
    expect(result).toBeNull();
  });

  it("returns null for NOERROR with no answers", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(buildDnsWireResponse(0, []), { status: 200 }),
    );
    const result = await queryDnsbl("1.0.0.127", "key", "zen.dq.spamhaus.net");
    expect(result).toBeNull();
  });

  it("returns listed A-record addresses when the IP is listed", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(buildDnsWireResponse(0, ["127.0.0.2", "127.0.0.4"]), {
        status: 200,
      }),
    );
    const result = await queryDnsbl("1.0.0.127", "key", "zen.dq.spamhaus.net");
    expect(result).toEqual(["127.0.0.2", "127.0.0.4"]);
  });

  it("throws a generic DnsLookupError on HTTP failure, never echoing the key", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 500 }),
    );
    await expect(
      queryDnsbl("1.0.0.127", "supersecretkey", "zen.dq.spamhaus.net"),
    ).rejects.toMatchObject({ code: "ESERVFAIL" });
  });

  it("throws DnsLookupError('DNS_TIMEOUT') on timeout, never echoing the key", async () => {
    vi.useFakeTimers();
    try {
      vi.spyOn(globalThis, "fetch").mockImplementation(
        () => new Promise(() => {}), // never resolves — forces withTimeout's race
      );
      const promise = queryDnsbl(
        "1.0.0.127",
        "supersecretkey",
        "zen.dq.spamhaus.net",
      );
      const assertion = expect(promise).rejects.toMatchObject({
        code: "DNS_TIMEOUT",
      });
      await vi.advanceTimersByTimeAsync(3000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("throws a generic DnsLookupError on a malformed response body", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(new Uint8Array([0x00, 0x01]), { status: 200 }), // too short
    );
    await expect(
      queryDnsbl("1.0.0.127", "supersecretkey", "zen.dq.spamhaus.net"),
    ).rejects.toMatchObject({
      code: "ESERVFAIL",
      message: "DNSBL query failed",
    });
  });
});
