import * as dnsPacket from "dns-packet";
import { describe, expect, it } from "vitest";

// This file runs inside the Cloudflare Workers runtime via
// `@cloudflare/vitest-pool-workers`. #736 replaced queryDnsbl's hand-rolled
// RFC 1035 wire-format encoder/decoder with the `dns-packet` library.
// `dns-packet` is Buffer-based, which works only because `nodejs_compat` is
// already on — the Node test pool can't verify that, since Node always has
// `Buffer`. This exercises the exact query shape `queryDnsbl` builds
// (`<reversed-ip>.<key>.<zone>`, type A) end-to-end inside real workerd.
describe("dns-packet encode/decode (runs inside real workerd runtime, #736)", () => {
  it("round-trips a DNSBL-shaped type-A query through encode and decode", () => {
    const name = "2.0.0.127.KEY.zen.dq.spamhaus.net";

    const query = dnsPacket.encode({
      type: "query",
      id: 0,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: "A", name }],
    });
    expect(query.length).toBeGreaterThan(12);

    const decodedQuery = dnsPacket.decode(query);
    expect(decodedQuery.questions?.[0]?.name).toBe(name);
    expect(decodedQuery.questions?.[0]?.type).toBe("A");

    // Build a synthetic type-A response the way a real resolver would,
    // using the encoder itself rather than hand-rolled bytes.
    const response = dnsPacket.encode({
      type: "response",
      id: 0,
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
      questions: [{ type: "A", name }],
      answers: [{ type: "A", name, ttl: 60, data: "127.0.0.2" }],
    });

    const decodedResponse = dnsPacket.decode(response) as dnsPacket.Packet & {
      rcode: string;
    };
    expect(decodedResponse.rcode).toBe("NOERROR");
    expect(decodedResponse.answers).toHaveLength(1);
    expect(decodedResponse.answers?.[0]).toMatchObject({
      type: "A",
      data: "127.0.0.2",
    });
  });

  it("decodes an NXDOMAIN response (RCODE 3) as queryDnsbl distinguishes it", () => {
    const name = "1.0.0.127.KEY.zen.dq.spamhaus.net";
    const nxdomain = dnsPacket.encode({
      type: "response",
      id: 0,
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE | 0x03, // RCODE 3
      questions: [{ type: "A", name }],
      answers: [],
    });

    const decoded = dnsPacket.decode(nxdomain) as dnsPacket.Packet & {
      rcode: string;
    };
    expect(decoded.rcode).toBe("NXDOMAIN");
    expect(decoded.answers).toHaveLength(0);
  });
});
