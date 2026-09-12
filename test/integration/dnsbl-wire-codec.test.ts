import { decode, encode, RECURSION_DESIRED } from "dns-packet";
import { describe, expect, it } from "vitest";

// This file runs inside the Cloudflare Workers runtime via
// `@cloudflare/vitest-pool-workers` (the "workers" project, real workerd —
// not a Node stand-in). `dns-packet` (#736, replacing #732's hand-rolled
// RFC 1035 codec) is Buffer-based, and Buffer is only available in workerd
// via the `nodejs_compat` flag — a Node-pool pass proves nothing about
// whether the library actually works in the runtime `queryDnsbl` (#728,
// `src/dns/client.ts`) runs in. This exercises the exact query shape
// queryDnsbl builds: `<reversed-ip>.<key>.<zone>`, type A.
const DNSBL_QUERY_NAME = "2.0.0.127.KEY.zen.dq.spamhaus.net";

describe("dns-packet wire codec (runs inside real workerd runtime, #736)", () => {
  it("encodes a type-A query and decodes it back to the same name/type", () => {
    const encoded = encode({
      type: "query",
      id: 0,
      flags: RECURSION_DESIRED,
      questions: [{ type: "A", name: DNSBL_QUERY_NAME }],
    });
    expect(encoded).toBeInstanceOf(Buffer);

    const decoded = decode(encoded);
    expect(decoded.questions).toHaveLength(1);
    expect(decoded.questions?.[0].name).toBe(DNSBL_QUERY_NAME);
    expect(decoded.questions?.[0].type).toBe("A");
  });

  it("decodes a synthetic type-A response the same way queryDnsbl does", () => {
    // A synthetic DQS-shaped response: NOERROR with one listing A record —
    // mirrors what queryDnsbl actually receives over the wire.
    const response = encode({
      type: "response",
      id: 0,
      flags: RECURSION_DESIRED,
      questions: [{ type: "A", name: DNSBL_QUERY_NAME }],
      answers: [
        { type: "A", name: DNSBL_QUERY_NAME, ttl: 60, data: "127.0.0.2" },
      ],
    });

    const decoded = decode(response);
    const rcode = (decoded.flags ?? 0) & 0x0f;
    expect(rcode).toBe(0); // NOERROR
    expect(decoded.answers).toHaveLength(1);
    expect(decoded.answers?.[0].type).toBe("A");
    expect(decoded.answers?.[0].data).toBe("127.0.0.2");
  });

  it("throws (never returns garbage) on a truncated/malformed buffer", () => {
    // queryDnsbl relies on decode() throwing here so a malformed body
    // surfaces as a generic DnsLookupError rather than a false "not listed".
    expect(() => decode(Buffer.from([0x00, 0x01]))).toThrow();
  });
});
