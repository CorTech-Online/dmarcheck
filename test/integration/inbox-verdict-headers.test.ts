import { describe, expect, it, vi } from "vitest";
import { handleInboundEmail, parseVerdict } from "../../src/inbox/store.js";
import { tokenFromAddress } from "../../src/inbox/tokens.js";
import { FakeKV } from "../helpers/fake-kv.js";

// Runs inside the real Cloudflare Workers runtime via
// `@cloudflare/vitest-pool-workers` (issue #731). `test/inbox-store.test.ts`
// covers `parseVerdict` in the Node pool, which constructs `Headers` itself —
// so the behavior of the `set_forwardable_email_full_headers` compatibility
// flag (default-on 2025-08-01, crossed by PR #727) on *repeated* headers is
// reasoned about there but never executed against workerd's real `Headers`.
// A message carrying two `DKIM-Signature` headers (sender + forwarder) is
// ordinary mail, and `Headers.get()` joins repeats with ", " per the Fetch
// spec — these tests pin what `parseVerdict` actually does with that joined
// value in the runtime that will really deliver it.

const TOKEN = "aabbccddeeff00112233445566778899";

describe("parseVerdict against workerd's real Headers (repeated headers)", () => {
  it("still prefers the DMARC-From-aligned DKIM signature over an unaligned one", () => {
    const headers = new Headers({
      "Authentication-Results":
        "mx; dkim=pass header.d=relay.example header.s=cf1; dkim=pass header.d=example.com header.s=selector1; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com",
    });
    const v = parseVerdict(headers, "bounce@relay.example", 2048);
    expect(v.dkim).toBe("pass");
    expect(v.dkim_domain).toBe("example.com");
    expect(v.dkim_selector).toBe("selector1");
    expect(v.dmarc).toBe("pass");
    expect(v.alignment).toBe("pass");
  });

  it("joins repeated DKIM-Signature headers with ', ' and degrades a corrupted fallback tag to null rather than a wrong value", () => {
    // Authentication-Results deliberately omits header.d/header.s so the
    // selector/domain fall back to the raw DKIM-Signature header — the path
    // that actually reads the joined value.
    const authResults =
      "mx; dkim=pass; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com";
    // `s=` is the last tag in the first signature, so joining with ", "
    // (not ";") lets the capture spill past the join boundary into the
    // second signature before the next ";" — the realistic case where a
    // fallback regex built for one header sees two.
    const sig1 = "v=1; a=rsa-sha256; d=example.com; s=selector1";
    const sig2 = "v=1; a=rsa-sha256; d=forwarder.example; s=selector2";
    const headers = new Headers([
      ["Authentication-Results", authResults],
      ["DKIM-Signature", sig1],
      ["DKIM-Signature", sig2],
    ]);

    // Pin the observed workerd join behavior this test depends on.
    expect(headers.get("DKIM-Signature")).toBe(`${sig1}, ${sig2}`);

    const v = parseVerdict(headers, "sender@example.com", 4096);
    expect(v.dkim).toBe("pass");
    // The d= tag has a trailing ";" before the join point, so it extracts
    // cleanly — the first signature's own domain, not a hybrid of the two.
    expect(v.dkim_domain).toBe("example.com");
    // The s= tag is last, so its capture spills across the ", " join and
    // picks up the next signature's "v=1; a=rsa-sha256" before the next
    // ";" — failing the selector charset check. Fail-closed null, never
    // "selector1, v=1" and never the second signature's selector.
    expect(v.dkim_selector).toBeNull();
  });

  it("resolves a repeated Received-SPF fallback to the first hop's result, not a joined value", () => {
    // No spf= clause in Authentication-Results forces the Received-SPF
    // fallback; two hops each stamping their own Received-SPF is ordinary
    // for forwarded mail.
    const headers = new Headers([
      [
        "Authentication-Results",
        "mx; dkim=pass header.d=example.com header.s=sel1; dmarc=none",
      ],
      ["Received-SPF", "softfail (mx: does not designate sender as permitted)"],
      ["Received-SPF", "pass (relay2: designates sender as permitted)"],
    ]);

    expect(headers.get("Received-SPF")).toBe(
      "softfail (mx: does not designate sender as permitted), pass (relay2: designates sender as permitted)",
    );

    const v = parseVerdict(headers, "sender@example.com", 512);
    // The fallback regex is anchored to the start of the (possibly joined)
    // string, so it reads only the first hop's leading token — never a
    // value bled in from the second, joined-in header.
    expect(v.spf).toBe("softfail");
  });

  it("treats message.to as envelope-based and charset-validated — a crafted multi-value address writes no KV key", () => {
    // message.to is a single string, not a Headers-style repeatable field,
    // but a sender-controlled address list smuggled in ahead of a
    // legitimate-looking one must not be treated as a match.
    const crafted = `attacker@evil.com, inbox+${TOKEN}@dmarc.mx`;
    expect(tokenFromAddress(crafted)).toBeNull();

    const kv = new FakeKV();
    const putSpy = vi.spyOn(kv, "put");
    return handleInboundEmail(
      {
        to: crafted,
        from: "attacker@evil.com",
        rawSize: 100,
        headers: new Headers({ "Authentication-Results": "mx; spf=pass" }),
        raw: new ReadableStream(),
        setReject() {},
        forward: async () => undefined,
        reply: async () => undefined,
      } as unknown as ForwardableEmailMessage,
      kv.asKv(),
    ).then(() => {
      expect(putSpy).not.toHaveBeenCalled();
    });
  });
});
