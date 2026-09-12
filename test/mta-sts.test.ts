import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeMtaSts, MAX_POLICY_BYTES } from "../src/analyzers/mta-sts.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
  vi.restoreAllMocks();
});

// fetchPolicy reads the body from resp.body with a stream reader, so the mock
// has to be a real Response with a real body stream — a bare object carrying
// an arrayBuffer() method no longer exercises the code under test.
function mockFetchPolicy(body: string | null, ok = true) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    body === null
      ? (new Response("", { status: 404 }) as unknown as Response)
      : (new Response(body, { status: ok ? 200 : 404 }) as unknown as Response),
  );
}

// A Response over a real stream that records how many chunks the consumer
// actually pulled. That count is the difference between bounding the read and
// buffering first: a reader that stops at the cap pulls only the chunks it
// needs, while resp.arrayBuffer() drains every chunk the sender offers.
function streamingResponse(body: string, chunkBytes: number) {
  const bytes = new TextEncoder().encode(body);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += chunkBytes) {
    chunks.push(bytes.subarray(i, i + chunkBytes));
  }
  const pulled = { chunks: 0 };
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (pulled.chunks >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[pulled.chunks]);
      pulled.chunks++;
    },
  });
  return {
    response: new Response(stream) as unknown as Response,
    pulled,
    totalChunks: chunks.length,
  };
}

function mockFetchError() {
  vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Network error"));
}

const validPolicy = `version: STSv1
mode: enforce
mx: *.example.com
mx: mail.example.com
max_age: 86400`;

describe("analyzeMtaSts", () => {
  it("returns fail when no DNS record and no policy file", async () => {
    mockQueryTxt.mockResolvedValue(null);
    mockFetchError();

    const result = await analyzeMtaSts("example.com");
    expect(result.status).toBe("fail");
    expect(result.dns_record).toBeNull();
    expect(result.policy).toBeNull();
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("No _mta-sts TXT record"),
      ),
    ).toBe(true);
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      ),
    ).toBe(true);
  });

  // f29 / GHSA-p676-gc7j-96mx — an attacker who controls mta-sts.<domain> must
  // not be able to stream an unbounded body into memory. The fetch body is
  // capped at MAX_POLICY_BYTES; anything past the cap is never parsed.
  it("caps the policy body and ignores content beyond MAX_POLICY_BYTES", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    // Valid directives in the first <64KB; a sentinel mx line pushed past the
    // cap by a giant colon-less (therefore ignored-by-parser) filler line.
    const prefix =
      "version: STSv1\nmode: enforce\nmx: legit.example.com\nmax_age: 86400\n";
    const filler = `${"#".repeat(MAX_POLICY_BYTES)}\n`;
    const sentinel = "mx: sneaky.evil.example\n";
    mockFetchPolicy(prefix + filler + sentinel);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mx).toContain("legit.example.com");
    // The sentinel sits beyond the byte cap, so it must never reach the parser.
    expect(result.policy?.mx).not.toContain("sneaky.evil.example");
  });

  // The cap has to be applied while reading, not after. resp.arrayBuffer()
  // resolves only once the whole body is resident in the isolate, so slicing
  // afterwards bounds parser cost but not peak memory — and the 3s
  // AbortSignal bounds elapsed time, not bytes. mta-sts.<domain> is derived
  // from a user-supplied domain on a public endpoint, so the sender is
  // attacker-controlled.
  it("stops reading the policy body once MAX_POLICY_BYTES is reached", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    const chunkBytes = 8 * 1024;
    const body = `version: STSv1\nmode: enforce\nmx: legit.example.com\nmax_age: 86400\n${"#".repeat(
      MAX_POLICY_BYTES * 8,
    )}\n`;
    const { response, pulled, totalChunks } = streamingResponse(
      body,
      chunkBytes,
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response);

    const result = await analyzeMtaSts("example.com");

    // Directives before the cap still parse exactly as they do today.
    expect(result.policy?.mx).toContain("legit.example.com");
    // The body is many times the cap, so a bounded read leaves most of it
    // unpulled. Two chunks of slack for stream read-ahead.
    expect(totalChunks).toBeGreaterThan(32);
    expect(pulled.chunks).toBeLessThanOrEqual(
      MAX_POLICY_BYTES / chunkBytes + 2,
    );
  });

  // The cancel() is best-effort cleanup. If it rejects, the bytes we already
  // read are still good — and fetchPolicy must never throw out to the
  // orchestrator, which would turn a live policy into a synthetic "fail".
  it("still parses the policy when cancelling the body rejects", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    const bytes = new TextEncoder().encode(
      `version: STSv1\nmode: enforce\nmx: legit.example.com\nmax_age: 86400\n${"#".repeat(
        MAX_POLICY_BYTES * 2,
      )}\n`,
    );
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(bytes.subarray(sent, sent + 8 * 1024));
        sent += 8 * 1024;
      },
      cancel() {
        throw new Error("connection already gone");
      },
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(stream) as unknown as Response,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mx).toContain("legit.example.com");
  });

  it("returns null policy when the response carries no body", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 200 }) as unknown as Response,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
  });

  it("passes when DNS record found with v=STSv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.dns_record).toBe("v=STSv1; id=20240101");
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" && v.message.includes("MTA-STS DNS record found"),
      ),
    ).toBe(true);
  });

  it("fails when TXT record exists but missing v=STSv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["some other txt record"],
      raw: "some other txt record",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.dns_record).toBeNull();
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("missing v=STSv1"),
      ),
    ).toBe(true);
  });

  it("detects enforce mode as pass", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mode).toBe("enforce");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("enforce"),
      ),
    ).toBe(true);
  });

  it("warns on testing mode", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(
      `version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 86400`,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mode).toBe("testing");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("testing"),
      ),
    ).toBe(true);
  });

  it("warns on none mode", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(
      `version: STSv1\nmode: none\nmx: *.example.com\nmax_age: 86400`,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mode).toBe("none");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("none"),
      ),
    ).toBe(true);
  });

  it("warns on low max_age (less than 1 day)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(
      `version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 3600`,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.max_age).toBe(3600);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("max_age"),
      ),
    ).toBe(true);
  });

  it("warns when no MX patterns in policy", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(`version: STSv1\nmode: enforce\nmax_age: 86400`);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mx).toEqual([]);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("No MX patterns"),
      ),
    ).toBe(true);
  });

  it("handles fetch failure gracefully", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchError();

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      ),
    ).toBe(true);
  });

  it("handles non-ok HTTP response gracefully", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(null);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
  });

  it("parses policy with multiple MX entries", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mx).toEqual(["*.example.com", "mail.example.com"]);
    expect(result.policy?.version).toBe("STSv1");
    expect(result.policy?.max_age).toBe(86400);
  });

  it("returns pass status when DNS and policy are both valid with enforce mode", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.status).toBe("pass");
  });

  // Regression guard for PRs #58 and #92: the policy fetch must use
  // redirect:"manual", NOT "error". `"error"` throws in the Cloudflare
  // Workers fetch runtime and breaks every scan. See src/analyzers/mta-sts.ts
  // and commit 2b47fe7 for the history.
  it("passes redirect:'manual' to fetch (regression guard for PR #58/#92)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      text: async () => validPolicy,
    } as Response);

    await analyzeMtaSts("example.com");

    expect(fetchSpy).toHaveBeenCalledWith(
      "https://mta-sts.example.com/.well-known/mta-sts.txt",
      expect.objectContaining({ redirect: "manual" }),
    );
  });

  it("returns null policy when fetch returns an opaque-redirect response", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 0,
      type: "opaqueredirect",
      text: async () => "",
    } as Response);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      ),
    ).toBe(true);
  });
});
