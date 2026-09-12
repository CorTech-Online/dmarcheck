import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeSecurityTxt } from "../src/analyzers/security-txt.js";

// Helper: mock the global fetch with a sequence of responses keyed by URL.
// First match wins; unmatched URLs return a 404.
function mockFetchByUrl(
  responses: Record<string, { body: string; ok?: boolean } | "throw">,
) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const r = responses[url];
    if (r === "throw") throw new Error("Network error");
    if (!r) {
      return { ok: false, type: "default" } as unknown as Response;
    }
    // fetchSecurityTxt reads from resp.body with a stream reader, so the mock
    // has to be a real Response with a real body stream.
    return new Response(r.body, {
      status: (r.ok ?? true) ? 200 : 404,
    }) as unknown as Response;
  });
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

beforeEach(() => {
  vi.resetAllMocks();
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("analyzeSecurityTxt", () => {
  it("returns info+null when neither URL responds", async () => {
    mockFetchByUrl({});
    const result = await analyzeSecurityTxt("example.com");
    expect(result.status).toBe("info");
    expect(result.fields).toBeNull();
    expect(result.source_url).toBeNull();
    expect(result.signed).toBe(false);
    expect(
      result.validations.some(
        (v) => v.status === "info" && v.message.includes("No security.txt"),
      ),
    ).toBe(true);
  });

  it("parses a valid file at the well-known URL", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const body = `# Comment line
Contact: mailto:security@example.com
Contact: https://example.com/security
Expires: ${future}
Encryption: https://example.com/pgp.asc
Policy: https://example.com/disclosure
Preferred-Languages: en, de
`;
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": { body },
    });

    const result = await analyzeSecurityTxt("example.com");
    expect(result.status).toBe("info");
    expect(result.source_url).toBe(
      "https://example.com/.well-known/security.txt",
    );
    expect(result.signed).toBe(false);
    expect(result.fields).not.toBeNull();
    expect(result.fields?.contact).toEqual([
      "mailto:security@example.com",
      "https://example.com/security",
    ]);
    expect(result.fields?.expires).toBe(future);
    expect(result.fields?.encryption).toEqual(["https://example.com/pgp.asc"]);
    expect(result.fields?.policy).toEqual(["https://example.com/disclosure"]);
    expect(result.fields?.preferred_languages).toBe("en, de");
  });

  it("falls back to /security.txt when /.well-known/ missing", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    mockFetchByUrl({
      "https://example.com/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: ${future}\n`,
      },
    });

    const result = await analyzeSecurityTxt("example.com");
    expect(result.source_url).toBe("https://example.com/security.txt");
    expect(result.fields?.contact).toEqual(["mailto:s@example.com"]);
  });

  it("falls back to /security.txt when /.well-known/ returns non-OK", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        ok: false,
        body: "",
      },
      "https://example.com/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: ${future}\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(result.source_url).toBe("https://example.com/security.txt");
  });

  it("warns when Contact: is missing", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Expires: ${future}\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("Contact"),
      ),
    ).toBe(true);
  });

  it("warns when Expires: is missing", async () => {
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Contact: mailto:s@example.com\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("Expires"),
      ),
    ).toBe(true);
  });

  it("warns when Expires: is in the past", async () => {
    const past = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: ${past}\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("in the past"),
      ),
    ).toBe(true);
  });

  it("informs when Expires: is more than a year out", async () => {
    const farFuture = new Date(
      Date.now() + 400 * 24 * 60 * 60 * 1000,
    ).toISOString();
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: ${farFuture}\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "info" && v.message.includes("more than a year"),
      ),
    ).toBe(true);
  });

  it("warns on unparseable Expires:", async () => {
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: not-a-date\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("not parseable"),
      ),
    ).toBe(true);
  });

  it("strips PGP cleartext-signature armor and flags signed", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const signed = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:s@example.com
Expires: ${future}
- -----This-line-is-dash-escaped-----

-----BEGIN PGP SIGNATURE-----
iQE... (snip)
-----END PGP SIGNATURE-----
`;
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": { body: signed },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(result.signed).toBe(true);
    expect(result.fields?.contact).toEqual(["mailto:s@example.com"]);
  });

  it("ignores unknown extension fields per RFC 9116 §2.4", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: ${future}\nFoo-Bar: ignored\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(result.status).toBe("info");
    // No throw, no Foo-Bar surfaced.
    expect(JSON.stringify(result.fields)).not.toContain("Foo-Bar");
  });

  it("accepts the British 'Acknowledgements' spelling", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    mockFetchByUrl({
      "https://example.com/.well-known/security.txt": {
        body: `Contact: mailto:s@example.com\nExpires: ${future}\nAcknowledgements: https://example.com/hall-of-fame\n`,
      },
    });
    const result = await analyzeSecurityTxt("example.com");
    expect(result.fields?.acknowledgments).toEqual([
      "https://example.com/hall-of-fame",
    ]);
  });

  it("returns info+null when fetch throws", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("DNS error"));
    const result = await analyzeSecurityTxt("example.com");
    expect(result.status).toBe("info");
    expect(result.fields).toBeNull();
  });

  // The cap has to be applied while reading, not after. resp.arrayBuffer()
  // resolves only once the whole body is resident in the isolate, so slicing
  // afterwards bounds parser cost but not peak memory — and the 3s
  // AbortSignal bounds elapsed time, not bytes. The URL is derived from a
  // user-supplied domain on a public endpoint, so the sender is
  // attacker-controlled.
  it("stops reading the body once MAX_BODY_BYTES is reached", async () => {
    const maxBodyBytes = 64 * 1024; // mirrors MAX_BODY_BYTES in the analyzer
    const chunkBytes = 8 * 1024;
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const body = `Contact: mailto:security@example.com\nExpires: ${future}\n${"#".repeat(
      maxBodyBytes * 8,
    )}\nContact: mailto:sneaky@evil.example\n`;
    const { response, pulled, totalChunks } = streamingResponse(
      body,
      chunkBytes,
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response);

    const result = await analyzeSecurityTxt("example.com");

    // Fields before the cap still parse exactly as they do today.
    expect(result.fields?.contact).toEqual(["mailto:security@example.com"]);
    // Anything past the cap never reaches the parser.
    expect(result.fields?.contact).not.toContain("mailto:sneaky@evil.example");
    // The body is many times the cap, so a bounded read leaves most of it
    // unpulled. Two chunks of slack for stream read-ahead.
    expect(totalChunks).toBeGreaterThan(32);
    expect(pulled.chunks).toBeLessThanOrEqual(maxBodyBytes / chunkBytes + 2);
  });

  // The cancel() is best-effort cleanup. If it rejects, the bytes we already
  // read are still good — and fetchSecurityTxt must never throw out to the
  // orchestrator, which would turn an informational card into a synthetic
  // "fail".
  it("still parses the file when cancelling the body rejects", async () => {
    const future = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const bytes = new TextEncoder().encode(
      `Contact: mailto:security@example.com\nExpires: ${future}\n${"#".repeat(
        64 * 1024 * 2,
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

    const result = await analyzeSecurityTxt("example.com");
    expect(result.fields?.contact).toEqual(["mailto:security@example.com"]);
  });

  it("returns info+null when the response carries no body", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 200 }) as unknown as Response,
    );
    const result = await analyzeSecurityTxt("example.com");
    expect(result.status).toBe("info");
    expect(result.fields).toBeNull();
  });
});
