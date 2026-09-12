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
    return {
      ok: r.ok ?? true,
      type: "default",
      arrayBuffer: async () => new TextEncoder().encode(r.body).buffer,
    } as unknown as Response;
  });
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

  // #716 — a discarded non-ok response body should be cancelled per
  // Cloudflare's fetch() guidance, without a rejected cancel() propagating.
  it("cancels the response body on a non-ok response without throwing when cancel() rejects", async () => {
    const cancel = vi.fn().mockRejectedValue(new Error("already cancelled"));
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async () =>
        ({
          ok: false,
          type: "default",
          body: { cancel },
        }) as unknown as Response,
    );

    const result = await analyzeSecurityTxt("example.com");
    // Called once per fetch attempt: well-known, then the /security.txt fallback.
    expect(cancel).toHaveBeenCalledTimes(2);
    expect(result.fields).toBeNull();
  });
});
