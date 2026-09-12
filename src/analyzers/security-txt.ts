import type {
  SecurityTxtFields,
  SecurityTxtResult,
  Validation,
} from "./types.js";

// RFC 9116 — security.txt. Informational analyzer (status always "info");
// does not affect the letter grade. security.txt is general domain-security
// hygiene, not part of the email authentication stack, so it surfaces as
// a separate card without nudging the email-security score.
//
// Fetch posture intentionally diverges from src/analyzers/mta-sts.ts:
//   - `redirect: "follow"` (NOT "manual"). RFC 9116 §3 doesn't forbid
//     redirects, and real-world deployments depend on them
//     (gov.uk → www.gov.uk → vdp.cabinetoffice.gov.uk). MTA-STS uses
//     "manual" because RFC 8461 §3.3 specifically forbids following
//     redirects on the policy fetch — a security-model requirement
//     security.txt does not share. See CLAUDE.md §Security.
//   - 3s timeout via AbortSignal.
//   - All fetch / decode / abort errors collapse to "no file found"
//     (informational), never throw out of the analyzer.

const FETCH_TIMEOUT_MS = 3000;
const MAX_BODY_BYTES = 64 * 1024; // RFC 9116 doesn't cap, but a 64KB ceiling
// is generous (real-world files are <2KB) and keeps a misconfigured server
// from streaming us megabytes.

function emptyFields(): SecurityTxtFields {
  return {
    contact: [],
    expires: null,
    encryption: [],
    policy: [],
    acknowledgments: [],
    preferred_languages: null,
    canonical: [],
    hiring: [],
  };
}

export async function analyzeSecurityTxt(
  domain: string,
): Promise<SecurityTxtResult> {
  // Try /.well-known/security.txt first (RFC 9116 §3 canonical location),
  // then the legacy /security.txt root fallback. The well-known URL wins
  // if both exist — that's what RFC 9116 §3 says.
  const wellKnown = `https://${domain}/.well-known/security.txt`;
  const fallback = `https://${domain}/security.txt`;

  const wkResp = await fetchSecurityTxt(wellKnown);
  if (wkResp) return finalize(wellKnown, wkResp);

  const fbResp = await fetchSecurityTxt(fallback);
  if (fbResp) return finalize(fallback, fbResp);

  return {
    status: "info",
    source_url: null,
    signed: false,
    fields: null,
    validations: [
      {
        status: "info",
        message: "No security.txt published (informational, not scored)",
      },
    ],
  };
}

async function fetchSecurityTxt(url: string): Promise<string | null> {
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "dmarcheck/1.0" },
      // `redirect: "follow"` — diverges from src/analyzers/mta-sts.ts
      // (which uses "manual") because RFC 9116 §3 does not forbid
      // redirects, and real-world security.txt deployments commonly
      // redirect (e.g. gov.uk → www.gov.uk → vdp.cabinetoffice.gov.uk).
      // RFC 8461 §3.3 specifically forbids following redirects on the
      // MTA-STS policy fetch for security-model reasons; security.txt
      // has no such constraint, so the user-friendly choice is to
      // follow. The fetch runtime caps the redirect chain itself, so
      // we don't need an explicit hop limit.
      redirect: "follow",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!resp.ok) {
      await discardBody(resp);
      return null;
    }

    // Bound the body AS IT ARRIVES, not after it lands. resp.arrayBuffer()
    // resolves only once the whole body is resident in the isolate, so
    // capping afterwards bounds parser cost but NOT peak memory — and a
    // Worker's 128 MB limit is shared by every concurrent request in the
    // isolate. The 3s AbortSignal bounds elapsed time, not bytes, and
    // Content-Length is whatever the sender claims. The URL is derived from
    // a user-supplied domain on a public endpoint, so the sender is
    // attacker-controlled. Read with a reader, stop at MAX_BODY_BYTES, then
    // cancel so the sender stops transmitting. Same control as mta-sts.
    const reader = resp.body?.getReader();
    if (!reader) return null;
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (total < MAX_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
    try {
      await reader.cancel();
    } catch {
      // Best-effort. A rejected cancel (aborted socket, already-disturbed
      // body) must not throw away the bytes we already read, and must not
      // escape: the contract is to return a result or null, never to throw.
    }

    return new TextDecoder("utf-8", {
      fatal: false,
      ignoreBOM: false,
    }).decode(concatCapped(chunks, total, MAX_BODY_BYTES));
  } catch {
    return null;
  }
}

// Release a response body we are not going to read, so the connection closes
// instead of waiting on a sender we have already rejected. Best-effort: a
// rejected cancel (already-disturbed body, aborted socket) must not escape,
// because fetchSecurityTxt's contract is to return null, never to throw.
async function discardBody(resp: Response): Promise<void> {
  try {
    await resp.body?.cancel();
  } catch {
    // Nothing to do — we are discarding this response either way.
  }
}

// Join the chunks we pulled into one buffer, truncated to `cap`. The final
// chunk can straddle the cap, so the truncation here — not the loop bound —
// is what makes the decoded bytes identical to the pre-streaming
// arrayBuffer()+slice(0, cap) output.
function concatCapped(
  chunks: Uint8Array[],
  total: number,
  cap: number,
): Uint8Array {
  const out = new Uint8Array(Math.min(total, cap));
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= out.length) break;
    const take = Math.min(chunk.byteLength, out.length - offset);
    out.set(chunk.subarray(0, take), offset);
    offset += take;
  }
  return out;
}

function finalize(sourceUrl: string, raw: string): SecurityTxtResult {
  const { body, signed } = stripPgpArmor(raw);
  const fields = parseFields(body);

  const validations: Validation[] = [];
  validations.push({
    status: "info",
    message: `Found at ${sourceUrl}`,
  });
  if (signed) {
    validations.push({
      status: "info",
      message: "PGP cleartext-signature armor detected",
    });
  }

  // RFC 9116 §2.5.3: Contact is REQUIRED and at least one MUST be present.
  if (fields.contact.length === 0) {
    validations.push({
      status: "warn",
      message: "Missing required Contact: field (RFC 9116 §2.5.3)",
    });
  } else {
    validations.push({
      status: "info",
      message: `${fields.contact.length} Contact entr${
        fields.contact.length === 1 ? "y" : "ies"
      }`,
    });
  }

  // RFC 9116 §2.5.5: Expires is REQUIRED, ISO 8601 format, MUST NOT be in
  // the past — and SHOULD be no more than a year out.
  if (!fields.expires) {
    validations.push({
      status: "warn",
      message: "Missing required Expires: field (RFC 9116 §2.5.5)",
    });
  } else {
    const expiresMs = Date.parse(fields.expires);
    if (Number.isNaN(expiresMs)) {
      validations.push({
        status: "warn",
        message: `Expires: not parseable as ISO 8601 (got "${fields.expires}")`,
      });
    } else if (expiresMs < Date.now()) {
      validations.push({
        status: "warn",
        message: `Expires: ${fields.expires} is in the past — file is stale`,
      });
    } else {
      const oneYearMs = 365 * 24 * 60 * 60 * 1000;
      if (expiresMs - Date.now() > oneYearMs) {
        validations.push({
          status: "info",
          message: `Expires: ${fields.expires} is more than a year out (RFC 9116 §2.5.5 SHOULD)`,
        });
      } else {
        validations.push({
          status: "info",
          message: `Expires: ${fields.expires}`,
        });
      }
    }
  }

  return {
    status: "info",
    source_url: sourceUrl,
    signed,
    fields,
    validations,
  };
}

// RFC 9116 §2.3: a security.txt file MAY be PGP-cleartext-signed. Strip
// the armor headers and trailing signature block before parsing so the
// signed body parses identically to an unsigned one.
function stripPgpArmor(raw: string): { body: string; signed: boolean } {
  const beginCleartext = raw.indexOf("-----BEGIN PGP SIGNED MESSAGE-----");
  if (beginCleartext === -1) return { body: raw, signed: false };

  const afterCleartextHeader = raw.indexOf("\n\n", beginCleartext);
  if (afterCleartextHeader === -1) return { body: raw, signed: true };

  const beginSignature = raw.indexOf(
    "-----BEGIN PGP SIGNATURE-----",
    afterCleartextHeader,
  );
  const bodyEnd = beginSignature === -1 ? raw.length : beginSignature;

  return {
    body: raw.slice(afterCleartextHeader + 2, bodyEnd),
    signed: true,
  };
}

function parseFields(body: string): SecurityTxtFields {
  const fields = emptyFields();

  let start = 0;
  while (start < body.length) {
    let end = body.indexOf("\n", start);
    if (end === -1) end = body.length;
    const line = body.slice(start, end).trim();
    start = end + 1;

    if (!line) continue;
    if (line.startsWith("#")) continue;
    // PGP cleartext-signature dash-escaping: per RFC 4880 §7.1, lines
    // starting with "- " in the signed body must be unescaped to "".
    const unescaped = line.startsWith("- ") ? line.slice(2) : line;

    const colonIdx = unescaped.indexOf(":");
    if (colonIdx === -1) continue;

    const key = unescaped.slice(0, colonIdx).trim().toLowerCase();
    const value = unescaped.slice(colonIdx + 1).trim();
    if (!value) continue;

    switch (key) {
      case "contact":
        fields.contact.push(value);
        break;
      case "expires":
        // RFC 9116 §2.5.5: at most one Expires field. If multiple are
        // present, last-write-wins matches what most clients do.
        fields.expires = value;
        break;
      case "encryption":
        fields.encryption.push(value);
        break;
      case "policy":
        fields.policy.push(value);
        break;
      case "acknowledgments":
      case "acknowledgements": // common misspelling; accept both
        fields.acknowledgments.push(value);
        break;
      case "preferred-languages":
        fields.preferred_languages = value;
        break;
      case "canonical":
        fields.canonical.push(value);
        break;
      case "hiring":
        fields.hiring.push(value);
        break;
      // Unknown fields ignored per RFC 9116 §2.4 ("Extension Fields"
      // — parsers MUST accept and ignore unrecognized fields).
    }
  }

  return fields;
}
