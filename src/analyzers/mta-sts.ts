import { queryTxt } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import type { MtaStsPolicy, MtaStsResult, Validation } from "./types.js";

// Cap the fetched policy body before decoding it (GHSA-p676-gc7j-96mx). RFC 8461
// policies are tiny, but an attacker who controls mta-sts.<domain> could
// otherwise stream an unbounded body into the isolate. This mirrors the
// MAX_BODY_BYTES ceiling that src/analyzers/security-txt.ts already applies.
export const MAX_POLICY_BYTES = 64 * 1024;

export async function analyzeMtaSts(
  domain: string,
  budget?: ScanBudget,
): Promise<MtaStsResult> {
  const [dnsResult, policyResult] = await Promise.allSettled([
    queryTxt(`_mta-sts.${domain}`, budget),
    fetchPolicy(domain),
  ]);

  const txt = dnsResult.status === "fulfilled" ? dnsResult.value : null;
  const policy =
    policyResult.status === "fulfilled" ? policyResult.value : null;

  const validations: Validation[] = [];

  // DNS record check
  let dnsRecord: string | null = null;
  if (txt) {
    const stsRecord = txt.entries.find((e) => e.includes("v=STSv1"));
    if (stsRecord) {
      dnsRecord = stsRecord;
      validations.push({
        status: "pass",
        message: "MTA-STS DNS record found (v=STSv1)",
      });
    } else {
      validations.push({
        status: "fail",
        message: "TXT record exists but missing v=STSv1",
      });
    }
  } else {
    validations.push({
      status: "fail",
      message: `No _mta-sts TXT record found`,
    });
  }

  // Policy file check
  if (policy) {
    validations.push({
      status: "pass",
      message: `Policy file fetched from https://mta-sts.${domain}/.well-known/mta-sts.txt`,
    });

    if (policy.mode === "enforce") {
      validations.push({
        status: "pass",
        message: "Policy mode is enforce (full protection)",
      });
    } else if (policy.mode === "testing") {
      validations.push({
        status: "warn",
        message: "Policy mode is testing (reports only, not enforced)",
      });
    } else if (policy.mode === "none") {
      validations.push({
        status: "warn",
        message: "Policy mode is none (MTA-STS effectively disabled)",
      });
    }

    if (policy.max_age < 86400) {
      validations.push({
        status: "warn",
        message: `max_age is ${policy.max_age}s (less than 1 day) — consider increasing`,
      });
    }

    if (policy.mx.length === 0) {
      validations.push({
        status: "warn",
        message: "No MX patterns specified in policy",
      });
    }
  } else {
    validations.push({
      status: "fail",
      message: `Policy file not accessible at https://mta-sts.${domain}/.well-known/mta-sts.txt`,
    });
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, dns_record: dnsRecord, policy, validations };
}

async function fetchPolicy(domain: string): Promise<MtaStsPolicy | null> {
  try {
    const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    const resp = await fetch(url, {
      headers: { "User-Agent": "dmarcheck/1.0" },
      // SECURITY / RUNTIME — DO NOT CHANGE to "error" without reading this.
      // RFC 8461 §3.3 forbids following redirects for MTA-STS policy fetches.
      // We use `redirect: "manual"` (NOT `"error"`) because `"error"` throws a
      // TypeError in the Cloudflare Workers fetch runtime, breaking the fetch
      // for EVERY domain — not just ones that redirect. With `"manual"`, any
      // 3xx yields an opaque-redirect Response (`type === "opaqueredirect"`,
      // `ok === false`), which the checks below reject safely.
      // History: PR #58 introduced "error" → regression fixed in 2b47fe7
      // → PR #92 re-introduced "error" → this fix. See those commits before
      // "hardening" this again.
      redirect: "manual",
      signal: AbortSignal.timeout(3000),
    });

    // Reject opaque-redirect responses explicitly (defense in depth — the
    // !resp.ok check below already catches them, but being explicit makes the
    // RFC 8461 §3.3 intent obvious to future readers and static analyzers).
    // `resp.type` is cast to string because @cloudflare/workers-types narrows
    // it to `"default" | "error"`, even though the runtime also emits
    // `"opaqueredirect"` when a 3xx is encountered under `redirect: "manual"`.
    if ((resp.type as string) === "opaqueredirect") {
      await discardBody(resp);
      return null;
    }
    if (!resp.ok) {
      await discardBody(resp);
      return null;
    }

    // Bound the body AS IT ARRIVES, not after it lands. resp.arrayBuffer()
    // resolves only once the whole body is resident in the isolate, so
    // capping afterwards bounds parser cost but NOT peak memory — and a
    // Worker's 128 MB limit is shared by every concurrent request in the
    // isolate. The 3s AbortSignal bounds elapsed time, not bytes, and
    // Content-Length is whatever the sender claims. mta-sts.<domain> is
    // derived from a user-supplied domain on a public endpoint, so the
    // sender is attacker-controlled. Read with a reader, stop at
    // MAX_POLICY_BYTES, then cancel so the sender stops transmitting.
    // Same control as security-txt.
    const reader = resp.body?.getReader();
    if (!reader) return null;
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (total < MAX_POLICY_BYTES) {
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

    const text = new TextDecoder("utf-8", {
      fatal: false,
      ignoreBOM: false,
    }).decode(concatCapped(chunks, total, MAX_POLICY_BYTES));
    return parsePolicy(text);
  } catch {
    return null;
  }
}

// Release a response body we are not going to read, so the connection closes
// instead of waiting on a sender we have already rejected. Best-effort: a
// rejected cancel (already-disturbed body, aborted socket) must not escape,
// because fetchPolicy's contract is to return null, never to throw.
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

function parsePolicy(text: string): MtaStsPolicy {
  let version = "";
  let mode = "";
  const mx: string[] = [];
  let maxAge = 0;

  // Performance optimization:
  // Use a single-pass `indexOf` loop instead of `text.split('\n').map(...).filter(...)`
  // This avoids allocating intermediate arrays and strings, reducing GC pressure.
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf("\n", start);
    if (end === -1) {
      end = text.length;
    }

    const line = text.slice(start, end).trim();
    start = end + 1;

    if (!line) continue;

    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;

    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();

    switch (key) {
      case "version":
        version = value;
        break;
      case "mode":
        mode = value;
        break;
      case "mx":
        mx.push(value);
        break;
      case "max_age":
        maxAge = parseInt(value, 10) || 0;
        break;
    }
  }

  return { version, mode, mx, max_age: maxAge };
}
