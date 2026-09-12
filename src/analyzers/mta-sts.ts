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
      // Free the discarded body per Cloudflare's fetch() guidance; `.catch`
      // keeps a rejected cancel() from becoming an unhandled rejection since
      // this function's contract is to return null, never throw.
      resp.body?.cancel().catch(() => {});
      return null;
    }
    if (!resp.ok) {
      resp.body?.cancel().catch(() => {});
      return null;
    }

    // Bound the body before decoding — reading via arrayBuffer()+slice caps
    // memory regardless of a lying Content-Length or a slow infinite stream
    // (the 3s AbortSignal bounds time, not bytes). Same control as security-txt.
    const buffer = await resp.arrayBuffer();
    const slice =
      buffer.byteLength > MAX_POLICY_BYTES
        ? buffer.slice(0, MAX_POLICY_BYTES)
        : buffer;
    const text = new TextDecoder("utf-8", {
      fatal: false,
      ignoreBOM: false,
    }).decode(slice);
    return parsePolicy(text);
  } catch {
    return null;
  }
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
