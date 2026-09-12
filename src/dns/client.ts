import dns from "node:dns";
import * as Sentry from "@sentry/cloudflare";
import type { Answer, StringAnswer } from "dns-packet";
import { decode, encode, RECURSION_DESIRED } from "dns-packet";
import { DnsLookupError } from "./errors.js";
// Type-only: enforcement is a runtime `budget?.consume()` call, so no value
// import of scan-budget.ts is emitted here.
import type { ScanBudget } from "./scan-budget.js";
import type { MxRecord, TxtRecord } from "./types.js";

// Re-exported so existing `import { DnsLookupError } from "../dns/client.js"`
// call sites keep working; the class itself now lives in ./errors.js so
// scan-budget.ts can subclass it without depending on this module (which tests
// frequently vi.mock).
export { DnsLookupError } from "./errors.js";

export function parseDnsServers(raw: string | undefined): string[] | null {
  if (!raw) return null;
  const servers = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return servers.length > 0 ? servers : null;
}

const DNS_TIMEOUT_MS = 3000;

// Local-dev override: `DNS_SERVERS=8.8.8.8,1.1.1.1 npm run dev` points the
// resolver at custom servers. In Cloudflare Workers prod the var is absent and
// the built-in polyfill is used as-is; setServers() may be a no-op there.
const customDnsServers =
  typeof process !== "undefined"
    ? parseDnsServers(process.env?.DNS_SERVERS)
    : null;

// One module-level handle is correct here. workerd's node:dns is a DoH client
// over fetch(), and its `Resolver` is a stateless pass-through — every method
// is `return moduleFunction(...args)`, it holds no socket and no per-instance
// query state, and setServers() is a no-op. #701 added a
// RESOLVER_RESET_THRESHOLD that recreated this handle every 50 queries on the
// theory that a c-ares handle was accumulating queries; the workerd binary
// contains zero `ares_` symbols, so there was no handle to recycle and the
// reset could not affect anything. Removed rather than left as dead code, so
// the next reader is not handed a disproven model. The real bound on cron DNS
// work is the per-invocation ceiling in src/cron/rescan.ts (#700).
const resolver = new dns.promises.Resolver();
if (customDnsServers) {
  try {
    resolver.setServers(customDnsServers);
  } catch (err) {
    console.warn("Failed to apply DNS_SERVERS override:", err);
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("DNS timeout")), ms);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    clearTimeout(timer);
  });
}

// ENOTFOUND/ENODATA = record genuinely absent (NXDOMAIN / NODATA).
// ESERVFAIL and timeouts are resolver errors — the record may exist but
// the query failed. These are re-thrown as DnsLookupError so callers can
// surface them to the user rather than treating them as "not configured".
function isDnsAbsent(err: unknown): boolean {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { code: string }).code;
    return code === "ENOTFOUND" || code === "ENODATA";
  }
  return false;
}

// Exported so callers/tests can assert the classification directly (#700).
export function toDnsLookupError(err: unknown): DnsLookupError | null {
  if (err instanceof Error && err.message === "DNS timeout") {
    return new DnsLookupError("DNS_TIMEOUT", "DNS query timed out");
  }
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { code: string }).code;
    if (code === "ESERVFAIL") {
      return new DnsLookupError(code, "DNS server failure (SERVFAIL)");
    }
    // Any other c-ares-level error code (EBADQUERY, ECONNREFUSED, etc.) is a
    // resolver fault, not a genuinely absent record. Falling through to a bare
    // throw here is what let a resolver hiccup masquerade as a scored
    // protocol failure (#700) — classify it the same way as SERVFAIL instead.
    return new DnsLookupError(code, `DNS resolver error (${code})`);
  }
  return null;
}

export async function queryTxt(
  name: string,
  budget?: ScanBudget,
): Promise<TxtRecord | null> {
  // Reserve a permit from the shared per-scan pool BEFORE any outbound query.
  // Throws (ScanBudgetError / ScanDeadlineError, both DnsLookupError) when the
  // pool is empty or the deadline has fired, so the query is never issued.
  budget?.consume();
  Sentry.addBreadcrumb({
    category: "dns.query",
    message: `TXT ${name}`,
    data: { type: "TXT", hostname: name },
    level: "info",
  });
  try {
    const records = await withTimeout(
      resolver.resolveTxt(name),
      DNS_TIMEOUT_MS,
    );
    // workerd's node:dns polyfill may join multi-part TXT chunks with literal
    // quote characters (e.g. 'part1" "part2') instead of splitting properly.
    // Strip these artifacts so downstream parsing sees a clean record.
    const entries = records.map((chunks) =>
      chunks.join("").replace(/"\s*"/g, ""),
    );
    return { entries, raw: entries.join(" ") };
  } catch (err: unknown) {
    if (isDnsAbsent(err)) {
      Sentry.addBreadcrumb({
        category: "dns.nxdomain",
        message: `TXT ${name} not found`,
        data: {
          type: "TXT",
          hostname: name,
          reason: (err as { code?: string }).code ?? "nxdomain",
        },
        level: "info",
      });
      return null;
    }
    const lookupErr = toDnsLookupError(err);
    if (lookupErr) {
      Sentry.addBreadcrumb({
        category: "dns.lookup_error",
        message: `TXT ${name} lookup failed: ${lookupErr.code}`,
        data: { type: "TXT", hostname: name, reason: lookupErr.code },
        level: "warning",
      });
      throw lookupErr;
    }
    throw err;
  }
}

// Shape of the Cloudflare 1.1.1.1 DoH JSON API response.
// Status 0 = NOERROR, 3 = NXDOMAIN. AD = Authenticated Data flag (DNSSEC).
export interface DohResponse {
  Status: number;
  AD: boolean;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

// DNS-over-HTTPS query via the Cloudflare 1.1.1.1 DoH JSON API.
// Returns null for NXDOMAIN / no answer; throws DnsLookupError for SERVFAIL
// or timeout — matching the semantics of queryTxt and queryMx.
// The URL is hardcoded (not user-supplied), so this is not an SSRF risk.
export async function queryDoh(
  name: string,
  type: string,
  budget?: ScanBudget,
): Promise<DohResponse | null> {
  budget?.consume();
  Sentry.addBreadcrumb({
    category: "dns.query",
    message: `DoH ${type} ${name}`,
    data: { type, hostname: name },
    level: "info",
  });
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  try {
    const resp = await withTimeout(
      fetch(url, {
        headers: { Accept: "application/dns-json" },
        redirect: "follow",
      }),
      DNS_TIMEOUT_MS,
    );
    if (!resp.ok) {
      throw new DnsLookupError(
        "ESERVFAIL",
        `DoH query returned HTTP ${resp.status}`,
      );
    }
    const data = (await resp.json()) as DohResponse;
    // NXDOMAIN or NOERROR with no answers → record absent
    if (data.Status === 3 || !data.Answer || data.Answer.length === 0) {
      Sentry.addBreadcrumb({
        category: "dns.nxdomain",
        message: `DoH ${type} ${name} not found (Status ${data.Status})`,
        data: { type, hostname: name, status: data.Status },
        level: "info",
      });
      return null;
    }
    return data;
  } catch (err: unknown) {
    if (err instanceof DnsLookupError) throw err;
    if (err instanceof Error && err.message === "DNS timeout") {
      throw new DnsLookupError("DNS_TIMEOUT", "DoH query timed out");
    }
    throw new DnsLookupError(
      "ESERVFAIL",
      `DoH query failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

// True for an Answer whose RDATA dns-packet already decoded to a dotted-quad
// string — i.e. a type-A record. dns-packet's own types group A together
// with AAAA/CNAME/NS/PTR under one "string data" variant, so a plain
// `type === "A"` check doesn't narrow far enough for TS to allow `.data`;
// this guard re-validates `data` is actually a string at runtime too, so a
// malformed/hostile answer can't slip a non-string through.
function isARecordAnswer(
  answer: Answer,
): answer is StringAnswer & { type: "A"; data: string } {
  return answer.type === "A" && typeof answer.data === "string";
}

// DNSBL/RBL lookup — RFC 8484 DoH POST with an RFC 1035 wire-format body
// (via the vetted `dns-packet` library, #736), not the GET-with-query-string
// shape queryDoh uses. The query name embeds a per-account Spamhaus DQS key
// (`<reversed-ip>.<key>.<zone>`), which is a deploy secret; POSTing the name
// in the body (rather than the URL) means the request URL is the bare
// endpoint with no query string at all, so nothing about the lookup lands
// in `url.full`/`url.query` on an outbound fetch span (#728). Breadcrumbs
// and error messages still never carry the full name — only the reversed IP
// + zone are logged, with the key replaced by a redacted placeholder — as
// defense-in-depth against a future path that echoes request details.
//
// Returns the listing A-record values (e.g. ["127.0.0.2"]) when the IP is
// listed, null when not listed (NXDOMAIN / no answer), and throws
// DnsLookupError on SERVFAIL/timeout/malformed response so callers surface
// "could not verify" rather than a false "clean".
export async function queryDnsbl(
  reversedIp: string,
  key: string,
  zone: string,
  budget?: ScanBudget,
): Promise<string[] | null> {
  budget?.consume();
  const redacted = `${reversedIp}.<key>.${zone}`;
  Sentry.addBreadcrumb({
    category: "dns.query",
    message: `DNSBL A ${redacted}`,
    data: { type: "A", hostname: redacted },
    level: "info",
  });
  const name = `${reversedIp}.${key}.${zone}`;
  try {
    const resp = await withTimeout(
      fetch("https://cloudflare-dns.com/dns-query", {
        method: "POST",
        headers: {
          "Content-Type": "application/dns-message",
          Accept: "application/dns-message",
        },
        body: encode({
          type: "query",
          id: 0,
          flags: RECURSION_DESIRED,
          questions: [{ type: "A", name }],
        }),
        redirect: "follow",
      }),
      DNS_TIMEOUT_MS,
    );
    if (!resp.ok) {
      throw new DnsLookupError(
        "ESERVFAIL",
        `DNSBL query returned HTTP ${resp.status}`,
      );
    }
    // dns-packet.decode throws on a malformed/truncated buffer — caught
    // below and turned into the same generic DnsLookupError as any other
    // failure, never an unhandled throw and never a false "not listed".
    const decoded = decode(Buffer.from(await resp.arrayBuffer()));
    const rcode = (decoded.flags ?? 0) & 0x0f; // 3 = NXDOMAIN (RFC 1035 §4.1.1)
    const aRecords = (decoded.answers ?? [])
      .filter(isARecordAnswer)
      .map((a) => a.data);
    if (rcode === 3 || aRecords.length === 0) {
      return null;
    }
    return aRecords;
  } catch (err: unknown) {
    if (err instanceof DnsLookupError) throw err;
    if (err instanceof Error && err.message === "DNS timeout") {
      throw new DnsLookupError("DNS_TIMEOUT", "DNSBL query timed out");
    }
    // Deliberately generic, as defense-in-depth (the request URL itself no
    // longer carries the key, but an error path shouldn't echo query details
    // either).
    throw new DnsLookupError("ESERVFAIL", "DNSBL query failed");
  }
}

export async function queryMx(
  name: string,
  budget?: ScanBudget,
): Promise<MxRecord[] | null> {
  budget?.consume();
  Sentry.addBreadcrumb({
    category: "dns.query",
    message: `MX ${name}`,
    data: { type: "MX", hostname: name },
    level: "info",
  });
  try {
    const records = await withTimeout(resolver.resolveMx(name), DNS_TIMEOUT_MS);
    return records.map((r) => ({ priority: r.priority, exchange: r.exchange }));
  } catch (err: unknown) {
    if (isDnsAbsent(err)) {
      Sentry.addBreadcrumb({
        category: "dns.nxdomain",
        message: `MX ${name} not found`,
        data: {
          type: "MX",
          hostname: name,
          reason: (err as { code?: string }).code ?? "nxdomain",
        },
        level: "info",
      });
      return null;
    }
    const lookupErr = toDnsLookupError(err);
    if (lookupErr) {
      Sentry.addBreadcrumb({
        category: "dns.lookup_error",
        message: `MX ${name} lookup failed: ${lookupErr.code}`,
        data: { type: "MX", hostname: name, reason: lookupErr.code },
        level: "warning",
      });
      throw lookupErr;
    }
    throw err;
  }
}
