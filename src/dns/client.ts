import dns from "node:dns";
import * as Sentry from "@sentry/cloudflare";
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

// DNS header flags for a minimal standard query: QR=0 (query), Opcode=0,
// RD=1 (recursion desired) — the only bit a resolver needs set to answer.
const DNS_QUERY_FLAGS = 0x0100;

// Encodes a single-question, type-A DNS query into RFC 1035 wire format so it
// can travel as an RFC 8484 DoH POST body instead of a GET query string.
// Only queryDnsbl needs this: its query name embeds a secret DQS key, and a
// GET's URL would put that key in `url.full`/`url.query` — which Workers
// Traces spans record automatically with no scrubbing hook (#728). This is a
// small, fixed encoder for exactly this shape (no compression, no EDNS,
// QTYPE hardcoded to A) — not a general DNS library.
function encodeDnsQueryA(name: string): Uint8Array {
  const encoder = new TextEncoder();
  const qname: number[] = [];
  for (const label of name.split(".")) {
    if (label.length === 0) continue;
    const bytes = encoder.encode(label);
    if (bytes.length > 63) {
      throw new Error("DNS label exceeds 63 octets");
    }
    qname.push(bytes.length, ...bytes);
  }
  qname.push(0); // root label terminator

  return new Uint8Array([
    0x00,
    0x00, // ID — unused; DoH is one request/response over HTTP, nothing to
    // disambiguate the way multiplexed queries on one socket would need.
    (DNS_QUERY_FLAGS >> 8) & 0xff,
    DNS_QUERY_FLAGS & 0xff,
    0x00,
    0x01, // QDCOUNT = 1
    0x00,
    0x00, // ANCOUNT = 0
    0x00,
    0x00, // NSCOUNT = 0
    0x00,
    0x00, // ARCOUNT = 0
    ...qname,
    0x00,
    0x01, // QTYPE = A
    0x00,
    0x01, // QCLASS = IN
  ]);
}

// Skips one (possibly compressed) NAME field in a wire-format DNS message,
// returning the offset just past it. A compression pointer (top two bits of
// the length byte set) is always exactly two bytes; the decoder never needs
// to follow it because it only reads what comes AFTER each name, never the
// name itself.
function skipDnsName(buf: Uint8Array, offset: number): number {
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) return offset + 1;
    if ((len & 0xc0) === 0xc0) return offset + 2;
    offset += 1 + len;
  }
  return offset;
}

// Decodes just enough of an RFC 1035 wire-format response to answer a type-A
// DNSBL query: the RCODE (for NXDOMAIN detection, mirroring DohResponse.Status
// from the JSON API) and any A-record RDATA.
function decodeDnsResponseA(buf: Uint8Array): {
  rcode: number;
  aRecords: string[];
} {
  if (buf.length < 12) {
    throw new Error("DNS response shorter than header");
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const rcode = view.getUint16(2) & 0x0f;
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;
  for (let i = 0; i < qdcount; i++) {
    offset = skipDnsName(buf, offset) + 4; // + QTYPE + QCLASS
  }

  const aRecords: string[] = [];
  for (let i = 0; i < ancount; i++) {
    offset = skipDnsName(buf, offset);
    const type = view.getUint16(offset);
    const rdlength = view.getUint16(offset + 8);
    const rdataOffset = offset + 10;
    if (type === 1 && rdlength === 4) {
      aRecords.push(
        `${buf[rdataOffset]}.${buf[rdataOffset + 1]}.${buf[rdataOffset + 2]}.${buf[rdataOffset + 3]}`,
      );
    }
    offset = rdataOffset + rdlength;
  }

  return { rcode, aRecords };
}

// DNSBL/RBL lookup — RFC 8484 DoH POST with a wire-format body (RFC 1035),
// not the GET-with-query-string shape queryDoh uses. The query name embeds a
// per-account Spamhaus DQS key (`<reversed-ip>.<key>.<zone>`), which is a
// deploy secret; POSTing the name in the body (rather than the URL) means the
// request URL is the bare endpoint with no query string at all, so nothing
// about the lookup lands in `url.full`/`url.query` on an outbound fetch span
// (#728). Breadcrumbs and error messages still never carry the full name —
// only the reversed IP + zone are logged, with the key replaced by a redacted
// placeholder — as defense-in-depth against a future path that echoes
// request details.
//
// Returns the listing A-record values (e.g. ["127.0.0.2"]) when the IP is
// listed, null when not listed (NXDOMAIN / no answer), and throws
// DnsLookupError on SERVFAIL/timeout so callers surface "could not verify"
// rather than a false "clean".
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
        body: encodeDnsQueryA(name),
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
    const { rcode, aRecords } = decodeDnsResponseA(
      new Uint8Array(await resp.arrayBuffer()),
    );
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
