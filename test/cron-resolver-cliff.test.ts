/**
 * Regression test for #700 — a long cron rescan exhausts the invocation's
 * outbound subrequest allowance partway through, and every DNS lookup after
 * that point fails with EBADQUERY for the rest of the invocation.
 *
 * The mock below models that allowance the way workerd actually behaves: ONE
 * counter shared by every query in the invocation, which never recovers once
 * spent. It is deliberately NOT a per-Resolver-instance limit — workerd's
 * `node:dns` is a DoH client over fetch() and its `Resolver` is a stateless
 * pass-through with no per-instance query state, so a per-instance model would
 * assert a mechanism that does not exist (and would pass while the real bug
 * remained live, which is what happened in #701).
 *
 * This exercises the REAL DNS client (src/dns/client.ts) and REAL analyzeMx
 * through the REAL scan() used by runDueRescans's default scanFn — only
 * node:dns and the non-MX analyzers are stubbed, following the pattern in
 * test/orchestrator-budget.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// One shared, per-invocation allowance: once SUBREQUEST_BUDGET lookups have
// been issued, every subsequent lookup throws EBADQUERY and never recovers —
// exactly what the production cliff looked like.
const { budget, SUBREQUEST_BUDGET } = vi.hoisted(() => ({
  budget: { used: 0 },
  SUBREQUEST_BUDGET: 120,
}));

function spendOrThrow(name: string): void {
  budget.used++;
  if (budget.used > SUBREQUEST_BUDGET) {
    throw Object.assign(new Error(`queryMx EBADQUERY ${name}`), {
      code: "EBADQUERY",
    });
  }
}

vi.mock("node:dns", () => {
  class Resolver {
    setServers() {}
    async resolveMx(name: string) {
      spendOrThrow(name);
      return [{ priority: 10, exchange: "mail.example.com" }];
    }
    async resolveTxt(name: string) {
      spendOrThrow(name);
      throw Object.assign(new Error("queryTxt ENODATA"), { code: "ENODATA" });
    }
  }
  return { default: { promises: { Resolver } } };
});

vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

// Every analyzer except MX is stubbed to a fixed, deterministic result — the
// resolver-exhaustion defect under test lives entirely in the DNS client and
// in analyzeMx's chained dependents (dkim/dane/dnsbl), not in analyzer logic.
vi.mock("../src/analyzers/dmarc.js", () => ({
  analyzeDmarc: vi.fn().mockResolvedValue({
    status: "pass",
    record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    tags: { v: "DMARC1", p: "reject", rua: "mailto:dmarc@example.com" },
    validations: [],
  }),
}));
vi.mock("../src/analyzers/spf.js", () => ({
  analyzeSpf: vi.fn().mockResolvedValue({
    status: "pass",
    record: "v=spf1 -all",
    lookups_used: 1,
    lookup_limit: 10,
    include_tree: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dkim.js", () => ({
  analyzeDkim: vi.fn().mockResolvedValue({
    status: "pass",
    selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
    validations: [],
  }),
}));
vi.mock("../src/analyzers/bimi.js", () => ({
  prefetchBimiDns: vi.fn().mockResolvedValue(null),
  analyzeBimi: vi.fn().mockResolvedValue({
    status: "warn",
    record: null,
    tags: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mta-sts.js", () => ({
  analyzeMtaSts: vi.fn().mockResolvedValue({
    status: "pass",
    dns_record: "v=STSv1; id=20260101",
    policy: {
      version: "STSv1",
      mode: "enforce",
      mx: ["*.example.com"],
      max_age: 86400,
    },
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mx-mta-sts-consistency.js", () => ({
  checkMxMtaStsConsistency: vi.fn().mockReturnValue([]),
}));
vi.mock("../src/analyzers/security-txt.js", () => ({
  analyzeSecurityTxt: vi.fn().mockResolvedValue({
    status: "info",
    source_url: null,
    signed: false,
    fields: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/tls-rpt.js", () => ({
  analyzeTlsRpt: vi.fn().mockResolvedValue({
    status: "info",
    record: null,
    tags: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dnssec.js", () => ({
  analyzeDnssec: vi.fn().mockResolvedValue({
    status: "info",
    signed: false,
    validated: false,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dane.js", () => ({
  analyzeDane: vi.fn().mockResolvedValue({
    status: "info",
    hosts: [],
    validations: [],
  }),
}));

import { runDueRescans } from "../src/cron/rescan.js";
import { scan } from "../src/orchestrator.js";

interface DomainRow {
  id: number;
  user_id: string;
  domain: string;
  is_free: number;
  scan_frequency: string;
  last_scanned_at: number | null;
  last_grade: string | null;
  created_at: number;
}

interface ScanHistoryRow {
  id: number;
  domain_id: number;
  grade: string;
  score_factors: string | null;
  protocol_results: string | null;
  scanned_at: number;
}

interface AlertRow {
  id: number;
  domain_id: number;
  alert_type: string;
  previous_value: string | null;
  new_value: string | null;
  created_at: number;
}

let domains: Map<number, DomainRow>;
let history: Map<number, ScanHistoryRow>;
let alerts: Map<number, AlertRow>;
let nextScanId: number;
let nextAlertId: number;

function makeD1Mock(): D1Database {
  const prepare = (sql: string) => ({
    bind: (...params: unknown[]) => ({
      run: async () => {
        if (/^INSERT INTO scan_history/i.test(sql)) {
          const [domainId, grade, scoreFactors, protocolResults, scannedAt] =
            params as [number, string, string, string, number];
          const id = nextScanId++;
          history.set(id, {
            id,
            domain_id: domainId,
            grade,
            score_factors: scoreFactors,
            protocol_results: protocolResults,
            scanned_at: scannedAt,
          });
        } else if (/^UPDATE domains SET last_grade/i.test(sql)) {
          const [grade, scannedAt, domainId] = params as [
            string,
            number,
            number,
          ];
          const row = domains.get(domainId);
          if (row) {
            domains.set(domainId, {
              ...row,
              last_grade: grade,
              last_scanned_at: scannedAt,
            });
          }
        } else if (/^INSERT INTO alerts/i.test(sql)) {
          const [domainId, type, prevVal, newVal, createdAt] = params as [
            number,
            string,
            string,
            string,
            number,
          ];
          const id = nextAlertId++;
          alerts.set(id, {
            id,
            domain_id: domainId,
            alert_type: type,
            previous_value: prevVal,
            new_value: newVal,
            created_at: createdAt,
          });
        }
        return { success: true };
      },
      first: async <T>(): Promise<T | null> => {
        if (/FROM scan_history WHERE domain_id = \? ORDER BY/i.test(sql)) {
          const [domainId] = params as [number];
          const rows = [...history.values()]
            .filter((r) => r.domain_id === domainId)
            .sort((a, b) => b.scanned_at - a.scanned_at);
          return (rows[0] ?? null) as T | null;
        }
        if (/FROM users WHERE id = \?/i.test(sql)) {
          return null as T | null;
        }
        return null;
      },
      all: async <T>(): Promise<{ results: T[] }> => {
        if (/FROM domains[\s\S]*scan_frequency = 'monthly'/i.test(sql)) {
          const [monthlyCutoff, weeklyCutoff, limit] = params as [
            number,
            number,
            number,
          ];
          const due = [...domains.values()]
            .filter((d) => {
              if (d.scan_frequency === "monthly") {
                return (
                  d.last_scanned_at === null ||
                  d.last_scanned_at < monthlyCutoff
                );
              }
              if (d.scan_frequency === "weekly") {
                return (
                  d.last_scanned_at === null || d.last_scanned_at < weeklyCutoff
                );
              }
              return false;
            })
            .sort((a, b) => (a.last_scanned_at ?? 0) - (b.last_scanned_at ?? 0))
            .slice(0, limit);
          return { results: due as T[] };
        }
        return { results: [] };
      },
    }),
  });
  return {
    prepare,
    batch: async (
      stmts: Array<{ run: () => Promise<{ success: boolean }> }>,
    ) => {
      for (const stmt of stmts) await stmt.run();
      return [];
    },
  } as unknown as D1Database;
}

describe("runDueRescans resolver exhaustion regression (#700)", () => {
  const now = 1_700_000_000;
  const monthSeconds = 30 * 24 * 60 * 60;
  const TOTAL = 260;

  beforeEach(() => {
    domains = new Map();
    history = new Map();
    alerts = new Map();
    nextScanId = 1;
    nextAlertId = 1;
    budget.used = 0;
  });

  it("a 260-domain cron run stops cleanly when the subrequest allowance runs out — no false grades, no alerts, no positional cliff", async () => {
    // Baseline: what a healthy scan produces against the same mocked
    // dependency graph, while the resolver still has plenty of headroom.
    const baseline = await scan("baseline.example", [], {});
    const baselineGrade = baseline.grade;
    expect(baseline.protocols.mx.status).not.toBe("fail");

    for (let i = 1; i <= TOTAL; i++) {
      domains.set(i, {
        id: i,
        user_id: "u",
        domain: `domain-${i}.example`,
        is_free: 1,
        scan_frequency: "monthly",
        last_scanned_at: now - monthSeconds - 1,
        last_grade: baselineGrade,
        created_at: 0,
      });
    }

    // maxDomainsPerRun is pinned to TOTAL so the allowance below, not the
    // default per-invocation domain ceiling, is what ends this run — the
    // ceiling has its own coverage in test/cron-rescan.test.ts.
    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      maxDomainsPerRun: TOTAL,
    });

    // The run stops instead of grinding the remaining domains through a
    // resolver that can no longer issue a single query.
    expect(result.scanned).toBeGreaterThan(0);
    expect(result.scanned).toBeLessThan(TOTAL);
    expect(result.skipped).toBeGreaterThan(0);
    expect(result.scanned + result.errors + result.skipped).toBe(TOTAL);

    // Nothing unverifiable was persisted, and nothing was alerted on.
    expect(result.alerts).toBe(0);
    expect(alerts.size).toBe(0);

    const rows = [...history.values()];
    expect(rows).toHaveLength(result.scanned);

    for (const row of rows) {
      expect(row.grade).toBe(baselineGrade);
      const protocols = JSON.parse(row.protocol_results ?? "{}") as {
        mx: { status: string; lookup_error?: unknown };
        dkim: { status: string };
      };
      // The #700 symptom: MX misclassifying EBADQUERY as a scored failure,
      // which cascades into DKIM (chained off the same MX promise).
      expect(protocols.mx.status).not.toBe("fail");
      expect(protocols.mx.lookup_error).toBeUndefined();
      expect(protocols.dkim.status).not.toBe("fail");
    }

    // Every domain past the cliff is left DUE rather than false-graded, so the
    // next invocation picks it up first (`ORDER BY last_scanned_at ASC`).
    const scannedIds = new Set(rows.map((r) => r.domain_id));
    for (let id = 1; id <= TOTAL; id++) {
      if (scannedIds.has(id)) continue;
      expect(domains.get(id)?.last_grade).toBe(baselineGrade);
      expect(domains.get(id)?.last_scanned_at).toBeLessThan(now);
    }

    // No domain_id bucket shows the 100%-failure cliff from #700: a bucket is
    // either scanned cleanly or not scanned at all, never scanned-and-failed.
    const bucketSize = 40;
    for (let start = 0; start < TOTAL; start += bucketSize) {
      const bucket = rows.filter(
        (r) => r.domain_id > start && r.domain_id <= start + bucketSize,
      );
      const failedInBucket = bucket.filter((r) => {
        const protocols = JSON.parse(r.protocol_results ?? "{}") as {
          mx: { status: string };
        };
        return protocols.mx.status === "fail";
      }).length;
      expect(failedInBucket).toBe(0);
    }
  });
});
