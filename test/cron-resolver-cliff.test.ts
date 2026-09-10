/**
 * Regression test for #700 — a long-lived cron rescan cumulatively exhausts
 * the shared node:dns resolver handle (c-ares EBADQUERY) partway through a
 * large run. Before this fix, the misclassified EBADQUERY bare-threw out of
 * analyzeMx, and because analyzeDkim/analyzeDane/analyzeDnsbl are chained off
 * the same raw MX promise (`mxPromise.then(...)`), that rejection cascaded
 * into all of them via the orchestrator's settle() fallback — tanking DKIM's
 * scored status and producing false grade/protocol-regression alerts.
 *
 * This exercises the REAL DNS client (src/dns/client.ts) and REAL analyzeMx
 * through the REAL scan() used by runDueRescans's default scanFn — only
 * node:dns and the non-MX analyzers are stubbed, following the pattern in
 * test/orchestrator-budget.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// Each Resolver instance "dies" (throws EBADQUERY on every subsequent call)
// once it exceeds PER_INSTANCE_LIMIT queries — simulating the c-ares handle
// exhaustion from #700. If the client resets the handle well before this
// point, no instance run through a 260-domain cron pass should ever see it.
const PER_INSTANCE_LIMIT = 60;

vi.mock("node:dns", () => {
  class Resolver {
    private calls = 0;
    setServers() {}
    async resolveMx(name: string) {
      this.calls++;
      if (this.calls > PER_INSTANCE_LIMIT) {
        throw Object.assign(new Error(`queryMX EBADQUERY ${name}`), {
          code: "EBADQUERY",
        });
      }
      return [{ priority: 10, exchange: "mail.example.com" }];
    }
    async resolveTxt() {
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
  });

  it("a 260-domain cron run produces zero EBADQUERY, no positional failure cliff, and no false alerts", async () => {
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

    // maxDomainsPerRun is pinned to TOTAL here so this test keeps measuring
    // what it was written to measure — DNS-layer resolver exhaustion across a
    // long run — rather than the separate per-invocation domain ceiling added
    // for #700 (default 150, covered by test/cron-rescan.test.ts).
    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      maxDomainsPerRun: TOTAL,
    });

    expect(result.scanned).toBe(TOTAL);
    expect(result.errors).toBe(0);
    // No cascade-driven grade-drop / protocol-regression alerts anywhere in
    // the run — every domain's grade must match the healthy baseline.
    expect(result.alerts).toBe(0);

    const rows = [...history.values()];
    expect(rows).toHaveLength(TOTAL);

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

    // No domain_id bucket shows the 100%-failure cliff from #700 (bucket
    // failure rate must stay flat at 0% throughout the run).
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
