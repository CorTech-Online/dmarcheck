import { beforeEach, describe, expect, it, vi } from "vitest";
import { runDueRescans } from "../src/cron/rescan.js";

interface UserRow {
  id: string;
  email: string;
  email_domain: string;
  stripe_customer_id: string | null;
  email_alerts_enabled: number;
  notify_on_change_only: number;
  api_key_retirement_acknowledged_at: number | null;
  created_at: number;
}

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

interface AlertRow {
  id: number;
  domain_id: number;
  alert_type: string;
  previous_value: string | null;
  new_value: string | null;
  notified_via: string | null;
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

let users: Map<string, UserRow>;
let domains: Map<number, DomainRow>;
let alerts: Map<number, AlertRow>;
let history: Map<number, ScanHistoryRow>;
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
            notified_via: null,
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
          const [userId] = params as [string];
          return (users.get(userId) ?? null) as T | null;
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

// Minimal fake ScanResult shape — only what rescan reads.
function makeScanResult(
  domain: string,
  grade: string,
  statuses: Record<string, string>,
) {
  return {
    domain,
    timestamp: "2026-04-19T00:00:00Z",
    grade,
    breakdown: {
      grade,
      tier: grade,
      tierReason: "",
      modifier: 0,
      modifierLabel: "",
      factors: [],
      recommendations: [],
      protocolSummaries: {},
    },
    summary: { mx_records: 0, mx_providers: [], dmarc_policy: null },
    protocols: {
      mx: { status: "info" },
      dmarc: { status: statuses.dmarc ?? "pass" },
      spf: { status: statuses.spf ?? "pass" },
      dkim: { status: statuses.dkim ?? "pass" },
      bimi: { status: statuses.bimi ?? "pass" },
      mta_sts: { status: statuses.mta_sts ?? "pass" },
    },
  };
}

describe("cron/runDueRescans", () => {
  const now = 1_700_000_000;
  const monthSeconds = 30 * 24 * 60 * 60;
  const weekSeconds = 7 * 24 * 60 * 60;

  beforeEach(() => {
    users = new Map();
    domains = new Map();
    alerts = new Map();
    history = new Map();
    nextScanId = 1;
    nextAlertId = 1;
  });

  it("skips domains that are not yet due", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "recent.com",
      is_free: 1,
      scan_frequency: "monthly",
      last_scanned_at: now - 1000,
      last_grade: "A",
      created_at: 0,
    });

    const scanFn = vi.fn();
    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });

    expect(result.scanned).toBe(0);
    expect(scanFn).not.toHaveBeenCalled();
  });

  it("scans due monthly domains and persists scan_history", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "stale.com",
      is_free: 1,
      scan_frequency: "monthly",
      last_scanned_at: now - monthSeconds - 100,
      last_grade: "A",
      created_at: 0,
    });

    const scanFn = vi
      .fn()
      .mockResolvedValue(makeScanResult("stale.com", "A", {}));

    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });

    expect(result).toEqual({ scanned: 1, alerts: 0, errors: 0, skipped: 0 });
    expect(scanFn).toHaveBeenCalledWith("stale.com");
    expect(history.size).toBe(1);
    expect([...history.values()][0].grade).toBe("A");
    expect(domains.get(1)?.last_grade).toBe("A");
    expect(domains.get(1)?.last_scanned_at).toBe(now);
  });

  it("skips weekly domains scanned within the last week", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "weekly.com",
      is_free: 0,
      scan_frequency: "weekly",
      last_scanned_at: now - 100,
      last_grade: "A",
      created_at: 0,
    });

    const scanFn = vi.fn();
    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });
    expect(result.scanned).toBe(0);
  });

  it("includes never-scanned domains (last_scanned_at IS NULL)", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "brand-new.com",
      is_free: 1,
      scan_frequency: "monthly",
      last_scanned_at: null,
      last_grade: null,
      created_at: 0,
    });

    const scanFn = vi
      .fn()
      .mockResolvedValue(makeScanResult("brand-new.com", "B", {}));

    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });
    expect(result.scanned).toBe(1);
    expect(result.alerts).toBe(0); // first scan is not a "drop"
  });

  it("records a grade_drop alert when the grade falls", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "falling.com",
      is_free: 1,
      scan_frequency: "monthly",
      last_scanned_at: now - monthSeconds - 1,
      last_grade: "A",
      created_at: 0,
    });

    const scanFn = vi
      .fn()
      .mockResolvedValue(makeScanResult("falling.com", "C", {}));

    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });
    expect(result.alerts).toBe(1);
    expect([...alerts.values()][0]).toMatchObject({
      domain_id: 1,
      alert_type: "grade_drop",
      previous_value: "A",
      new_value: "C",
    });
  });

  it("records protocol_regression alerts when statuses worsen", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "regress.com",
      is_free: 0,
      scan_frequency: "weekly",
      last_scanned_at: now - weekSeconds - 1,
      last_grade: "B",
      created_at: 0,
    });
    // Seed previous history so protocol diff has a baseline
    history.set(99, {
      id: 99,
      domain_id: 1,
      grade: "B",
      score_factors: null,
      protocol_results: JSON.stringify({
        dmarc: { status: "pass" },
        spf: { status: "pass" },
        dkim: { status: "pass" },
        bimi: { status: "pass" },
        mta_sts: { status: "pass" },
      }),
      scanned_at: now - weekSeconds - 1,
    });

    const scanFn = vi
      .fn()
      .mockResolvedValue(
        makeScanResult("regress.com", "B", { dmarc: "fail", spf: "warn" }),
      );

    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });

    expect(result.scanned).toBe(1);
    expect(result.alerts).toBe(2); // dmarc pass→fail, spf pass→warn
    const types = [...alerts.values()].map((a) => a.alert_type);
    expect(types.every((t) => t === "protocol_regression")).toBe(true);
  });

  it("counts errors but continues past a failing domain", async () => {
    domains.set(1, {
      id: 1,
      user_id: "u",
      domain: "broken.com",
      is_free: 1,
      scan_frequency: "monthly",
      last_scanned_at: null,
      last_grade: null,
      created_at: 0,
    });
    domains.set(2, {
      id: 2,
      user_id: "u",
      domain: "ok.com",
      is_free: 1,
      scan_frequency: "monthly",
      last_scanned_at: null,
      last_grade: null,
      created_at: 1,
    });

    const scanFn = vi.fn(async (domain: string) => {
      if (domain === "broken.com") throw new Error("DNS timeout");
      return makeScanResult(domain, "A", {});
    });

    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      scanFn: scanFn as never,
    });
    expect(result.errors).toBe(1);
    expect(result.scanned).toBe(1);
  });

  // Regression test for https://github.com/schmug/dmarcheck/issues/240
  // 60 domains with realistic mixed DNS responses must NOT produce a
  // false-fail cascade. A stub scanFn returns accurate grades — the rescan
  // must record exactly those grades, not a sea of D/F caused by batch-level
  // DNS overload. Uses batchSize=5 (the fixed default) to verify the timing
  // stays sequential and no domain's result is corrupted by its neighbours.
  it("no false-fail cascade: 60 domains produce accurate grades with batchSize=5", async () => {
    const TOTAL = 60;
    // Realistic grade distribution matching prod (roughly A/B/C/D/F mix)
    const gradePool = [
      "A+",
      "A+",
      "A+",
      "A",
      "A",
      "B",
      "B",
      "C",
      "D",
      "F",
    ] as const;
    const expectedGrades: Record<number, string> = {};

    for (let i = 1; i <= TOTAL; i++) {
      const grade = gradePool[(i - 1) % gradePool.length];
      expectedGrades[i] = grade;
      domains.set(i, {
        id: i,
        user_id: "u",
        domain: `domain-${i}.example`,
        is_free: 1,
        scan_frequency: "monthly",
        last_scanned_at: now - monthSeconds - 1,
        last_grade: grade, // same grade so no alert fires
        created_at: 0,
      });
    }

    // Stub scanFn: returns accurate grades and never simulates DNS overload.
    // This is the contract we expect the rescan to uphold — the saved grade
    // must always match what scanFn returned.
    const scanFn = vi.fn(async (domain: string) => {
      const match = /domain-(\d+)\.example/.exec(domain);
      const id = match ? Number(match[1]) : 0;
      const grade = expectedGrades[id] ?? "A";
      return makeScanResult(domain, grade, {});
    });

    const result = await runDueRescans({
      db: makeD1Mock(),
      now,
      batchSize: 5,
      scanFn: scanFn as never,
    });

    // All 60 domains must be scanned without errors
    expect(result.scanned).toBe(TOTAL);
    expect(result.errors).toBe(0);
    expect(scanFn).toHaveBeenCalledTimes(TOTAL);

    // Every saved scan_history row must reflect the accurate grade from scanFn,
    // not a false-fail D/F caused by cascading DNS timeouts.
    const historyRows = [...history.values()];
    expect(historyRows).toHaveLength(TOTAL);

    let falseFails = 0;
    for (const row of historyRows) {
      const domainId = row.domain_id;
      const expected = expectedGrades[domainId];
      if (row.grade !== expected) falseFails++;
    }
    // Zero tolerance for false-fail cascade: every grade must match exactly
    expect(falseFails).toBe(0);
  });

  describe("notify_on_change_only webhook gating", () => {
    const monthSeconds = 30 * 24 * 60 * 60;

    function makeDomain(overrides: Partial<DomainRow> = {}): DomainRow {
      return {
        id: 1,
        user_id: "u1",
        domain: "stable.com",
        is_free: 1,
        scan_frequency: "monthly",
        last_scanned_at: now - monthSeconds - 1,
        last_grade: "A",
        created_at: 0,
        ...overrides,
      };
    }

    function makeUser(notifyOnChangeOnly: number): UserRow {
      return {
        id: "u1",
        email: "user@example.com",
        email_domain: "example.com",
        stripe_customer_id: null,
        email_alerts_enabled: 1,
        notify_on_change_only: notifyOnChangeOnly,
        api_key_retirement_acknowledged_at: null,
        created_at: 0,
      };
    }

    it("default off (setting=0): webhook fires even when result is identical", async () => {
      users.set("u1", makeUser(0));
      domains.set(1, makeDomain({ last_grade: "A" }));
      history.set(99, {
        id: 99,
        domain_id: 1,
        grade: "A",
        score_factors: null,
        protocol_results: JSON.stringify({
          dmarc: { status: "pass" },
          spf: { status: "pass" },
          dkim: { status: "pass" },
          bimi: { status: "pass" },
          mta_sts: { status: "pass" },
        }),
        scanned_at: now - monthSeconds - 1,
      });

      const webhookFn = vi.fn().mockResolvedValue(undefined);
      const scanFn = vi
        .fn()
        .mockResolvedValue(makeScanResult("stable.com", "A", {}));

      await runDueRescans({
        db: makeD1Mock(),
        now,
        scanFn: scanFn as never,
        fireWebhookFn: webhookFn as never,
      });

      expect(webhookFn).toHaveBeenCalledOnce();
    });

    it("setting=1, no change: webhook suppressed", async () => {
      users.set("u1", makeUser(1));
      domains.set(1, makeDomain({ last_grade: "A" }));
      history.set(99, {
        id: 99,
        domain_id: 1,
        grade: "A",
        score_factors: null,
        protocol_results: JSON.stringify({
          dmarc: { status: "pass" },
          spf: { status: "pass" },
          dkim: { status: "pass" },
          bimi: { status: "pass" },
          mta_sts: { status: "pass" },
        }),
        scanned_at: now - monthSeconds - 1,
      });

      const webhookFn = vi.fn().mockResolvedValue(undefined);
      const scanFn = vi
        .fn()
        .mockResolvedValue(makeScanResult("stable.com", "A", {}));

      await runDueRescans({
        db: makeD1Mock(),
        now,
        scanFn: scanFn as never,
        fireWebhookFn: webhookFn as never,
      });

      expect(webhookFn).not.toHaveBeenCalled();
    });

    it("setting=1, grade dropped: webhook fires", async () => {
      users.set("u1", makeUser(1));
      domains.set(1, makeDomain({ last_grade: "A" }));

      const webhookFn = vi.fn().mockResolvedValue(undefined);
      const scanFn = vi
        .fn()
        .mockResolvedValue(makeScanResult("stable.com", "C", {}));

      await runDueRescans({
        db: makeD1Mock(),
        now,
        scanFn: scanFn as never,
        fireWebhookFn: webhookFn as never,
      });

      expect(webhookFn).toHaveBeenCalledOnce();
    });

    it("setting=1, grade improved: webhook fires", async () => {
      users.set("u1", makeUser(1));
      domains.set(1, makeDomain({ last_grade: "B" }));
      history.set(99, {
        id: 99,
        domain_id: 1,
        grade: "B",
        score_factors: null,
        protocol_results: JSON.stringify({
          dmarc: { status: "pass" },
          spf: { status: "pass" },
          dkim: { status: "pass" },
          bimi: { status: "pass" },
          mta_sts: { status: "pass" },
        }),
        scanned_at: now - monthSeconds - 1,
      });

      const webhookFn = vi.fn().mockResolvedValue(undefined);
      const scanFn = vi
        .fn()
        .mockResolvedValue(makeScanResult("stable.com", "A+", {}));

      await runDueRescans({
        db: makeD1Mock(),
        now,
        scanFn: scanFn as never,
        fireWebhookFn: webhookFn as never,
      });

      expect(webhookFn).toHaveBeenCalledOnce();
    });
  });
  // #700 — the weekly full-portfolio run exhausted the invocation's outbound
  // subrequest allowance partway through. workerd's node:dns is a DoH client
  // over fetch(), so every lookup is a subrequest; once the allowance is gone
  // every remaining fetch() throws and the polyfill reports EBADQUERY for the
  // rest of the invocation. 147 of 147 domains past that point were graded
  // D/F off the resolver fault and 137 alerts fired in one run.
  describe("resolver exhaustion (#700)", () => {
    const lookupError = { code: "EBADQUERY", message: "queryMx EBADQUERY x" };

    // What the orchestrator now produces once EBADQUERY is classified as a
    // DnsLookupError: warn + lookup_error on every DNS-backed protocol.
    function makeDegradedScanResult(domain: string) {
      const base = makeScanResult(domain, "D", {});
      return {
        ...base,
        protocols: {
          mx: { status: "warn", lookup_error: lookupError },
          dmarc: { status: "warn", lookup_error: lookupError },
          spf: { status: "warn", lookup_error: lookupError },
          dkim: { status: "fail" },
          bimi: { status: "fail" },
          mta_sts: { status: "fail" },
        },
      };
    }

    function seedUser(): void {
      users.set("u1", {
        id: "u1",
        email: "user@example.com",
        email_domain: "example.com",
        stripe_customer_id: null,
        email_alerts_enabled: 1,
        notify_on_change_only: 0,
        api_key_retirement_acknowledged_at: null,
        created_at: 0,
      });
    }

    function seedDueDomains(count: number): void {
      seedUser();
      for (let i = 1; i <= count; i++) {
        domains.set(i, {
          id: i,
          user_id: "u1",
          domain: `d${i}.example`,
          is_free: 1,
          scan_frequency: "weekly",
          last_scanned_at: now - weekSeconds - 1000 + i,
          last_grade: "A",
          created_at: 0,
        });
      }
    }

    it("does not record or alert on a scan the resolver could not verify", async () => {
      seedUser();
      domains.set(1, {
        id: 1,
        user_id: "u1",
        domain: "appstate.edu",
        is_free: 1,
        scan_frequency: "weekly",
        last_scanned_at: now - weekSeconds - 1,
        last_grade: "B+",
        created_at: 0,
      });

      const webhookFn = vi.fn().mockResolvedValue(undefined);
      const result = await runDueRescans({
        db: makeD1Mock(),
        now,
        scanFn: vi
          .fn()
          .mockResolvedValue(makeDegradedScanResult("appstate.edu")) as never,
        fireWebhookFn: webhookFn as never,
      });

      expect(history.size).toBe(0);
      expect(alerts.size).toBe(0);
      expect(webhookFn).not.toHaveBeenCalled();
      // Grade and due-ness are left untouched, so the next run retries it.
      expect(domains.get(1)?.last_grade).toBe("B+");
      expect(domains.get(1)?.last_scanned_at).toBe(now - weekSeconds - 1);
      expect(result.scanned).toBe(0);
      expect(result.errors).toBe(1);
    });

    it("does not cascade across a 260-domain run when the resolver dies mid-run", async () => {
      seedDueDomains(260);

      const healthyScans = 40;
      let calls = 0;
      const scanFn = vi.fn(async (domain: string) => {
        calls++;
        return calls <= healthyScans
          ? makeScanResult(domain, "A", {})
          : makeDegradedScanResult(domain);
      });

      const webhookFn = vi.fn().mockResolvedValue(undefined);
      const result = await runDueRescans({
        db: makeD1Mock(),
        now,
        scanFn: scanFn as never,
        fireWebhookFn: webhookFn as never,
      });

      // No false grades stored, and no grade-drop / protocol-regression alerts
      // fired off the resolver fault.
      expect(alerts.size).toBe(0);
      expect([...history.values()].every((r) => r.grade === "A")).toBe(true);
      expect(history.size).toBe(healthyScans);
      expect(result.scanned).toBe(healthyScans);

      // The run stops instead of grinding the remaining ~200 domains through a
      // resolver that cannot answer.
      expect(scanFn.mock.calls.length).toBeLessThan(100);

      // Every unverified domain keeps its old grade and stays due.
      for (let i = healthyScans + 1; i <= 260; i++) {
        expect(domains.get(i)?.last_grade).toBe("A");
        expect(domains.get(i)?.last_scanned_at).toBeLessThan(now - weekSeconds);
      }
    });

    it("caps a run below the per-invocation subrequest ceiling and defers the rest", async () => {
      seedDueDomains(260);

      const scanFn = vi.fn(async (domain: string) =>
        makeScanResult(domain, "A", {}),
      );

      const result = await runDueRescans({
        db: makeD1Mock(),
        now,
        maxDomainsPerRun: 60,
        scanFn: scanFn as never,
        fireWebhookFn: vi.fn().mockResolvedValue(undefined) as never,
      });

      expect(scanFn.mock.calls.length).toBe(60);
      expect(result.scanned).toBe(60);
      expect(result.skipped).toBe(200);
      // Deferred domains sort first next run (last_scanned_at ASC), so the
      // portfolio still gets full coverage across consecutive daily runs.
      expect(domains.get(61)?.last_scanned_at).toBeLessThan(now - weekSeconds);
    });
  });
});
