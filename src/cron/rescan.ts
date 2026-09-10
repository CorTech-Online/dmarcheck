import * as Sentry from "@sentry/cloudflare";
import {
  type AlertPayload,
  detectGradeDrop,
  detectProtocolRegressions,
} from "../alerts/detector.js";
import type { ScanResult } from "../analyzers/types.js";
import { recordAlerts } from "../db/alerts.js";
import { type Domain, getDueDomains } from "../db/domains.js";
import { recordScan } from "../db/scans.js";
import { getUserById } from "../db/users.js";
import { scan } from "../orchestrator.js";
import type { ScoringConfig } from "../shared/scoring.js";
import { fireScanCompletedWebhook } from "../webhooks/triggers.js";

export interface RescanResult {
  scanned: number;
  alerts: number;
  errors: number;
  /** Due domains deliberately not attempted this run — deferred to the next. */
  skipped: number;
}

type WebhookFireFn = (
  db: D1Database,
  userId: string,
  input: {
    domain: string;
    grade: string;
    scanId: string | number;
    trigger: "cron";
  },
) => Promise<void>;

interface RescanDeps {
  db: D1Database;
  now: number;
  batchSize?: number;
  scanFn?: (domain: string) => Promise<ScanResult>;
  // Self-host scoring rubric override, forwarded to scan() (issue #25).
  scoringConfig?: Partial<ScoringConfig>;
  // Optional Spamhaus DQS key, forwarded to scan() (issue #587); absent → no-op.
  dnsblKey?: string;
  fireWebhookFn?: WebhookFireFn;
  // #700 knobs; see MAX_DOMAINS_PER_RUN / DEGRADED_STREAK_LIMIT.
  maxDomainsPerRun?: number;
  degradedStreakLimit?: number;
}

interface PreviousProtocolStatuses {
  dmarc?: string;
  spf?: string;
  dkim?: string;
  bimi?: string;
  mta_sts?: string;
}

// Reads the most recent scan_history row's protocol_results (parsed JSON) so
// we can diff protocol statuses. Returns null on first-ever scan or when the
// row is missing / unparseable — detectProtocolRegressions handles null.
async function getPreviousProtocolStatuses(
  db: D1Database,
  domainId: number,
): Promise<PreviousProtocolStatuses | null> {
  const row = await db
    .prepare(
      "SELECT protocol_results FROM scan_history WHERE domain_id = ? ORDER BY scanned_at DESC LIMIT 1",
    )
    .bind(domainId)
    .first<{ protocol_results: string | null }>();
  if (!row?.protocol_results) return null;
  try {
    const parsed = JSON.parse(row.protocol_results) as Record<
      string,
      { status?: string }
    >;
    return {
      dmarc: parsed.dmarc?.status,
      spf: parsed.spf?.status,
      dkim: parsed.dkim?.status,
      bimi: parsed.bimi?.status,
      mta_sts: parsed.mta_sts?.status,
    };
  } catch {
    return null;
  }
}

function extractStatuses(result: ScanResult): PreviousProtocolStatuses {
  return {
    dmarc: result.protocols.dmarc.status,
    spf: result.protocols.spf.status,
    dkim: result.protocols.dkim.status,
    bimi: result.protocols.bimi.status,
    mta_sts: result.protocols.mta_sts.status,
  };
}

function resultChanged(
  domain: Domain,
  prevStatuses: PreviousProtocolStatuses | null,
  result: ScanResult,
): boolean {
  if (result.grade !== domain.last_grade) return true;
  if (!prevStatuses) return true;
  const next = extractStatuses(result);
  return (
    prevStatuses.dmarc !== next.dmarc ||
    prevStatuses.spf !== next.spf ||
    prevStatuses.dkim !== next.dkim ||
    prevStatuses.bimi !== next.bimi ||
    prevStatuses.mta_sts !== next.mta_sts
  );
}

// #700 — a scan whose DNS lookups failed is not a verdict about the domain.
// These three protocols determine the grade: scoring.ts returns a flat D on a
// DMARC lookup_error, and MX/SPF drive the modifiers. If any of them could not
// be read, the computed grade describes the lookup, not the domain, so it is
// never alerted on. Alerting on it is what fired 137 alerts in one run.
const GRADE_CRITICAL_PROTOCOLS = ["dmarc", "spf", "mx"] as const;

function lookupErrorCode(result: ScanResult): string | null {
  for (const id of GRADE_CRITICAL_PROTOCOLS) {
    const code = result.protocols[id].lookup_error?.code;
    if (code) return code;
  }
  return null;
}

// Whose fault the lookup failure is decides whether we defer the domain or
// record it. This distinction is load-bearing, not cosmetic:
//
//   OUR fault — the invocation could not issue the query at all. EBADQUERY is
//   raised only when workerd's DoH fetch() itself throws, i.e. the
//   per-invocation subrequest allowance is spent; BUDGET_EXCEEDED /
//   SCAN_DEADLINE are our own guards; analyzer_error is an internal blow-up.
//   These say nothing about the domain, so the result is discarded and the
//   domain left due.
//
//   THE DOMAIN'S (or the network's) — DNS_TIMEOUT, ESERVFAIL, EBADRESP,
//   EREFUSED: the query went out and came back bad. That IS a finding about
//   the domain (real senders see it too), so it is recorded like any other
//   result — just never alerted on.
//
// Deferring domain-side faults instead would starve the queue: `getDueDomains`
// orders by `last_scanned_at ASC`, so a domain with dead nameservers would sort
// FIRST on every subsequent run, hold a MAX_DOMAINS_PER_RUN slot forever, and —
// once enough clustered at the head — trip DEGRADED_STREAK_LIMIT before a
// single healthy domain was scanned. This portfolio already carries ~10 such
// domains (the DNS_TIMEOUT set).
const OUR_FAULT_CODES = new Set([
  "EBADQUERY",
  "BUDGET_EXCEEDED",
  "SCAN_DEADLINE",
  "analyzer_error",
]);

// Backstop for a fault we blame on ourselves that nevertheless never clears
// (say an analyzer that reliably throws on one domain's records). Past this
// much staleness the domain is recorded with its lookup_error anyway, so
// `last_scanned_at` advances and it can never hold a slot indefinitely. The
// invariant is unconditional: no domain can be deferred forever.
const MAX_DEFERRAL_SECONDS = 3 * 24 * 60 * 60;

function deferralExhausted(domain: Domain, now: number): boolean {
  const cadence =
    domain.scan_frequency === "monthly" ? 30 * 24 * 60 * 60 : 7 * 24 * 60 * 60;
  // last_scanned_at null = never successfully scanned; measure from creation
  // so a never-scannable domain can't sit at the head of NULLS FIRST forever.
  const since = domain.last_scanned_at ?? domain.created_at;
  return now - since > cadence + MAX_DEFERRAL_SECONDS;
}

async function rescanOne(
  deps: RescanDeps,
  domain: Domain,
): Promise<{ alerts: number; error?: unknown; degraded?: boolean }> {
  const scanFn =
    deps.scanFn ??
    ((domain: string) =>
      scan(domain, [], deps.scoringConfig ?? {}, undefined, deps.dnsblKey));
  const prevStatuses = await getPreviousProtocolStatuses(deps.db, domain.id);

  let result: ScanResult;
  try {
    result = await scanFn(domain.domain);
  } catch (err) {
    return { alerts: 0, error: err };
  }

  // Our own fault and not yet stale enough to force through: discard the
  // result and leave last_scanned_at untouched, so the domain stays due and is
  // retried at the front of the next run's `ORDER BY last_scanned_at ASC`.
  const errorCode = lookupErrorCode(result);
  if (
    errorCode &&
    OUR_FAULT_CODES.has(errorCode) &&
    !deferralExhausted(domain, deps.now)
  ) {
    Sentry.addBreadcrumb({
      category: "cron.rescan",
      message: `Deferring ${domain.domain}: could not issue DNS lookups (${errorCode})`,
      data: { domain: domain.domain, code: errorCode },
      level: "warning",
    });
    return { alerts: 0, degraded: true };
  }

  await recordScan(deps.db, {
    domainId: domain.id,
    grade: result.grade,
    scoreFactors: result.breakdown.factors,
    protocolResults: result.protocols,
    scannedAt: deps.now,
  });

  // An unverifiable scan is recorded (so the domain advances) but never
  // asserts its grade to an outbound channel: the same false-claim reasoning
  // as the alert gate below applies to a webhook carrying `grade: "D"` for a
  // scan we could not complete (#703).
  const user = await getUserById(deps.db, domain.user_id);
  const shouldFireWebhook =
    !errorCode &&
    (!user?.notify_on_change_only ||
      resultChanged(domain, prevStatuses, result));
  if (shouldFireWebhook) {
    const fireWebhook = deps.fireWebhookFn ?? fireScanCompletedWebhook;
    await fireWebhook(deps.db, domain.user_id, {
      domain: domain.domain,
      grade: result.grade,
      scanId: domain.id,
      trigger: "cron",
    });
  }

  // An unverifiable scan is recorded (so the domain advances) but never
  // alerted on: "your grade dropped to D" off a lookup we could not complete
  // is the false-alarm this issue is about, whoever's fault the lookup was.
  const alerts: AlertPayload[] = [];
  if (!errorCode) {
    const gradeAlert = detectGradeDrop(domain.last_grade, result.grade);
    if (gradeAlert) alerts.push(gradeAlert);
    alerts.push(
      ...detectProtocolRegressions(prevStatuses, extractStatuses(result)),
    );
  }

  if (alerts.length > 0) {
    await recordAlerts(
      deps.db,
      alerts.map((alert) => ({
        domainId: domain.id,
        type: alert.type,
        previousValue: alert.previousValue,
        newValue: alert.newValue,
        createdAt: deps.now,
      })),
    );
  }

  return { alerts: alerts.length };
}

// #700 — per-invocation domain ceiling.
//
// In workerd, `node:dns` is not c-ares: it is a DoH client that fetch()es
// https://cloudflare-dns.com/dns-query for every lookup (see the polyfill's
// sendDnsRequest). Every DNS query a scan makes is therefore a Workers
// SUBREQUEST, and subrequests are capped per invocation, not per second. A
// full-portfolio run exhausts that allowance partway through; from then on
// every fetch() throws, the polyfill reports EBADQUERY, and it never recovers
// for the rest of the invocation — which is exactly the observed hard cliff at
// a fixed position with 100% failure after it and 0% correlation with batching.
//
// Note this is NOT the module-level `new dns.promises.Resolver()` handle in
// src/dns/client.ts: workerd's Resolver is a stateless pass-through to the
// same module functions and holds no socket, so recycling it changes nothing.
//
// 150 is derived from production: run 1788934679 completed 192 domains before
// the cliff, so 150 leaves ~22% headroom. The cron fires daily while domains
// come due weekly, so a 344-domain portfolio is fully covered in ~3 runs;
// deferred domains keep their old last_scanned_at and therefore sort FIRST in
// the next run's `ORDER BY last_scanned_at ASC`, which rotates coverage
// without any extra bookkeeping.
const MAX_DOMAINS_PER_RUN = 150;

// Backstop for when the ceiling above is still too high (a heavier-than-usual
// portfolio, or a platform limit lower than the measured one). Once this many
// domains in a row are DEFERRED — meaning we could not issue their lookups at
// all — the invocation's outbound allowance is spent: continuing cannot produce
// a usable scan and only burns wall-clock, so stop and let the next run pick up
// the remainder. 10 = two default batches. Only deferrals count; domain-side
// lookup failures and DB errors are recorded/counted but never halt the run.
const DEGRADED_STREAK_LIMIT = 10;

// Entry point for the scheduled() handler. Runs the rescan pipeline across
// due domains in bounded batches, up to the per-invocation ceiling. Failures
// on individual domains are caught and counted — one domain's DNS timeout must
// not stop the rest.
//
// batchSize default is 5: each scan fires ~6 concurrent DNS queries, so
// 5 × 6 = ~30 concurrent lookups per batch — well within the workerd
// node:dns polyfill's capacity. The original value of 25 (~150 concurrent
// lookups) overwhelmed the resolver and caused every query in the batch to
// time out, producing a false-fail cascade across all monitored domains.
// See: https://github.com/schmug/dmarcheck/issues/240
//
// batchSize bounds CONCURRENCY; MAX_DOMAINS_PER_RUN bounds CUMULATIVE work.
// #240 fixed the first and left the second — keep both.
export async function runDueRescans(deps: RescanDeps): Promise<RescanResult> {
  const batchSize = deps.batchSize ?? 5;
  const maxDomains = deps.maxDomainsPerRun ?? MAX_DOMAINS_PER_RUN;
  const streakLimit = deps.degradedStreakLimit ?? DEGRADED_STREAK_LIMIT;
  const due = await getDueDomains(deps.db, deps.now);
  const budgeted = due.slice(0, maxDomains);
  let scanned = 0;
  let alertCount = 0;
  let errors = 0;
  let processed = 0;
  let degradedStreak = 0;

  Sentry.addBreadcrumb({
    category: "cron.rescan",
    message: `Starting rescan: ${due.length} due, ${budgeted.length} this run, batchSize=${batchSize}`,
    data: { total: due.length, thisRun: budgeted.length, batchSize },
    level: "info",
  });

  for (let i = 0; i < budgeted.length; i += batchSize) {
    const batch = budgeted.slice(i, i + batchSize);
    Sentry.addBreadcrumb({
      category: "cron.rescan",
      message: `Batch ${Math.floor(i / batchSize) + 1}: scanning ${batch.map((d) => d.domain).join(", ")}`,
      data: {
        batchIndex: Math.floor(i / batchSize),
        domains: batch.map((d) => d.domain),
      },
      level: "info",
    });
    const outcomes = await Promise.allSettled(
      batch.map((d) => rescanOne(deps, d)),
    );
    processed += batch.length;
    for (const outcome of outcomes) {
      // A rejection here is a DB / webhook failure, not a DNS one (scan() is
      // wrapped in rescanOne's try, and settle() means it does not reject for
      // analyzer reasons). It must not trip the DNS circuit breaker — one bad
      // row would otherwise halt the whole rescan.
      if (outcome.status === "rejected") {
        errors += 1;
        Sentry.captureException(outcome.reason);
        continue;
      }
      if (outcome.value.error) {
        errors += 1;
        Sentry.captureException(outcome.value.error);
        continue;
      }
      if (outcome.value.degraded) {
        // Only a deferral — i.e. we could not issue the query at all — counts
        // toward the breaker. Domain-side faults are recorded, not deferred,
        // so they can never halt a run.
        errors += 1;
        degradedStreak += 1;
        continue;
      }
      degradedStreak = 0;
      scanned += 1;
      alertCount += outcome.value.alerts;
    }
    if (degradedStreak >= streakLimit) {
      Sentry.addBreadcrumb({
        category: "cron.rescan",
        message: `Stopping run: ${degradedStreak} consecutive domains could not be resolved — outbound budget likely exhausted`,
        data: { processed, remaining: due.length - processed, degradedStreak },
        level: "error",
      });
      break;
    }
  }

  const skipped = due.length - processed;

  Sentry.addBreadcrumb({
    category: "cron.rescan",
    message: `Rescan complete: scanned=${scanned}, alerts=${alertCount}, errors=${errors}, skipped=${skipped}`,
    data: { scanned, alerts: alertCount, errors, skipped },
    level: errors > 0 ? "warning" : "info",
  });

  return { scanned, alerts: alertCount, errors, skipped };
}
