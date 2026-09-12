/**
 * The nightly cron entrypoint must report its own outcome to the platform.
 *
 * The handler used to hand the rescan to `ctx.waitUntil()` and return, so the
 * Cron Trigger recorded a microsecond-long SUCCESS no matter what the rescan
 * actually did — including the run that false-graded 147 domains (#700). The
 * `.catch()` routed the failure to Sentry and swallowed it, so nothing the
 * platform could see ever went red, and the reported duration measured a
 * handler that had already returned.
 *
 * The handler now awaits the work and re-throws after capturing, so a failed
 * invocation is recorded as failed and the duration covers the real rescan.
 * `Sentry.withSentry`'s scheduled wrapper re-throws after its own capture
 * (`instrumentations/worker/instrumentScheduled.js`), so the rejection reaches
 * the runtime through it.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env.js";

const {
  captureException,
  setTag,
  runDueRescans,
  dispatchPendingAlerts,
  sweepWorkosRetries,
} = vi.hoisted(() => ({
  captureException: vi.fn(),
  setTag: vi.fn(),
  runDueRescans: vi.fn(),
  dispatchPendingAlerts: vi.fn(),
  sweepWorkosRetries: vi.fn(),
}));

// `withSentry` is a pass-through here so the default export is the raw handler
// object: this test is about the handler's own contract, not the SDK wrapper.
vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException,
  getCurrentScope: () => ({ setTag }),
  withSentry: <T>(_optionsCallback: unknown, handler: T) => handler,
}));

vi.mock("../src/cron/rescan.js", () => ({ runDueRescans }));
vi.mock("../src/alerts/dispatcher.js", () => ({ dispatchPendingAlerts }));
vi.mock("../src/account/workos-retry.js", () => ({
  sweepWorkosRetries,
  enqueueWorkosRetry: vi.fn(),
}));

const worker = (await import("../src/index.js")).default;

const controller = {
  cron: "17 6 * * *",
  scheduledTime: Date.now(),
  noRetry: () => {},
} as unknown as ScheduledController;

function makeCtx() {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

const env = { DB: {} } as unknown as Env;

/** Lets every already-queued microtask and timer callback run. */
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

function runScheduled(e: Env, ctx: ExecutionContext): Promise<void> {
  const scheduled = worker.scheduled;
  if (!scheduled) throw new Error("worker has no scheduled handler");
  return Promise.resolve(scheduled(controller, e, ctx));
}

beforeEach(() => {
  vi.clearAllMocks();
  runDueRescans.mockResolvedValue({
    scanned: 12,
    alerts: 2,
    errors: 1,
    skipped: 7,
  });
  dispatchPendingAlerts.mockResolvedValue({ sent: 2, skipped: 1, errors: 0 });
  sweepWorkosRetries.mockResolvedValue({
    retried: 1,
    cleared: 1,
    givenUp: 0,
  });
});

describe("scheduled() cron handler", () => {
  it("rejects when the rescan fails, after reporting it to Sentry", async () => {
    const boom = new Error("rescan blew up");
    runDueRescans.mockRejectedValue(boom);

    await expect(runScheduled(env, makeCtx())).rejects.toThrow(
      "rescan blew up",
    );
    expect(captureException).toHaveBeenCalledWith(boom);
  });

  it("rejects when alert dispatch fails", async () => {
    const boom = new Error("dispatch blew up");
    dispatchPendingAlerts.mockRejectedValue(boom);

    await expect(runScheduled(env, makeCtx())).rejects.toThrow(
      "dispatch blew up",
    );
    expect(captureException).toHaveBeenCalledWith(boom);
  });

  it("does not resolve until the rescan work has finished", async () => {
    let release: (result: unknown) => void = () => {};
    runDueRescans.mockReturnValue(
      new Promise((resolve) => {
        release = resolve;
      }),
    );

    let settled = false;
    const promise = runScheduled(env, makeCtx()).then(() => {
      settled = true;
    });

    await tick();
    expect(settled).toBe(false);
    expect(dispatchPendingAlerts).not.toHaveBeenCalled();
    expect(sweepWorkosRetries).not.toHaveBeenCalled();

    release({ scanned: 1, alerts: 0, errors: 0, skipped: 0 });
    await promise;

    expect(settled).toBe(true);
    expect(dispatchPendingAlerts).toHaveBeenCalledTimes(1);
    expect(sweepWorkosRetries).toHaveBeenCalledTimes(1);
  });

  it("sets the cron.* scope tags a successful run reports", async () => {
    await runScheduled(env, makeCtx());

    expect(Object.fromEntries(setTag.mock.calls)).toEqual({
      "cron.scanned": "12",
      "cron.alerts": "2",
      "cron.errors": "1",
      "cron.skipped": "7",
      "cron.emails_sent": "2",
      "cron.emails_skipped": "1",
      "cron.emails_errors": "0",
      "cron.workos_retried": "1",
      "cron.workos_cleared": "1",
      "cron.workos_given_up": "0",
    });
  });

  it("returns without scanning when DB is unbound", async () => {
    await expect(
      runScheduled({} as unknown as Env, makeCtx()),
    ).resolves.toBeUndefined();

    expect(runDueRescans).not.toHaveBeenCalled();
    expect(captureException).not.toHaveBeenCalled();
  });
});
