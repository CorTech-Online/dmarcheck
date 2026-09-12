# `.factory/` — software factory configuration

The autonomous issue→fix→merge loop. The engine lives in the
[shipofclaudius](https://github.com/schmug/shipofclaudius) plugin
(`factory-issue-fix` / `factory-land` / `packages/factory-gate`); this directory holds only
**this repo's** configuration, and `.github/workflows/factory.yml` is the scheduler.

| File | What it is |
|---|---|
| `gate.json` | The merge gate's config. Read from **`main`** on every run, never from the PR. |
| `setup-labels.sh` | Creates the label state machine. Idempotent; already run. |

## Status: WIRED, NOT ARMED

The plumbing is in place and can be exercised end to end, but the factory **cannot auto-merge
anything today** and that is deliberate. Three independent things still gate it:

1. **`fix-verified` is human-minted.** `requireFixtureEvidence` is `false` because this repo has no
   reproduction harness yet (see the issue tracker). Until it does, the reproduce phase has no
   mechanical definition of done, so a human applies the trust token after reviewing the draft PR.
2. **`secrets.FACTORY_GH_TOKEN` does not exist yet**, and it must be a **distinct identity from
   @schmug**. GitHub forbids self-approval, so a token acting as the code owner can never satisfy
   the `require_code_owner_review` rule on `main-protection`. Until that identity exists the
   `advance` and `land` jobs cannot run.
3. **The rollback lever is built but undrilled.** `.github/workflows/rollback.yml` (#657) gives
   production a revert path from GitHub: `pin-version` shifts traffic back to a previous Worker
   version in seconds with no PR and no review, and `revert-commit` opens the `revert:` PR that
   makes it durable. Runbook: [docs/rollback.md](../docs/rollback.md). **It has not yet been
   exercised against production**, and an untested rollback lever is not a rollback lever — run
   the drill in the runbook and record it on #657 before treating this blocker as cleared.

Do not raise `allowlistAuthors` off a reviewed list, and do not set `requireFixtureEvidence: true`,
until those are resolved.

## `gate.json` mirrors CODEOWNERS on purpose

Anything a code owner must approve is also something the gate refuses to auto-merge. The denylist
is a **superset** of `.github/CODEOWNERS`, adding paths that are security- or money-sensitive but
not currently code-owned: `src/auth/**`, `src/account/**`, `src/billing/**`, `src/webhooks/**`,
`src/rate-limit-do.ts`, `mta-sts-worker/**`, `scripts/routine-gate/**`.

`.factory/**`, `.github/workflows/**`, `.github/CODEOWNERS` and `CODEOWNERS` are added
**automatically** by the gate and cannot be removed by this file — a PR must never be able to widen
the rules it is judged by. Every condition **fails closed**: missing data, ambiguous data, and an
`UNKNOWN` CI state all mean "no".

## The two human-only labels

- **`fix-verified`** — the trust token, and the only thing that unlocks the merge gate. Apply it
  only after reviewing the draft PR and its preview.
- **`pipeline-paused`** — the kill switch. Apply it to any open issue and the whole factory halts on
  its next run. No PR, no redeploy, no waiting.
