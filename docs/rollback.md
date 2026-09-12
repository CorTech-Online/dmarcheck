# Production rollback runbook

How to undo a bad production deploy of the main Worker.

## Why this document exists

Production deploys leave GitHub entirely. A merge to `main` is picked up by the
**Cloudflare Git integration** (Workers Builds), which builds and deploys
without any GitHub Actions job owning it. That means there is no workflow to
re-run, no artifact to redeploy, and no "revert this deployment" button.
[`prod-smoke.yml`](../.github/workflows/prod-smoke.yml) can *detect* a bad
deploy and file an incident issue, but it cannot undo one.

[`rollback.yml`](../.github/workflows/rollback.yml) is the undo.

## Who runs it

Anyone with **write access** to the repository — GitHub only offers the
`workflow_dispatch` "Run workflow" button to those collaborators. In practice
that is the maintainer. No Cloudflare dashboard login is needed; the workflow
uses the `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` repository secrets.

Run it from **Actions → Rollback → Run workflow**.

## The two levers, and why you need both

| | `pin-version` | `revert-commit` |
|---|---|---|
| What it does | Shifts 100% of production traffic to a previously-uploaded Worker version | Opens a `revert:` PR against `main` |
| Time to take effect | **Seconds** (typically <60s end to end, most of which is `npm ci`) | **Minutes to hours** — bounded by CI, and by review if the change touched a code-owned path |
| Needs a PR? | No | Yes |
| Needs review? | No | Only if the reverted change touched a [CODEOWNERS](../.github/CODEOWNERS) path |
| Durable? | **No** — superseded by the next push to `main` | Yes |

They are complements, not alternatives.

`pin-version` stops the bleeding immediately, but it is **temporary**: the next
push to `main` triggers a fresh Git-integration deploy, and that new version
becomes active — putting the bad code straight back. Until the revert lands,
`main` still contains the defect.

> [!IMPORTANT]
> After a `pin-version`, treat `main` as frozen. Land the revert PR before
> anything else merges, or the next unrelated merge will silently undo your
> rollback.

## Procedure

### 1. Inspect (read-only — always start here)

Run **Rollback** with `action: inspect`. It prints the currently active
deployment and the 10 most recent versions, with their version IDs, creation
times and authors, into the workflow run summary.

Copy the version ID you want to return to. It is normally the entry directly
below the current one.

Cloudflare retains the **100 most recent versions**; if you need something
older than the 10 listed, get its ID from the Cloudflare dashboard under
Workers & Pages → the Worker → Deployments.

### 2. Pin the previous version (the emergency lever)

Run **Rollback** with:

- `action: pin-version`
- `version_id`: the ID from step 1 — or **leave blank** to fall back to the
  version uploaded immediately before the current one
- `reason`: a sentence. It is recorded in the Cloudflare deployment message and
  is what you will read in six months.

The job runs `wrangler rollback`, prints the new active deployment, and
automatically triggers `prod-smoke.yml` so you get an independent check that
the live surface actually recovered.

### 3. Revert the commit (make it durable)

Run **Rollback** with:

- `action: revert-commit`
- `commit`: the SHA on `main` to revert (7–40 hex characters)
- `reason`: same sentence

The job verifies the SHA is an ancestor of `main`, reverts it on a
`rollback/revert-<sha>-<run-id>` branch, opens a PR labelled `rollback`, and
enables auto-merge (squash — `main` requires linear history).

Merge that PR. The Git integration then deploys the reverted `main`, which
supersedes the version pin from step 2 with the same code. Production and
`main` are back in agreement.

## What a version rollback does *not* undo

`wrangler rollback` reverts **executing code only**. It is not a time machine
for state. Specifically:

- **D1 schema is not rolled back.** `migrate.yml` applies migrations
  separately. This is safe by construction rather than by luck: migrations in
  this repo are **additive-only**, enforced by `scripts/migration-lint/`, because
  the migration workflow and the Cloudflare deploy already race with no ordering
  guarantee (see [src/db/CLAUDE.md](../src/db/CLAUDE.md)). Old code is therefore
  expected to run against newer schema. If you ever land a genuinely destructive
  migration through the escape hatch, a code rollback across it is **not** safe.
- **KV, Durable Object and D1 *data* are untouched.** Anything the bad version
  wrote stays written. Rolling back the code does not un-write a corrupt
  `INBOX_TOKENS` entry or a bad `scan_history` row.
- **Bindings and secrets are not restored.** Cloudflare's documentation is
  explicit that resources connected to the Worker are unchanged by a rollback.
- **The `mta-sts-worker` is a separate deployment** with its own
  [workflow](../.github/workflows/deploy-mta-sts.yml). This lever does not touch it.

## Failure modes to expect

| Symptom | Cause and what to do |
|---|---|
| `pin-version` fails with a Durable Object error | Cloudflare **blocks** a rollback across a Durable Object class lifecycle change. If a `[[migrations]]` entry for `RateLimiterDO` landed between the two versions, you must roll forward with a fix instead. |
| `pin-version` fails citing a missing binding | The target version references a KV/D1/R2/queue binding that no longer exists. Pick a newer version, or roll forward. |
| The version you want is not listed | Older than the 100 retained versions. Use `revert-commit`. |
| `inspect` fails on credentials | `CLOUDFLARE_API_TOKEN` needs **Workers Scripts: Edit** on the account owning the Worker. It is the same secret `deploy-mta-sts.yml` uses; account-scoped tokens cover both Workers, but a token scoped to only the MTA-STS Worker will not. Use `revert-commit` meanwhile. |
| `revert-commit` fails with a conflict | The commit cannot be reverted mechanically because later commits touched the same lines. Use `pin-version` to hold the line, then write the revert by hand. |
| The revert PR sits with no checks running | See below. |

### The revert PR shows no CI

GitHub deliberately suppresses workflow triggers for events raised by
`GITHUB_TOKEN`, to prevent recursive runs. A PR opened by the workflow with the
default token therefore does **not** fire `pull_request`, so CI never starts,
the required `check` context never reports, and the PR cannot merge.

**Workaround:** close the PR and immediately reopen it. That is a human action
and fires the event normally. The workflow detects this case and prints the
instruction in both the PR body and the run summary.

**Proper fix:** once `secrets.FACTORY_GH_TOKEN` exists (the bot-identity split,
[#299](https://github.com/schmug/dmarc.mx/issues/299)), the workflow picks it up
automatically — it already prefers that secret and falls back only when it is
absent. No workflow change will be needed.

## On the CODEOWNERS exemption

[Issue #657](https://github.com/schmug/dmarc.mx/issues/657) asked for a
CODEOWNERS exemption "for that path so a revert never needs an approving review
to land." **This repo does not have one, deliberately.** The reasoning:

1. **CODEOWNERS cannot express it.** Ownership is matched on the paths in a
   PR's diff. A revert PR's diff is, by definition, the paths the reverted
   commit touched. Un-owning `.github/workflows/rollback.yml` would exempt
   *edits to the rollback workflow itself* — not reverts. There is no
   path-based way to say "PRs that are reverts skip review."
2. **It would be the wrong file to un-own.** `rollback.yml` holds
   `contents: write`, `pull-requests: write`, `actions: write` and the
   Cloudflare deploy token. `/.github/` is code-owned precisely because "a PR
   can otherwise rewrite its own merge gate." Un-owning the most privileged
   workflow in the repo to buy nothing is a bad trade.
3. **The gap it was meant to close is already closed.** The factory's merge
   gate (`.factory/gate.json`) refuses to auto-merge any PR touching its
   `riskPathDenylist`, which is a **superset** of CODEOWNERS and additionally
   force-includes `.github/**`, `.factory/**` and `CODEOWNERS`. So every change
   the factory can land unattended is, by construction, outside every
   code-owned path — and so is its revert. Those revert PRs need no approval
   today and will need none after the bot-identity split.
4. **For the remaining case, review is correct.** A human-authored change to
   `src/index.ts` is code-owned, so its revert is too. Reverting input
   validation or rate limiting on an unreviewed automated trigger is a
   capability worth *not* having — and `pin-version` already restores service
   in seconds without touching git, so the review costs no downtime.

Note that today the gate is even looser than the above: GitHub does not request
review from a PR's own author, and @schmug is the sole code owner, so a
@schmug-authored PR on a code-owned path merges freely regardless. The analysis
above is written for the post-#299 state, where that no longer holds. See
[#658](https://github.com/schmug/dmarc.mx/issues/658).

If the maintainer decides review-free git reverts are worth it anyway, the
mechanism is a `bypass_actors` entry on the `main-protection` ruleset (a repo
setting, not a file in this repo). That is strictly *wider* than a CODEOWNERS
exemption, which is the main argument against it.

## Release side effects

A revert lands on `main` like any other commit, so `Release` runs and cuts a
CalVer tag. **This is intended.** The GitHub Releases page is this project's
changelog, and a rollback changes what is running in production; suppressing
the tag would leave the changelog asserting that reverted code is still live.
`cliff.toml` groups these commits under a **Reverted** heading, and
`scripts/release/__tests__/releasable.test.ts` pins both behaviours so neither
drifts silently.

## Drill

An untested rollback lever is not a rollback lever.

> [!NOTE]
> GitHub only offers the "Run workflow" button for `workflow_dispatch`
> workflows that exist on the **default branch**. This workflow cannot be
> dispatched — not even the read-only `inspect` action — until it has merged
> to `main`. The drill necessarily happens after merge, not before it.

The drill is:

1. `action: inspect` — confirm credentials work and versions are listed.
   Read-only; safe to run any time.
2. `action: pin-version` with the previous version ID and
   `reason: "scheduled rollback drill"`. Confirm `prod-smoke` goes green
   against the rolled-back deploy.
3. Roll forward by re-running the Cloudflare Git integration deploy for
   `main`'s current head (or `action: pin-version` back to the version you
   started on). Confirm `prod-smoke` is green again.
4. `action: revert-commit` against a low-risk, easily-reverted commit to
   confirm the PR path works end to end, then close the PR without merging if
   the revert is not actually wanted.
5. Record the run URLs and timings in
   [#657](https://github.com/schmug/dmarc.mx/issues/657).

> [!NOTE]
> **Drill status: not yet run.** Steps 1–5 are the maintainer's to execute —
> they mutate live production traffic. Until they are done and recorded, treat
> this lever as untested and do not count #657 as satisfying the arming
> precondition in [`.factory/README.md`](../.factory/README.md).
