# Security Policy

Thanks for helping keep dmarcheck safe for everyone who uses it.

## Reporting a vulnerability

**Please do not open public GitHub issues for security problems.**

Report suspected vulnerabilities privately via
[GitHub's private vulnerability reporting](https://github.com/schmug/dmarcheck/security/advisories/new).
That creates a confidential advisory only the maintainer can see.

If you cannot use GitHub's private reporting, email the maintainer via the
contact listed on the [GitHub profile](https://github.com/schmug).

Please include:

- A clear description of the issue
- Steps to reproduce (a proof-of-concept URL or payload is ideal)
- The impact you believe the issue has
- Any suggested remediation, if you have one in mind

### Disclosure timeline

dmarcheck is maintained by a single person in their spare time, so these are
best-effort targets rather than contractual SLAs — but they are concrete so you
know what to expect:

| Stage | Target |
|-------|--------|
| **Acknowledgement** — we confirm we received your report | within **3 business days** |
| **Triage** — we validate the issue and assign a severity | within **7 business days** of acknowledgement |
| **Fix** — a remediation ships to the live service | **critical/high:** target **30 days**; **medium/low:** next convenient release |
| **Public disclosure** — the advisory is published as a [GitHub Security Advisory](https://github.com/schmug/dmarcheck/security/advisories) under `schmug/dmarcheck` | when the fix is deployed, or **90 days** after the report, whichever comes first |

Because dmarcheck is a rolling release deployed continuously from `main` (see
[Supported versions](#supported-versions)), a fix reaches all users as soon as
it merges — there is no back-porting. Critical issues affecting the live service
at [dmarc.mx](https://dmarc.mx) are prioritised over everything else. We'll keep
you updated through the advisory and credit you in the published advisory unless
you ask us not to.

## Scope

In scope:

- The live service at [dmarc.mx](https://dmarc.mx) and its API
- The [mta-sts.dmarc.mx](https://mta-sts.dmarc.mx) helper worker
- The source code in this repository, including CI/CD workflows

Out of scope:

- Denial-of-service attacks against the live service (Cloudflare's edge
  handles this — reports about generic DoS will be closed)
- Findings that require the reporter to control DNS records for an
  arbitrary third-party domain they do not own
- Reports generated solely by automated scanners without a working
  proof-of-concept
- Vulnerabilities in third-party dependencies that are already tracked by
  Dependabot unless you have a working exploit chain

## Supported versions

dmarcheck is a rolling release deployed continuously from `main`. There are
no long-lived branches or LTS versions. The only supported version is the
current contents of `main` / the deployed Worker.

## Rolling back a bad deploy

Because deploys go out through the Cloudflare Git integration rather than a
GitHub Actions job, there is no deployment to re-run and no artifact to
redeploy. The revert path is the **Rollback** workflow
([.github/workflows/rollback.yml](.github/workflows/rollback.yml)), run from
Actions → Rollback → Run workflow by anyone with write access:

- **`pin-version`** shifts production traffic back to a previously-uploaded
  Worker version in seconds, with no PR and no review. This is the lever to
  pull first when the live service is broken — including when the break is a
  security regression.
- **`revert-commit`** opens the `revert:` PR that makes it durable. A version
  pin is superseded by the next push to `main`, so the revert must land before
  anything else merges.

A code rollback does **not** roll back D1 schema, KV/Durable Object data, or
bindings. Read [docs/rollback.md](docs/rollback.md) before using it — it
documents the preconditions, the failure modes, and why no CODEOWNERS
exemption accompanies it.

## Vulnerability management

We run automated software-composition analysis (SCA) and static analysis (SAST)
on every change, with the following remediation thresholds:

**Dependencies (SCA).**

- CI runs `npm audit --audit-level=high --omit=dev` as a required `check` step.
  A **HIGH or CRITICAL** CVE in a **runtime** dependency **blocks the merge** and
  must be fixed (upgrade, patch, or remove the dependency) before the PR can land.
- **Moderate/low** runtime CVEs and **dev-only** dependency CVEs (biome, vitest,
  wrangler, sharp — none of which ship to the Worker runtime) do not block
  merges. They are surfaced as Dependabot alerts in the **Security** tab and
  batched into routine dependency-bump PRs.
- [Dependabot](.github/dependabot.yml) opens dependency and GitHub-Actions
  update PRs weekly.
- **Exception process:** if a HIGH/CRITICAL runtime CVE genuinely cannot be
  remediated (no patch is available yet, or the advisory does not apply to how
  the dependency is actually used), the maintainer may accept the risk by
  recording the justification in the PR and overriding the gate — the same
  dismiss-with-justification discipline applied to CodeQL alerts below. The
  override and its rationale stay visible in the PR history, and the CVE is
  re-checked when Dependabot's next bump lands a fix.

**Code (SAST).**

- [CodeQL](.github/workflows/codeql.yml) runs on every pull request and on a
  weekly schedule (`Analyze (actions)` and `Analyze (javascript-typescript)`).
- **Error-severity** CodeQL alerts are triaged and remediated before the
  associated change merges; warning/note-level alerts are reviewed in the
  Security tab and fixed or dismissed-with-justification.

These thresholds intentionally match CI's gate so the "what blocks a merge"
answer is the same whether you read the policy or the workflow. They tighten if
the [threat model](THREAT_MODEL.md) expands to cover developer machines.

See [docs/OSPS-DEVIATIONS.md](docs/OSPS-DEVIATIONS.md) for where dmarcheck
intentionally deviates from the OSPS Baseline, and [THREAT_MODEL.md](THREAT_MODEL.md)
for the system's assets, entry points, and threats.

## Safe harbour

Security research conducted in good faith against the scope above — including
automated scanning at reasonable rates, and testing with domains you own — is
welcome. Please avoid:

- Testing against third parties' domains you do not control
- Automated scanning that hammers `dmarc.mx` at high volume
- Actions that could degrade service for other users
- Accessing, modifying, or exfiltrating data that is not yours

Reports that follow this policy will not result in legal action from the
maintainer.
