import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Invariants for the production rollback lever (#657). This is the one
// workflow an operator runs while production is broken, so the failure modes
// that matter are the ones that only surface at 3am:
//
//   - a `${{ inputs.* }}` interpolated straight into a `run:` body is a shell
//     injection carrying `contents: write` (the `reason` input is free text),
//   - a hardcoded repo slug silently breaks on a rename — schmug/dmarcheck →
//     schmug/dmarc.mx already did exactly this to the release workflow (#679),
//   - an unpinned action is an unreviewed dependency in the rollback path.
//
// These assertions are tripwires, not a YAML parser: they exist so a later
// edit that reintroduces one of those shapes fails in CI rather than during an
// incident.

const WORKFLOW_PATH = ".github/workflows/rollback.yml";
const workflow = readFileSync(resolve(process.cwd(), WORKFLOW_PATH), "utf8");
const lines = workflow.split("\n");

// `${{ inputs.x }}` / `${{ github.event.inputs.x }}` in any form.
const INPUT_EXPR = /\$\{\{[^}]*\binputs\./;
// Two legal homes for one:
//   VERSION_ID: ${{ inputs.version_id }}   — an UPPER_SNAKE env mapping; the
//     shell then reads "$VERSION_ID", which it does not re-parse.
//   if: ${{ inputs.action == 'pin-version' }} — a job/step condition,
//     evaluated by the Actions expression engine and never by a shell.
// Anything else means the value reaches a `run:` body as literal text.
const SAFE_HOST = /^\s*(?:[A-Z][A-Z0-9_]*:\s*\$\{\{|if:\s*\$\{\{)/;

describe("rollback workflow — shell-injection safety", () => {
  it("never interpolates a dispatch input anywhere but an env mapping or an if:", () => {
    const offenders = lines
      .map((line, i) => ({ line, lineNo: i + 1 }))
      .filter(({ line }) => INPUT_EXPR.test(line) && !SAFE_HOST.test(line));

    expect(
      offenders.map(
        ({ line, lineNo }) => `${WORKFLOW_PATH}:${lineNo}: ${line.trim()}`,
      ),
    ).toEqual([]);
  });

  it("validates the version_id and commit inputs against an anchored allowlist regex", () => {
    // Both reach a git/wrangler argv. Anchored character-class validation is
    // what keeps an operator typo (or a malicious dispatch) from becoming an
    // argument-injection primitive.
    expect(workflow).toMatch(/\[0-9a-f\]\{7,40\}\$/);
    expect(workflow).toMatch(/\[0-9a-f-\]\{36\}\$/);
  });
});

describe("rollback workflow — rename resilience (#679)", () => {
  it("uses github.repository instead of a hardcoded owner/repo slug", () => {
    // Regex rather than a string literal: biome's noTemplateCurlyInString
    // flags a bare "${{ ... }}" inside quotes.
    expect(workflow).toMatch(/\$\{\{\s*github\.repository\s*\}\}/);
  });

  it("hardcodes neither the old nor the current repo slug", () => {
    // The release workflow's Sigstore identity regexp is a deliberate
    // exception (it pins WHICH identity we trust). A rollback lever has no
    // such need, so any literal slug here is a rename trap.
    expect(workflow).not.toMatch(/schmug\/dmarcheck/);
    expect(workflow).not.toMatch(/schmug\/dmarc\.mx/);
  });
});

describe("rollback workflow — supply chain", () => {
  it("pins every action by full 40-character commit SHA", () => {
    // Steps are list items, so the line reads "- uses: owner/repo@sha".
    const uses = lines
      .map((l) => l.trim().replace(/^-\s*/, ""))
      .filter((l) => l.startsWith("uses:"))
      .map((l) => l.replace(/^uses:\s*/, ""));

    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) {
      expect(action).toMatch(/@[0-9a-f]{40}(\s|$)/);
    }
  });

  it("declares an explicit least-privilege top-level permissions block", () => {
    expect(workflow).toMatch(/^permissions:\n {2}contents: read$/m);
  });
});

describe("rollback workflow — operator safety", () => {
  it("defaults the dispatch to the read-only inspect action", () => {
    // A rollback form that defaults to a mutating action is one mis-click from
    // shifting production traffic. `inspect` must be the default choice.
    const actionInput = workflow.slice(workflow.indexOf("      action:"));
    const defaultLine = actionInput.match(/default:\s*(\S+)/);
    expect(defaultLine?.[1]).toBe("inspect");
  });

  it("passes --message to wrangler rollback so it never blocks on a TTY prompt", () => {
    // `wrangler rollback` prompts interactively unless --message is supplied.
    // Without it the job hangs until the job timeout, mid-incident.
    expect(workflow).toMatch(
      /wrangler rollback[^\n]*--message|--message[^\n]*\n[^\n]*ROLLBACK/,
    );
  });
});
