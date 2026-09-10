import { describe, it, expect } from "vitest";
import { CONFIG } from "../config.js";
import { parseClosesIssue, isProvenanceTrusted, closesIssueRefs } from "../gate-core.js";
import { touchesRiskPath, withinSizeEnvelope, scopeDrift } from "../gate-core.js";
import { evaluateGate, type GateInput } from "../gate-core.js";
import { evaluateProvenanceOnly } from "../gate-core.js";

describe("CONFIG", () => {
  it("only allowlists the repo owner", () => {
    expect(CONFIG.allowlistAuthors).toEqual(["schmug"]);
  });
  it("uses the higher-throughput envelope", () => {
    expect(CONFIG.size.maxChangedLines).toBe(250);
    expect(CONFIG.size.maxChangedFiles).toBe(8);
    expect(CONFIG.implementerBatch).toBe(6);
  });
  it("has a non-empty risk-path denylist and the four labels", () => {
    expect(CONFIG.riskPathDenylist.length).toBeGreaterThan(5);
    expect(CONFIG.labels).toMatchObject({
      specApproved: "spec-approved",
      autoImpl: "auto-impl",
      needsYou: "needs-you",
      implBlocked: "impl-blocked",
    });
  });
  it("knows dmarcheck is main-flow and donthype-me is dev-flow", () => {
    expect(CONFIG.baseBranchByRepo["dmarcheck"]).toBe("main");
    expect(CONFIG.baseBranchByRepo["donthype-me"]).toBe("dev");
  });
});

describe("parseClosesIssue", () => {
  it("extracts the issue number from a Closes line", () => {
    expect(parseClosesIssue("Adds X.\n\nCloses #42")).toBe(42);
  });
  it("is case-insensitive", () => {
    expect(parseClosesIssue("closes #7")).toBe(7);
  });
  it("returns null when absent", () => {
    expect(parseClosesIssue("no link here")).toBeNull();
  });
});

describe("isProvenanceTrusted", () => {
  const cfg = CONFIG;
  it("trusts allowlisted author WITH spec-approved label", () => {
    expect(isProvenanceTrusted({ number: 1, author: "schmug", labels: ["spec-approved"], filePointers: [] }, cfg)).toBe(true);
  });
  it("rejects a stranger even if labelled", () => {
    expect(isProvenanceTrusted({ number: 1, author: "drive-by", labels: ["spec-approved"], filePointers: [] }, cfg)).toBe(false);
  });
  it("rejects allowlisted author WITHOUT the label", () => {
    expect(isProvenanceTrusted({ number: 1, author: "schmug", labels: [], filePointers: [] }, cfg)).toBe(false);
  });
  it("rejects a null issue (fail-closed)", () => {
    expect(isProvenanceTrusted(null, cfg)).toBe(false);
  });
});

describe("touchesRiskPath", () => {
  it("flags a workflow file", () => {
    expect(touchesRiskPath([".github/workflows/ci.yml"], CONFIG.riskPathDenylist))
      .toEqual([".github/workflows/ci.yml"]);
  });
  it("flags an mta-sts source file", () => {
    expect(touchesRiskPath(["src/mta-sts-fetch.ts"], CONFIG.riskPathDenylist))
      .toEqual(["src/mta-sts-fetch.ts"]);
  });
  it("passes an ordinary source file", () => {
    expect(touchesRiskPath(["src/analyzers/spf.ts"], CONFIG.riskPathDenylist)).toEqual([]);
  });
});

describe("withinSizeEnvelope", () => {
  const base = { number: 1, body: "", changedFiles: ["a.ts"], ciAllGreen: true };
  it("accepts a small diff", () => {
    expect(withinSizeEnvelope({ ...base, additions: 100, deletions: 40 }, CONFIG)).toBe(true);
  });
  it("rejects too many lines", () => {
    expect(withinSizeEnvelope({ ...base, additions: 300, deletions: 0 }, CONFIG)).toBe(false);
  });
  it("rejects too many files", () => {
    expect(withinSizeEnvelope(
      { ...base, additions: 10, deletions: 0, changedFiles: Array(9).fill("x.ts") }, CONFIG)).toBe(false);
  });
});

describe("scopeDrift", () => {
  it("returns files outside declared pointers", () => {
    expect(scopeDrift(["src/a.ts", "src/b.ts"], ["src/a.ts"])).toEqual(["src/b.ts"]);
  });
  it("treats empty pointers as total drift (fail-closed)", () => {
    expect(scopeDrift(["src/a.ts"], [])).toEqual(["src/a.ts"]);
  });
  it("matches glob pointers", () => {
    expect(scopeDrift(["src/analyzers/spf.ts"], ["src/analyzers/**"])).toEqual([]);
  });
});

function baseInput(): GateInput {
  return {
    cfg: CONFIG,
    issue: { number: 42, author: "schmug", labels: ["spec-approved"], filePointers: ["src/analyzers/**"] },
    pr: {
      number: 100,
      body: "Implements analyzer tweak.\n\nCloses #42",
      changedFiles: ["src/analyzers/spf.ts"],
      additions: 30, deletions: 5, ciAllGreen: true,
    },
  };
}

describe("evaluateGate", () => {
  it("PASSES a trusted, small, in-scope, green PR", () => {
    const v = evaluateGate(baseInput());
    expect(v.pass).toBe(true);
    expect(v.reasons).toEqual([]);
  });
  it("FAILS a stranger's issue (provenance)", () => {
    const i = baseInput(); i.issue!.author = "drive-by";
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/not on allowlist/);
  });
  it("FAILS when no Closes link", () => {
    const i = baseInput(); i.pr.body = "no link";
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/Closes/);
  });
  it("FAILS when linked issue is missing (fail-closed)", () => {
    const i = baseInput(); i.issue = null;
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
  });
  it("FAILS on risk path even if everything else is fine", () => {
    const i = baseInput(); i.pr.changedFiles = [".github/workflows/ci.yml"]; i.issue!.filePointers = [".github/workflows/**"];
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/risk-path/);
  });
  it("FAILS on oversize diff", () => {
    const i = baseInput(); i.pr.additions = 500;
    expect(evaluateGate(i).pass).toBe(false);
  });
  it("FAILS on scope drift", () => {
    const i = baseInput(); i.pr.changedFiles = ["src/unrelated.ts"];
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/scope drift/);
  });
  it("FAILS on red CI", () => {
    const i = baseInput(); i.pr.ciAllGreen = false;
    expect(evaluateGate(i).pass).toBe(false);
  });
  it("FAILS when PR closes a different issue than evaluated", () => {
    const i = baseInput(); i.pr.body = "Closes #999";
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/#999/);
  });
});

describe("parseClosesIssue / closesIssueRefs hardening", () => {
  it("ignores Closes inside HTML comments", () => {
    expect(parseClosesIssue("<!-- Closes #999 -->\n\nCloses #42")).toBe(42);
  });
  it("ignores Closes inside blockquotes", () => {
    expect(parseClosesIssue("> Closes #999\n\nCloses #42")).toBe(42);
  });
  it("fails closed on multiple distinct refs", () => {
    expect(parseClosesIssue("Closes #42\nCloses #999")).toBeNull();
  });
  it("collapses duplicate identical refs to one", () => {
    expect(parseClosesIssue("Closes #42 and again Closes #42")).toBe(42);
    expect(closesIssueRefs("Closes #42 Closes #42")).toEqual([42]);
  });
  it("ignores Closes inside inline code span", () => {
    expect(parseClosesIssue("Example: `Closes #999`\n\nCloses #42")).toBe(42);
  });
  it("ignores Closes inside fenced code block", () => {
    expect(parseClosesIssue("```\nCloses #999\n```\n\nCloses #42")).toBe(42);
  });
  it("ignores Closes inside unterminated HTML comment (strips to end of line)", () => {
    expect(parseClosesIssue("<!-- Closes #999\n\nCloses #42")).toBe(42);
  });
});

describe("evaluateGate ambiguity + provenance source-of-truth", () => {
  function baseInput2() {
    return {
      cfg: CONFIG,
      issue: { number: 42, author: "schmug", labels: ["spec-approved"], filePointers: ["src/analyzers/**"] },
      pr: { number: 100, body: "Implements analyzer tweak.\n\nCloses #42",
            changedFiles: ["src/analyzers/spf.ts"], additions: 30, deletions: 5, ciAllGreen: true },
    };
  }
  it("FAILS with an ambiguous reason on multiple Closes refs", () => {
    const i = baseInput2(); i.pr.body = "Closes #42\nCloses #999";
    const v = evaluateGate(i);
    expect(v.pass).toBe(false);
    expect(v.reasons.join(" ")).toMatch(/ambiguous Closes refs/);
  });
});

describe("evaluateProvenanceOnly (#705, PR provenance required check)", () => {
  it("PASSES a trusted author's linked issue", () => {
    const issue = { number: 42, author: "schmug", labels: [], filePointers: [] };
    const v = evaluateProvenanceOnly("Fixes the thing.\n\nCloses #42", issue, CONFIG);
    expect(v).toEqual({ pass: true, reason: null });
  });
  it("PASSES a trusted author's issue even without the spec-approved label (Condition 1 only)", () => {
    const issue = { number: 42, author: "schmug", labels: [], filePointers: [] };
    expect(evaluateProvenanceOnly("Closes #42", issue, CONFIG).pass).toBe(true);
  });
  it("PASSES a PR with no linked issue (linkage is Condition 3, not this check)", () => {
    expect(evaluateProvenanceOnly("no link here", null, CONFIG)).toEqual({ pass: true, reason: null });
  });
  it("PASSES a PR with ambiguous Closes refs (linkage stays routine-side)", () => {
    expect(evaluateProvenanceOnly("Closes #42\nCloses #999", null, CONFIG).pass).toBe(true);
  });
  it("FAILS a stranger's issue", () => {
    const issue = { number: 42, author: "drive-by", labels: [], filePointers: [] };
    const v = evaluateProvenanceOnly("Closes #42", issue, CONFIG);
    expect(v.pass).toBe(false);
    expect(v.reason).toMatch(/not on allowlist/);
  });
  it("FAILS closed when the linked issue is unreadable", () => {
    const v = evaluateProvenanceOnly("Closes #42", null, CONFIG);
    expect(v.pass).toBe(false);
    expect(v.reason).toMatch(/unreadable/);
  });
  it("FAILS when the fetched issue doesn't match the parsed Closes number", () => {
    const issue = { number: 999, author: "schmug", labels: [], filePointers: [] };
    const v = evaluateProvenanceOnly("Closes #42", issue, CONFIG);
    expect(v.pass).toBe(false);
    expect(v.reason).toMatch(/#42/);
  });
});

describe("gate self-modification is denylisted", () => {
  it("blocks changes to the gate core", () => {
    expect(touchesRiskPath(["scripts/routine-gate/gate-core.ts"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("blocks changes to the gate config", () => {
    expect(touchesRiskPath(["scripts/routine-gate/config.ts"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("blocks changes to pipeline scripts/prompts", () => {
    expect(touchesRiskPath(["scripts/routine-pipeline/routine-reviewer.md"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("still allows ordinary source", () => {
    expect(touchesRiskPath(["src/analyzers/spf.ts"], CONFIG.riskPathDenylist).length).toBe(0);
  });
});

describe("denylist hardening + normalization", () => {
  it("blocks nested wrangler.toml", () => {
    expect(touchesRiskPath(["packages/x/wrangler.toml"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("blocks nested .github/workflows", () => {
    expect(touchesRiskPath(["apps/web/.github/workflows/ci.yml"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("blocks an authz directory file", () => {
    expect(touchesRiskPath(["src/authz/policy.ts"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("blocks capitalized AuthGuard via case-insensitive denylist", () => {
    expect(touchesRiskPath(["src/AuthGuard.ts"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("blocks reversed access*cloudflare order", () => {
    expect(touchesRiskPath(["src/access-cloudflare.ts"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("normalizes ./-prefixed risky paths", () => {
    expect(touchesRiskPath(["./src/auth/login.ts"], CONFIG.riskPathDenylist).length).toBe(1);
  });
  it("scopeDrift normalizes ./-prefixed in-scope paths", () => {
    expect(scopeDrift(["./src/analyzers/spf.ts"], ["src/analyzers/**"])).toEqual([]);
  });
  it("size envelope exact boundary passes (<=)", () => {
    const pr = { number: 1, body: "", changedFiles: Array(8).fill("a.ts"), additions: 200, deletions: 50, ciAllGreen: true };
    expect(withinSizeEnvelope(pr, CONFIG)).toBe(true);
  });
});
