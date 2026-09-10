import { minimatch } from "minimatch";
import type { CONFIG as CONFIG_T } from "./config.js";

export interface IssueInfo {
  number: number;
  author: string;
  labels: string[];
  filePointers: string[]; // glob-ish paths the issue declared as in-scope
}

export interface PrInfo {
  number: number;
  body: string;
  changedFiles: string[];
  additions: number;
  deletions: number;
  ciAllGreen: boolean;
}

type Cfg = typeof CONFIG_T;

// Strip code spans, HTML comments, and markdown blockquote lines, then collect DISTINCT issue refs.
export function closesIssueRefs(body: string): number[] {
  const cleaned = body
    .replace(/```[\s\S]*?```/g, " ")           // drop fenced code blocks
    .replace(/`[^`\n]+`/g, " ")               // drop inline code spans
    .replace(/<!--[\s\S]*?-->/g, " ")          // drop complete HTML comments
    .replace(/<!--[^\n]*/g, " ")              // drop unterminated HTML comment starts (to end of line)
    .split("\n")
    .filter((line) => !/^\s*>/.test(line))      // drop blockquote lines
    .join("\n");
  const refs = new Set<number>();
  for (const m of cleaned.matchAll(/\bcloses\s+#(\d+)\b/gi)) {
    refs.add(Number(m[1]));
  }
  return [...refs];
}

// Fail-closed: exactly one distinct ref => that number; zero OR ambiguous(>1) => null.
export function parseClosesIssue(body: string): number | null {
  const refs = closesIssueRefs(body);
  return refs.length === 1 ? refs[0] : null;
}

export function isProvenanceTrusted(issue: IssueInfo | null, cfg: Cfg): boolean {
  if (!issue) return false; // fail-closed
  return (
    cfg.allowlistAuthors.includes(issue.author) &&
    issue.labels.includes(cfg.labels.specApproved)
  );
}

export interface ProvenanceVerdict {
  pass: boolean;
  reason: string | null;
}

// Server-side backstop for routine-gate Condition 1 ONLY (#705): is the linked
// issue's author on the allowlist? A PR linking no issue (or an ambiguous
// `Closes` set) passes here — linkage itself is Condition 3, which stays a
// routine-side auto-merge decision, not this check's job.
export function evaluateProvenanceOnly(
  prBody: string,
  issue: IssueInfo | null,
  cfg: Cfg,
): ProvenanceVerdict {
  const closes = parseClosesIssue(prBody);
  if (closes === null) return { pass: true, reason: null };
  if (!issue) return { pass: false, reason: `issue #${closes} unreadable (fail-closed)` };
  if (issue.number !== closes) {
    return { pass: false, reason: `PR closes #${closes} but evaluated issue is #${issue.number}` };
  }
  if (!cfg.allowlistAuthors.includes(issue.author)) {
    return { pass: false, reason: `issue #${closes} author @${issue.author} not on allowlist` };
  }
  return { pass: true, reason: null };
}

function normalizePath(p: string): string {
  return p.replace(/^(\.\/)+/, "").replace(/\/{2,}/g, "/");
}

export function touchesRiskPath(files: string[], denylist: string[]): string[] {
  return files.filter((f) => {
    const nf = normalizePath(f);
    return denylist.some((p) => minimatch(nf, p, { dot: true, nocase: true }));
  });
}

export function withinSizeEnvelope(pr: PrInfo, cfg: Cfg): boolean {
  return (
    pr.additions + pr.deletions <= cfg.size.maxChangedLines &&
    pr.changedFiles.length <= cfg.size.maxChangedFiles
  );
}

// Returns changed files NOT covered by the issue's declared pointers.
// Empty pointers => every file is drift (fail-closed: no declared scope = not safe).
export function scopeDrift(changedFiles: string[], pointers: string[]): string[] {
  if (pointers.length === 0) return [...changedFiles];
  return changedFiles.filter((f) => {
    const nf = normalizePath(f);
    return !pointers.some((p) => minimatch(nf, p, { dot: true }));
  });
}

export interface GateInput {
  cfg: Cfg;
  issue: IssueInfo | null;
  pr: PrInfo;
}

export interface GateVerdict {
  pass: boolean;
  reasons: string[]; // empty iff pass === true
}

export function evaluateGate(input: GateInput): GateVerdict {
  const { cfg, issue, pr } = input;
  const reasons: string[] = [];

  // Condition 3: linkage (fail-closed on zero OR ambiguous Closes refs)
  const refs = closesIssueRefs(pr.body);
  const closes = refs.length === 1 ? refs[0] : null;
  if (refs.length === 0) reasons.push("PR body has no `Closes #n` link");
  else if (refs.length > 1) reasons.push(`ambiguous Closes refs (#${refs.join(", #")}) — fail-closed`);

  // Conditions 1 + 2: provenance + intent token
  if (!issue) {
    reasons.push("linked issue not found / unreadable (fail-closed)");
  } else {
    if (closes !== null && closes !== issue.number) {
      reasons.push(`PR closes #${closes} but evaluated issue is #${issue.number}`);
    }
    if (!isProvenanceTrusted(issue, cfg)) {
      if (!cfg.allowlistAuthors.includes(issue.author)) {
        reasons.push(`issue author @${issue.author} not on allowlist`);
      }
      if (!issue.labels.includes(cfg.labels.specApproved)) {
        reasons.push(`issue #${issue.number} missing "${cfg.labels.specApproved}" label`);
      }
    }
  }

  // Condition 4: risk-path denylist
  const risky = touchesRiskPath(pr.changedFiles, cfg.riskPathDenylist);
  if (risky.length) reasons.push(`touches risk-path(s): ${risky.join(", ")}`);

  // Condition 5: size envelope
  if (!withinSizeEnvelope(pr, cfg)) {
    reasons.push(
      `exceeds size envelope (${pr.additions + pr.deletions} lines / ${pr.changedFiles.length} files; ` +
        `max ${cfg.size.maxChangedLines}/${cfg.size.maxChangedFiles})`,
    );
  }

  // Condition 6a: scope-fit
  const drift = issue ? scopeDrift(pr.changedFiles, issue.filePointers) : [...pr.changedFiles];
  if (drift.length) reasons.push(`scope drift outside declared pointers: ${drift.join(", ")}`);

  // Condition 6b: CI
  if (!pr.ciAllGreen) reasons.push("CI not green");

  return { pass: reasons.length === 0, reasons };
}
