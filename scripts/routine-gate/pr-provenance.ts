#!/usr/bin/env -S npx tsx
// Server-side enforcement of routine-gate Condition 1 ONLY (#705): the
// "PR provenance" required check. Every other gate.ts condition (spec-approved
// label, size envelope, scope-fit, risk paths, CI) stays a routine-side
// auto-merge decision — see CLAUDE.md's routine-gate section.
//
// Usage: npx tsx scripts/routine-gate/pr-provenance.ts --repo owner/name --pr 123
import { CONFIG } from "./config.js";
import { evaluateProvenanceOnly, parseClosesIssue } from "./gate-core.js";
import { fetchPr, fetchIssue } from "./github.js";

function arg(flag: string): string {
  const i = process.argv.indexOf(flag);
  if (i === -1 || i + 1 >= process.argv.length) {
    console.error(`missing ${flag}`);
    process.exit(1);
  }
  return process.argv[i + 1];
}

const repo = arg("--repo");
const prNum = Number(arg("--pr"));

// Fail closed on a malformed allowlist rather than let `includes` silently
// reject (or an unguarded throw pass through as an ambiguous failure).
if (
  !Array.isArray(CONFIG.allowlistAuthors) ||
  CONFIG.allowlistAuthors.length === 0 ||
  !CONFIG.allowlistAuthors.every((a) => typeof a === "string" && a.length > 0)
) {
  console.error("scripts/routine-gate/config.ts: allowlistAuthors is unparseable — failing closed");
  process.exit(1);
}

const pr = fetchPr(repo, prNum);
const closes = parseClosesIssue(pr.body);
const issue = closes !== null ? fetchIssue(repo, closes) : null;

const verdict = evaluateProvenanceOnly(pr.body, issue, CONFIG);

console.log(JSON.stringify({ repo, pr: prNum, ...verdict }, null, 2));
process.exit(verdict.pass ? 0 : 1);
