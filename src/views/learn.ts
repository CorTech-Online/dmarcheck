import { COMMON_SELECTORS } from "../analyzers/dkim.js";
import { LEARN_ANCHORS } from "../shared/learn-anchors.js";
import { esc, generateCreature } from "./components.js";
import { page, SITE_ORIGIN } from "./html.js";

// Learn pages are tutorial/deep-dive content — distinct in shape from the
// /scoring page which owns the FAQPage schema. These pages emit TechArticle +
// BreadcrumbList so search engines treat them as a separate lane. Do not copy
// prose verbatim from SCORING_JSON_LD or the /scoring page — paraphrase.

// Original publication date of the learn lane. Stable — never bump this on
// edits; search engines treat a moving datePublished as freshness gaming.
const LEARN_PUBLISHED = "2026-04-11";

// Bump when materially editing any learn page prose. It lives here rather than
// per-function so all pages stay in sync by default. Only this constant moves
// on edits; LEARN_PUBLISHED stays fixed.
export const LEARN_MODIFIED = "2026-06-12";

interface LearnPageOptions {
  protocol: string; // "DMARC"
  slug: string; // "dmarc" — matches the route
  title: string; // <title> / og:title
  headline: string; // TechArticle.headline (also rendered as the H1)
  description: string; // meta description + og:description
  body: string; // inner HTML for <main>
}

function learnJsonLd(opts: {
  protocol: string;
  slug: string;
  headline: string;
  description: string;
}): string {
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        headline: opts.headline,
        description: opts.description,
        datePublished: LEARN_PUBLISHED,
        dateModified: LEARN_MODIFIED,
        author: {
          "@type": "Organization",
          name: "dmarcheck",
          url: `${SITE_ORIGIN}/`,
        },
        publisher: {
          "@type": "Organization",
          name: "dmarcheck",
          url: `${SITE_ORIGIN}/`,
          logo: {
            "@type": "ImageObject",
            url: `${SITE_ORIGIN}/logo.svg`,
          },
        },
        image: `${SITE_ORIGIN}/og-image.png`,
        mainEntityOfPage: `${SITE_ORIGIN}/learn/${opts.slug}`,
      },
      {
        "@type": "BreadcrumbList",
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: "dmarcheck",
            item: `${SITE_ORIGIN}/`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: "Learn",
            item: `${SITE_ORIGIN}/learn`,
          },
          {
            "@type": "ListItem",
            position: 3,
            name: opts.protocol,
            item: `${SITE_ORIGIN}/learn/${opts.slug}`,
          },
        ],
      },
    ],
  });
}

export const LEARN_SIBLINGS: Array<{
  slug: string;
  protocol: string;
  blurb: string;
}> = [
  {
    slug: "dmarc",
    protocol: "DMARC",
    blurb: "Policy records, alignment, and reporting.",
  },
  {
    slug: "spf",
    protocol: "SPF",
    blurb: "Authorized senders and the 10-lookup budget.",
  },
  {
    slug: "dkim",
    protocol: "DKIM",
    blurb: "Signing keys, selectors, and rotation.",
  },
  {
    slug: "bimi",
    protocol: "BIMI",
    blurb: "Inbox logos and VMC/CMC certification.",
  },
  {
    slug: "mta-sts",
    protocol: "MTA-STS",
    blurb: "TLS enforcement for inbound mail.",
  },
  {
    slug: "security-txt",
    protocol: "security.txt",
    blurb: "Machine-readable security disclosure policies.",
  },
  {
    slug: "tls-rpt",
    protocol: "TLS-RPT",
    blurb: "SMTP TLS failure reporting via DNS.",
  },
  {
    slug: "dnssec",
    protocol: "DNSSEC",
    blurb: "Signed DNS zones and the chain of trust.",
  },
  {
    slug: "dane",
    protocol: "DANE/TLSA",
    blurb: "TLSA records pinning MX certificates over DNSSEC.",
  },
];

function siblingLinks(currentSlug: string): string {
  const items = LEARN_SIBLINGS.filter((s) => s.slug !== currentSlug)
    .map(
      (s) =>
        `<li><a href="/learn/${s.slug}"><strong>${s.protocol}</strong> &mdash; ${s.blurb}</a></li>`,
    )
    .join("");
  return `<ul class="learn-siblings">${items}</ul>`;
}

function learnCta(placeholder: string): string {
  return `<div class="bd-card">
    <div class="bd-card-title">Check your domain</div>
    <div class="bd-card-body">
      <form action="/check" method="GET" class="learn-cta-form">
        <div class="search-box">
          <input type="text" name="domain" placeholder="${esc(placeholder)}" aria-label="Enter a domain" autocapitalize="none" autocorrect="off" spellcheck="false" required>
          <button type="submit" data-loading-text="Scanning...">Scan</button>
        </div>
      </form>
    </div>
  </div>`;
}

const LEARN_FOOTER = `<div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Free and open source &mdash; MIT License
    </a>
  </div>`;

function renderLearnPage(opts: LearnPageOptions): string {
  const jsonLd = learnJsonLd({
    protocol: opts.protocol,
    slug: opts.slug,
    headline: opts.headline,
    description: opts.description,
  });

  const body = `<main class="breakdown learn">
  <nav class="report-nav" aria-label="Breadcrumb">
    <a href="/">${generateCreature("sm")} Home</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <a href="/learn">Learn</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <span class="breadcrumb-current">${esc(opts.protocol)}</span>
  </nav>
  <h1 class="rubric-title">${esc(opts.headline)}</h1>
  ${opts.body}
  <div class="bd-card">
    <div class="bd-card-title">Keep learning</div>
    <div class="bd-card-body">
      ${siblingLinks(opts.slug)}
      <p class="tier-text" style="margin-top:12px">Want the full grading rubric? See <a href="/scoring">how dmarcheck calculates your score</a>.</p>
    </div>
  </div>
  ${LEARN_FOOTER}
</main>`;

  return page({
    title: opts.title,
    path: `/learn/${opts.slug}`,
    description: opts.description,
    jsonLd,
    body,
  });
}

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

export function renderLearnHub(): string {
  const hubJsonLd = JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "CollectionPage",
        name: "Learn email authentication — dmarcheck",
        description:
          "Plain-English guides to DMARC, SPF, DKIM, BIMI, MTA-STS, security.txt, TLS-RPT, DNSSEC, and DANE — what they do, how to read each record, and how to fix the most common misconfigurations.",
        url: `${SITE_ORIGIN}/learn`,
        mainEntity: {
          "@type": "ItemList",
          itemListElement: LEARN_SIBLINGS.map((s, i) => ({
            "@type": "ListItem",
            position: i + 1,
            url: `${SITE_ORIGIN}/learn/${s.slug}`,
            name: s.protocol,
          })),
        },
      },
      {
        "@type": "BreadcrumbList",
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: "dmarcheck",
            item: `${SITE_ORIGIN}/`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: "Learn",
            item: `${SITE_ORIGIN}/learn`,
          },
        ],
      },
    ],
  });

  const cards = LEARN_SIBLINGS.map(
    (s) =>
      `<li><a href="/learn/${s.slug}" class="learn-hub-card">
        <h2>${s.protocol}</h2>
        <p>${s.blurb}</p>
      </a></li>`,
  ).join("");

  const body = `<main class="breakdown learn">
  <nav class="report-nav" aria-label="Breadcrumb">
    <a href="/">${generateCreature("sm")} Home</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <span class="breadcrumb-current">Learn</span>
  </nav>
  <h1 class="rubric-title">Learn email authentication</h1>
  <p class="rubric-intro">${LEARN_SIBLINGS.length} short guides to the DNS records dmarcheck scans. Each page walks through how the record works, how to read a real example, and how to fix the misconfigurations that lower your grade.</p>
  <ul class="learn-hub-grid">${cards}</ul>
  ${learnCta("Enter a domain to scan")}
  ${LEARN_FOOTER}
</main>`;

  return page({
    title: "Learn email authentication — dmarcheck",
    path: "/learn",
    description:
      "Plain-English guides to DMARC, SPF, DKIM, BIMI, MTA-STS, security.txt, TLS-RPT, DNSSEC, and DANE. Read each DNS record, understand the tags, and fix the common misconfigurations.",
    jsonLd: hubJsonLd,
    body,
  });
}

// ---------------------------------------------------------------------------
// DMARC
// ---------------------------------------------------------------------------

export function renderLearnDmarc(): string {
  const body = `
  <p class="rubric-intro">DMARC is the DNS TXT record at <code>_dmarc.yourdomain.com</code> that ties SPF and DKIM results together and tells receiving mail servers what to do with messages that fail authentication. It is the single most important record for protecting your domain from spoofing.</p>

  <div class="bd-card">
    <div class="bd-card-title">How to read a DMARC record</div>
    <div class="bd-card-body">
      <p class="tier-text">A DMARC record is a list of <code>tag=value</code> pairs separated by semicolons. Here is a typical strict policy:</p>
      <pre class="learn-example"><code>v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; adkim=s; aspf=s</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>v</code></dt><dd>Version. Must be <code>DMARC1</code> or the record is ignored.</dd></div>
        <div><dt><code>p</code></dt><dd>Policy. <code>none</code> is monitor-only, <code>quarantine</code> routes failing mail to spam, <code>reject</code> blocks it outright.</dd></div>
        <div><dt><code>sp</code></dt><dd>Subdomain policy. Overrides <code>p</code> for subdomains; if omitted, subdomains inherit <code>p</code>.</dd></div>
        <div><dt><code>rua</code></dt><dd>Aggregate report URI. Where receivers send daily XML reports so you can see who is sending on your behalf.</dd></div>
        <div><dt><code>ruf</code></dt><dd>Forensic report URI. Where to send per-failure reports (rarely honored by receivers today).</dd></div>
        <div><dt><code>pct</code></dt><dd>Percentage of messages the policy applies to. Anything below 100 is a partial rollout.</dd></div>
        <div><dt><code>adkim</code> / <code>aspf</code></dt><dd>Alignment mode. Strict (<code>s</code>) requires an exact match between the From domain and the signing/authenticated domain; relaxed (<code>r</code>) allows organizational-domain matching.</dd></div>
        <div><dt><code>fo</code></dt><dd>Failure-report options. Controls when forensic reports are generated.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>No record at all.</strong> Without <code>_dmarc.yourdomain.com</code>, receivers have no policy to apply and spoofers have a free pass. This is an automatic F in dmarcheck.</li>
        <li id="${esc(LEARN_ANCHORS.dmarcPolicyNone.id)}"><strong><code>p=none</code> left in place forever.</strong> Monitor mode is useful for a few weeks of triage, but leaving it there means you are only watching the fire, not putting it out. dmarcheck treats <code>p=none</code> as a failing grade because it provides no real protection.</li>
        <li><strong>Missing <code>rua</code>.</strong> Without aggregate reports you cannot see which third-party senders are failing authentication, which makes the move from <code>none</code> to <code>quarantine</code> or <code>reject</code> a guessing game.</li>
        <li><strong><code>pct</code> below 100.</strong> A partial rollout is fine as a transition, but the unprotected slice is still spoofable. Increase it steadily and delete the tag once you are at 100.</li>
        <li><strong>Invalid tag at <code>_dmarc</code>.</strong> A TXT record exists but does not start with <code>v=DMARC1</code>. This usually means a wildcard DNS entry is returning the wrong value — receivers will ignore it.</li>
        <li><strong>Subdomain blind spot.</strong> Parent policy is strict but subdomains have no <code>sp</code> override and no record of their own, so attackers spoof <code>billing.yourdomain.com</code> instead of <code>yourdomain.com</code>.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Publish <code>v=DMARC1; p=none; rua=mailto:you@yourdomain.com</code> and watch reports for two to four weeks.</li>
        <li>Fix the senders you see failing in the reports — usually marketing tools, ticketing systems, or forgotten forwarders.</li>
        <li>Move to <code>p=quarantine; pct=10</code>, then raise <code>pct</code> each week while watching for collateral damage.</li>
        <li>Once quarantine is clean at 100, switch to <code>p=reject</code> and delete <code>pct</code>.</li>
        <li>Add <code>sp=reject</code> so subdomains inherit the protection, and keep the <code>rua</code> tag in place permanently.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for DMARC")}
  `;

  return renderLearnPage({
    protocol: "DMARC",
    slug: "dmarc",
    title:
      "What is DMARC? Policy records, alignment, and reporting — dmarcheck",
    headline: "What is DMARC? Policy records, alignment, and reporting",
    description:
      "A plain-English guide to DMARC: how the _dmarc DNS TXT record works, what each tag means, the common misconfigurations, and the safe rollout path from p=none to p=reject.",
    body,
  });
}

// ---------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------

export function renderLearnSpf(): string {
  const body = `
  <p class="rubric-intro">SPF is a DNS TXT record on your root domain that lists the IP addresses and hostnames allowed to send mail as you. Receivers compare the envelope sender against the list and either accept, soft-fail, or reject depending on how your record ends.</p>

  <div class="bd-card">
    <div class="bd-card-title">How to read an SPF record</div>
    <div class="bd-card-body">
      <p class="tier-text">An SPF record starts with <code>v=spf1</code>, lists mechanisms, and ends with an <code>all</code> qualifier:</p>
      <pre class="learn-example"><code>v=spf1 ip4:198.51.100.10 include:_spf.google.com include:spf.protection.outlook.com -all</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>ip4</code> / <code>ip6</code></dt><dd>Literal IP addresses or CIDR ranges authorized to send. Cheap — zero DNS lookups.</dd></div>
        <div><dt><code>a</code> / <code>mx</code></dt><dd>Authorize hosts whose A or MX records match. Each one counts as a DNS lookup.</dd></div>
        <div><dt><code>include</code></dt><dd>Delegate to another domain's SPF record (e.g. your email provider). One lookup per include, plus whatever lookups that record chains into.</dd></div>
        <div><dt><code>redirect</code></dt><dd>Hand off the entire policy to another domain. Counts as one lookup and replaces the rest of your record.</dd></div>
        <div><dt><code>-all</code></dt><dd>Hardfail. Anything not matched above should be rejected.</dd></div>
        <div><dt><code>~all</code></dt><dd>Softfail. Anything not matched is suspicious but not blocked — useful during rollout.</dd></div>
        <div><dt><code>?all</code></dt><dd>Neutral. No opinion. Provides essentially no protection.</dd></div>
        <div><dt><code>+all</code></dt><dd>Pass everything. <strong>Never use this</strong>; it authorizes every sender on the internet.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li id="${esc(LEARN_ANCHORS.spfLookupLimit.id)}"><strong>Exceeding the 10 DNS lookup limit (RFC 7208 §4.6.4).</strong> <code>include</code>, <code>a</code>, <code>mx</code>, <code>exists</code>, and <code>redirect</code> each cost a lookup, and every include recursively spends lookups too. Once you cross 10, receivers return <code>permerror</code> and the entire policy is ignored. dmarcheck counts lookups recursively and flags this as a hard failure.</li>
        <li><strong>Circular includes.</strong> Two SPF records including each other produce a permerror. Usually happens after a migration leaves stale entries.</li>
        <li><strong>Using <code>+all</code>.</strong> Often a copy/paste mistake. It allows any host on the internet to pass SPF for your domain, which breaks DMARC alignment and actively harms you.</li>
        <li><strong>Using <code>?all</code> (neutral).</strong> Provides no guidance to receivers. Replace with <code>~all</code> or <code>-all</code>.</li>
        <li><strong>Leaving the deprecated <code>ptr</code> mechanism in place.</strong> RFC 7208 recommends against it: it is slow, expensive for receivers, and unreliable.</li>
        <li><strong>Forgetting a sender.</strong> A new marketing tool or transactional mail provider goes live, the SPF record is not updated, and their mail starts failing silently once DMARC is enforced. Aggregate (<code>rua</code>) reports catch this.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Scan your domain and note the current lookup count. If you are over 10, the record is broken even if it looks fine.</li>
        <li>Replace heavy <code>include</code>s you do not need. Consolidate third-party senders, or use an SPF flattening service if your vendors insist on deep chains.</li>
        <li>Prefer <code>ip4</code>/<code>ip6</code> literals for infrastructure you control — they are free, lookup-wise.</li>
        <li>End with <code>-all</code> once you are confident, or <code>~all</code> if you still have stragglers. Both are treated equally when DMARC is enforced, per M3AAWG guidance.</li>
        <li>Keep the lookup count under 6 to earn the SPF bonus modifier in dmarcheck.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for SPF")}
  `;

  return renderLearnPage({
    protocol: "SPF",
    slug: "spf",
    title: "What is SPF? The 10 DNS lookup limit, explained — dmarcheck",
    headline: "What is SPF? Mechanisms, the 10-lookup limit, and fallouts",
    description:
      "A plain-English guide to SPF: how the v=spf1 record works, why the 10 DNS lookup limit matters, and how to fix permerrors, +all mistakes, and deprecated ptr mechanisms.",
    body,
  });
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

export function renderLearnDkim(): string {
  const body = `
  <p class="rubric-intro">DKIM attaches a cryptographic signature to every outgoing message using a private key that only your mail server holds. The matching public key lives in DNS under a named selector, so receivers can fetch it and verify nothing was altered in transit.</p>

  <div class="bd-card">
    <div class="bd-card-title">How to read a DKIM record</div>
    <div class="bd-card-body">
      <p class="tier-text">DKIM records live at <code>&lt;selector&gt;._domainkey.yourdomain.com</code> as TXT records. A minimal example:</p>
      <pre class="learn-example"><code>v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC...</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>v</code></dt><dd>Version. Must be <code>DKIM1</code>.</dd></div>
        <div><dt><code>k</code></dt><dd>Key type. Defaults to <code>rsa</code>. Ed25519 (<code>k=ed25519</code>) is supported by most major receivers.</dd></div>
        <div><dt><code>p</code></dt><dd>The base64-encoded public key. An empty <code>p=</code> means the key has been revoked.</dd></div>
        <div><dt><code>t</code></dt><dd>Flags. <code>t=y</code> marks the selector as testing-only — receivers are expected to treat failures leniently.</dd></div>
        <div><dt>Selector</dt><dd>An arbitrary label you pick (e.g. <code>google</code>, <code>selector1</code>, <code>s1</code>) that lets you publish multiple keys simultaneously for rotation.</dd></div>
      </dl>
      <p class="tier-text" style="margin-top:12px">dmarcheck automatically probes ${COMMON_SELECTORS.length} common selectors used by major providers (Google Workspace, Microsoft 365, Proton Mail, Fastmail, Zoho, Postmark, Amazon SES, and others), and you can pass a custom selector in the Advanced options on the home page if you use something unusual.</p>
    </div>
  </div>

  <div class="bd-card">
    <h2 class="bd-card-title" id="find-your-selector">How to find your DKIM selector</h2>
    <div class="bd-card-body">
      <p class="tier-text">The selector is not a secret — every signed message announces it. If a vendor doc told you to &ldquo;check your DKIM selector&rdquo; or a scan came back with no selectors found, here is where to look.</p>
      <ol class="learn-steps">
        <li><strong>Read it out of a message you sent.</strong> Open a message from your domain in the receiving mailbox and view the full headers (Gmail: three-dot menu &rarr; &ldquo;Show original&rdquo;; Outlook: &ldquo;View message source&rdquo;). Find the <code>DKIM-Signature</code> header — the <code>s=</code> tag is the selector and <code>d=</code> is the domain it signs for:
        <pre class="learn-example"><code>DKIM-Signature: v=1; a=rsa-sha256; d=yourdomain.com; s=selector1; ...</code></pre>
        Here the selector is <code>selector1</code>, so the public key lives at <code>selector1._domainkey.yourdomain.com</code> — exactly the record dmarcheck looks up.</li>
        <li><strong>Try your provider's documented default.</strong> Google Workspace signs with <code>google</code>, Microsoft 365 rotates between <code>selector1</code> and <code>selector2</code>, Proton Mail uses <code>protonmail</code> (plus <code>protonmail2</code> and <code>protonmail3</code>), Fastmail uses <code>fm1</code> through <code>fm3</code>, and Zoho Mail uses <code>default</code>.</li>
        <li><strong>Or skip the detective work and scan.</strong> dmarcheck probes ${COMMON_SELECTORS.length} common selectors on every scan — the provider defaults above plus the usual names from transactional senders like Postmark, Mandrill, and Amazon SES. If yours is custom, add it under Advanced options on the home page and scan again.</li>
      </ol>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li id="${esc(LEARN_ANCHORS.dkimFindSelector.id)}"><strong>No selector found.</strong> If dmarcheck cannot locate a DKIM record at any of the common selectors, either you have not set DKIM up yet, the selector name is unusual, or the CNAME/TXT record is pointing at the wrong place. Try the Advanced options on the home page with your provider's selector name.</li>
        <li><strong>Weak 1024-bit RSA keys.</strong> Still legal per spec, but industry guidance is 2048 bits or larger. dmarcheck flags any key under 2048 bits and applies a grade penalty.</li>
        <li><strong>Revoked keys (empty <code>p=</code>).</strong> Usually the remnant of a rotation that never cleaned up. The record still resolves, so receivers treat signed mail from that selector as broken.</li>
        <li><strong>Stuck in testing mode.</strong> <code>t=y</code> is useful while you verify a new key, but leaving it in place permanently tells receivers to ignore DKIM failures — effectively disabling the protection.</li>
        <li><strong>Only one selector.</strong> Single-selector setups make rotation disruptive. Publishing a second selector lets you roll keys by changing which one the mail server signs with, with no downtime.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card" id="${esc(LEARN_ANCHORS.dkimKeyRotation.id)}">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Generate or obtain a 2048-bit (or larger) RSA key from your mail provider and publish it as a new selector in DNS.</li>
        <li>Enable signing in your mail platform and verify with a test message — most platforms include a "DKIM status" tool in the admin console.</li>
        <li>Publish a second selector so you can rotate without downtime. Two selectors earns a bonus modifier in dmarcheck.</li>
        <li>Rotate keys at least once a year. Sign with the new selector, leave the old one published for a cool-down period, then remove it.</li>
        <li>If you see a key under 2048 bits in your scan, upgrade it — most providers let you regenerate with a single click.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for DKIM")}
  `;

  return renderLearnPage({
    protocol: "DKIM",
    slug: "dkim",
    title:
      "What is DKIM? Selectors, key rotation, and 2048-bit keys — dmarcheck",
    headline: "What is DKIM? Selectors, key strength, and rotation",
    description:
      "A plain-English guide to DKIM: how to find your DKIM selector from a message header or your provider's default, why 2048-bit keys matter, and how to rotate without downtime.",
    body,
  });
}

// ---------------------------------------------------------------------------
// BIMI
// ---------------------------------------------------------------------------

export function renderLearnBimi(): string {
  const body = `
  <p class="rubric-intro">BIMI (Brand Indicators for Message Identification) lets your verified brand logo appear next to authenticated messages in supporting inboxes. It is effectively a reward for reaching <code>p=quarantine</code> or <code>p=reject</code> on DMARC — receivers will not honor a BIMI record without enforced authentication.</p>

  <div class="bd-card">
    <div class="bd-card-title">How to read a BIMI record</div>
    <div class="bd-card-body">
      <p class="tier-text">BIMI records live at <code>default._bimi.yourdomain.com</code> as TXT records:</p>
      <pre class="learn-example"><code>v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>v</code></dt><dd>Version. Must be <code>BIMI1</code>.</dd></div>
        <div><dt><code>l</code></dt><dd>Logo URL. Must be HTTPS and must point at an SVG Tiny PS file — not a full SVG, not a PNG.</dd></div>
        <div><dt><code>a</code></dt><dd>Authority evidence. The URL of a Verified Mark Certificate (VMC) or Common Mark Certificate (CMC). Gmail and Apple Mail require this to actually display the logo.</dd></div>
      </dl>
      <p class="tier-text" style="margin-top:12px">Selectors other than <code>default</code> are supported by the spec but rarely used — dmarcheck checks <code>default._bimi</code>.</p>
    </div>
  </div>

  <div class="bd-card">
    <h2 class="bd-card-title">BIMI certification: VMC vs CMC</h2>
    <div class="bd-card-body">
      <p class="tier-text">The certificate behind the <code>a=</code> tag is what turns BIMI from "record published" into "logo actually displays." A Mark Certificate is issued only after a certificate authority verifies you have the right to use the logo — that verification work is the product you are paying for. Two certificate types exist, and the difference comes down to the evidence you can offer:</p>
      <dl class="explainer-grid" style="margin-top:12px">
        <div><dt>VMC</dt><dd>A <strong>Verified Mark Certificate</strong> requires the logo to be a registered trademark with a recognized intellectual-property office (USPTO or EUIPO, among others). It is the original certificate type, the most widely honored, and the one that unlocks Gmail's blue verified checkmark.</dd></div>
        <div><dt>CMC</dt><dd>A <strong>Common Mark Certificate</strong> drops the trademark requirement: it accepts a government-issued mark, or proof the logo has been in continuous use for at least 12 months (dated screenshots, archived pages, marketing material). The logo displays, but receivers currently reserve the verified checkmark for VMC holders.</dd></div>
      </dl>
      <p class="tier-text" style="margin-top:12px">Both types share the same hard prerequisite: DMARC at enforcement — <code>p=quarantine</code> or <code>p=reject</code> applied to all mail (<code>pct=100</code>). The issuing CA checks this before selling you anything, and receivers re-check it on every message.</p>
      <p class="tier-text" style="margin-top:12px"><strong>Issuers and cost.</strong> DigiCert and Entrust are the established Mark Verifying Authorities, and both sell VMCs and CMCs. Budget roughly $1,000&ndash;$1,500 per year as of 2026 — pricing is per logo, per year, and most of it covers the human verification step rather than the certificate itself.</p>
      <p class="tier-text" style="margin-top:12px"><strong>How issuance works:</strong></p>
      <ol class="learn-steps">
        <li>Get DMARC to <code>p=quarantine</code> or <code>p=reject</code> at <code>pct=100</code> first — nothing else matters until this is done.</li>
        <li>Pick the certificate type your evidence supports: registered trademark means VMC; a government mark or 12 months of documented prior use means CMC.</li>
        <li>Convert the exact logo you will use to SVG Tiny PS. The CA embeds the artwork in the certificate, so it must match the file your <code>l=</code> tag serves.</li>
        <li>Apply through the CA and complete identity verification — document checks and often a recorded video call. Issuance takes days to a few weeks, not minutes.</li>
        <li>Host the issued PEM file over HTTPS, reference it from the <code>a=</code> tag, and re-scan to confirm the record validates end to end.</li>
      </ol>
      <p class="tier-text" style="margin-top:14px"><strong>Logo still not showing?</strong> Certificate problems fail silently — the logo just never appears. Work through these in order:</p>
      <ul class="learn-pitfalls">
        <li><strong>Certificate expired.</strong> Mark Certificates last about a year and renewals are not automatic. dmarcheck fetches the certificate from your <code>a=</code> URL on every scan and flags an expired one.</li>
        <li><strong>Chain not trusted.</strong> The PEM at your <code>a=</code> URL must include the intermediates chaining to the issuing CA's root — serving only the leaf certificate fails validation at receivers.</li>
        <li><strong>DMARC not at enforcement.</strong> <code>p=none</code>, or a <code>pct</code> below 100, disqualifies the domain even with a perfectly valid certificate.</li>
        <li><strong>SVG is not Tiny PS.</strong> Both the hosted logo and the artwork embedded in the certificate must use the Tiny PS profile — a standard SVG export will not render.</li>
        <li><strong>Reputation lag.</strong> Gmail also weighs sender reputation, and logos can take days to appear after a fix. If everything validates, wait before debugging further.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>DMARC is not enforced.</strong> BIMI is explicit about this: without <code>p=quarantine</code> or <code>p=reject</code>, receivers ignore your record entirely. Fix DMARC first, then come back to BIMI.</li>
        <li><strong>Logo URL is not HTTPS.</strong> The spec requires HTTPS, and receivers will not fetch an HTTP asset.</li>
        <li><strong>Wrong SVG profile.</strong> BIMI requires <em>SVG Tiny PS</em>, a constrained subset. A regular SVG exported from Illustrator will not pass validation — use a dedicated BIMI converter or a service like Entrust or DigiCert.</li>
        <li id="${esc(LEARN_ANCHORS.bimiCertification.id)}"><strong>No <code>a=</code> tag.</strong> Without a VMC or CMC, Gmail and Apple Mail will not render your logo even if the BIMI record is otherwise valid. The logo may appear in other clients that do not require certification.</li>
        <li><strong>Self-signed or expired certificate.</strong> The authority evidence must chain to a trusted issuer and be currently valid. Certificates typically last one year.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Confirm your DMARC policy is <code>quarantine</code> or <code>reject</code>. If not, BIMI will not display — start with the <a href="/learn/dmarc">DMARC guide</a>.</li>
        <li>Convert your logo to SVG Tiny PS and host it over HTTPS. Many CAs offer a converter as part of the VMC purchase flow.</li>
        <li>Obtain a VMC from a supported certificate authority (Entrust, DigiCert). You will need a trademark registration for the logo.</li>
        <li>Publish the <code>default._bimi</code> TXT record with <code>v=BIMI1</code>, <code>l=</code>, and <code>a=</code>.</li>
        <li>Test with a supporting inbox — Gmail shows BIMI logos in the message list once the record is valid and your domain has reputation.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for BIMI")}
  `;

  return renderLearnPage({
    protocol: "BIMI",
    slug: "bimi",
    title: "What is BIMI? Logos, VMC/CMC certification, and DMARC — dmarcheck",
    headline: "What is BIMI? Brand logos, VMC/CMC certification, and DMARC",
    description:
      "A plain-English guide to BIMI and BIMI certification: how the default._bimi record works, VMC vs CMC, what a certificate roughly costs, why enforced DMARC is required, and how to debug a logo that will not display.",
    body,
  });
}

// ---------------------------------------------------------------------------
// MTA-STS
// ---------------------------------------------------------------------------

export function renderLearnMtaSts(): string {
  const body = `
  <p class="rubric-intro">MTA-STS (RFC 8461) tells other mail servers that your domain requires TLS when they deliver mail to you. It has two parts: a short DNS TXT record that announces the policy, and an HTTPS-hosted policy file that spells out which MX hosts are valid and whether the policy is enforced or still in testing.</p>

  <div class="bd-card">
    <div class="bd-card-title">How MTA-STS works</div>
    <div class="bd-card-body">
      <p class="tier-text">The DNS half lives at <code>_mta-sts.yourdomain.com</code>:</p>
      <pre class="learn-example"><code>v=STSv1; id=20260411000000</code></pre>
      <p class="tier-text">The policy file is served over HTTPS at a fixed path:</p>
      <pre class="learn-example"><code>https://mta-sts.yourdomain.com/.well-known/mta-sts.txt

version: STSv1
mode: enforce
mx: mx1.yourdomain.com
mx: mx2.yourdomain.com
max_age: 604800</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>version</code></dt><dd>Must be <code>STSv1</code>.</dd></div>
        <div><dt><code>mode</code></dt><dd><code>enforce</code> requires TLS to valid MX hosts, <code>testing</code> reports failures without blocking, <code>none</code> disables the policy.</dd></div>
        <div><dt><code>mx</code></dt><dd>One line per MX host or wildcard. Only these hosts are accepted once enforcement is on.</dd></div>
        <div><dt><code>max_age</code></dt><dd>How long (in seconds) receiving servers should cache the policy. RFC 8461 recommends at least 604800 (one week) in production.</dd></div>
        <div><dt><code>id</code> (DNS)</dt><dd>An opaque identifier — usually a timestamp. Change it whenever you update the policy so receivers re-fetch.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>DNS record without the policy file.</strong> The TXT record claims MTA-STS is live, but <code>https://mta-sts.yourdomain.com/.well-known/mta-sts.txt</code> returns 404. Receivers treat this as no policy.</li>
        <li><strong>Policy file without the DNS record.</strong> The reverse: file exists, but receivers never discover it because the <code>_mta-sts</code> TXT record is missing.</li>
        <li><strong>Stuck in <code>mode: testing</code>.</strong> Testing mode is a useful pre-launch step, but it does not block any mail. dmarcheck applies a penalty to testing-only policies to nudge you to switch to <code>enforce</code>.</li>
        <li><strong>Too-short <code>max_age</code>.</strong> Anything under 86400 (one day) is flagged. Production deployments should be at least one week.</li>
        <li><strong>Missing <code>mx</code> lines.</strong> Without MX patterns the policy cannot actually validate hosts. dmarcheck warns when the list is empty.</li>
        <li><strong>Redirecting the policy fetch.</strong> RFC 8461 §3.3 forbids following redirects for the policy fetch. Serve the file directly from <code>mta-sts.&lt;domain&gt;</code>, not via a 301/302 from somewhere else.</li>
        <li><strong>Forgetting to bump <code>id</code>.</strong> You update the policy file but leave the DNS <code>id</code> unchanged, so receivers keep serving the cached old version until <code>max_age</code> expires.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Publish the HTTPS policy file at <code>https://mta-sts.yourdomain.com/.well-known/mta-sts.txt</code> with <code>mode: testing</code> first.</li>
        <li>Add the <code>_mta-sts</code> TXT record with a fresh <code>id</code>.</li>
        <li>Watch TLS-RPT reports (via an <code>_smtp._tls</code> TXT record) for a week or two to catch senders that cannot negotiate TLS to your MX hosts.</li>
        <li>Switch the policy file from <code>testing</code> to <code>enforce</code> and bump <code>id</code>.</li>
        <li>Raise <code>max_age</code> to <code>604800</code> (one week) or longer once you are confident in the MX list.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for MTA-STS")}
  `;

  return renderLearnPage({
    protocol: "MTA-STS",
    slug: "mta-sts",
    title: "What is MTA-STS? Enforcing TLS for inbound mail — dmarcheck",
    headline: "What is MTA-STS? Enforcing TLS for inbound mail",
    description:
      "A plain-English guide to MTA-STS (RFC 8461): the _mta-sts DNS record, the HTTPS policy file, enforce vs testing mode, and how to roll out without breaking legitimate senders.",
    body,
  });
}

// ---------------------------------------------------------------------------
// security.txt
// ---------------------------------------------------------------------------

export function renderLearnSecurityTxt(): string {
  const body = `
  <p class="rubric-intro">security.txt (RFC 9116) is a plain-text file hosted on your web server that tells security researchers how to responsibly disclose vulnerabilities. A machine-readable format means automated scanners and bug-bounty platforms can find your contact information without guessing email addresses.</p>

  <div class="bd-card">
    <div class="bd-card-title">How security.txt works</div>
    <div class="bd-card-body">
      <p class="tier-text">The file must be served over HTTPS at one of two canonical paths. The preferred location is the <code>.well-known</code> directory:</p>
      <pre class="learn-example"><code>https://example.com/.well-known/security.txt
https://example.com/security.txt</code></pre>
      <p class="tier-text">A minimal but complete security.txt looks like this:</p>
      <pre class="learn-example"><code>Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
Policy: https://example.com/security-policy
Acknowledgments: https://example.com/hall-of-fame</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>Contact</code></dt><dd>Required. One or more URI values — <code>mailto:</code>, <code>https:</code> (for a bug-bounty form), or <code>tel:</code>. Multiple <code>Contact</code> lines are allowed; researchers use the first they can reach.</dd></div>
        <div><dt><code>Expires</code></dt><dd>Required. An ISO 8601 datetime after which the file should be considered stale. RFC 9116 recommends no more than one year in the future. dmarcheck flags files with an expiry more than 12 months out or that have already expired.</dd></div>
        <div><dt><code>Policy</code></dt><dd>Recommended. A URL linking to your full vulnerability disclosure policy — scope, safe-harbor language, response SLA, and reward structure if you run a bug-bounty program.</dd></div>
        <div><dt><code>Acknowledgments</code></dt><dd>Recommended. A page where you credit researchers who have disclosed past issues. Builds trust and encourages future reports.</dd></div>
        <div><dt><code>Encryption</code></dt><dd>Optional. A URL to a PGP public key so researchers can send reports end-to-end encrypted.</dd></div>
        <div><dt><code>Canonical</code></dt><dd>Optional. The definitive URL of this security.txt file. Useful when the file is served from a CDN or a different origin than the one being scanned.</dd></div>
        <div><dt><code>Preferred-Languages</code></dt><dd>Optional. A comma-separated list of BCP 47 language tags indicating which languages the security team can respond in.</dd></div>
        <div><dt><code>CSAF</code></dt><dd>Optional. A URL to a CSAF (Common Security Advisory Framework) provider-metadata.json, for organizations that publish machine-readable advisories.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">The two canonical paths and redirect behavior</div>
    <div class="bd-card-body">
      <p class="tier-text">RFC 9116 specifies that the preferred location is <code>/.well-known/security.txt</code>. If that path is absent, tools fall back to <code>/security.txt</code> at the root. dmarcheck checks <code>/.well-known/security.txt</code> first, then the root path.</p>
      <p class="tier-text">Unlike MTA-STS (which explicitly forbids following redirects), RFC 9116 §3 places no equivalent restriction on security.txt. Real-world deployments commonly use redirects — for example, a government domain redirecting to a central vulnerability disclosure portal. dmarcheck follows redirects (<code>redirect: "follow"</code>) to honor this convention. If the final destination is a valid security.txt, the scan passes regardless of how many hops were involved.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>No <code>Contact</code> field.</strong> <code>Contact</code> is the only field RFC 9116 marks as mandatory. A file without it is malformed and dmarcheck reports the missing field.</li>
        <li><strong>No <code>Expires</code> field.</strong> Also required. Files without an expiry date have no freshness signal, which means researchers cannot tell if the contact is still monitored.</li>
        <li><strong>Expired file.</strong> An <code>Expires</code> date in the past means the file has not been reviewed recently. Rotate it at least annually — a cron job or calendar reminder is the usual approach.</li>
        <li><strong>Expiry too far in the future.</strong> RFC 9116 recommends the expiry be no more than one year out. Setting it to 2099 defeats the purpose of the freshness signal.</li>
        <li><strong>Served over HTTP instead of HTTPS.</strong> The RFC requires HTTPS. A plain-HTTP file can be tampered with in transit and most security scanners will reject it.</li>
        <li><strong>Wrong content type.</strong> RFC 9116 specifies <code>text/plain</code>. Serving it as <code>application/octet-stream</code> or <code>text/html</code> confuses automated parsers.</li>
        <li><strong>File exists at <code>/security.txt</code> but not <code>/.well-known/security.txt</code>.</strong> The preferred path is the <code>.well-known</code> location. Serve the canonical copy there, and optionally redirect from the root.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Create the file at <code>https://yourdomain.com/.well-known/security.txt</code>. Use <a href="https://securitytxt.org/">securitytxt.org</a> to generate a signed version with a PGP key, or hand-craft the minimal two-field version to start.</li>
        <li>Set <code>Contact</code> to an email address or HTTPS form that your security team actually monitors. A generic <code>security@</code> alias works if it goes somewhere real.</li>
        <li>Set <code>Expires</code> to roughly 12 months from today in ISO 8601 format (e.g. <code>2027-06-01T00:00:00.000Z</code>). Add a calendar reminder to renew it.</li>
        <li>Add a <code>Policy</code> link once you have written a disclosure policy — even a brief page clarifying scope and response expectations meaningfully lowers the friction for researchers.</li>
        <li>Serve the file with <code>Content-Type: text/plain; charset=utf-8</code>. Verify with <code>curl -I https://yourdomain.com/.well-known/security.txt</code>.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for security.txt")}
  `;

  return renderLearnPage({
    protocol: "security.txt",
    slug: "security-txt",
    title: "What is security.txt? Contact, Expires, and RFC 9116 — dmarcheck",
    headline:
      "What is security.txt? Responsible disclosure made machine-readable",
    description:
      "A plain-English guide to security.txt (RFC 9116): the two canonical paths, required Contact and Expires fields, redirect behavior, and the common misconfigurations that make security researchers give up.",
    body,
  });
}

// ---------------------------------------------------------------------------
// TLS-RPT
// ---------------------------------------------------------------------------

export function renderLearnTlsRpt(): string {
  const body = `
  <p class="rubric-intro">TLS-RPT (SMTP TLS Reporting, RFC 8460) is a DNS TXT record that tells other mail servers where to send reports about TLS negotiation failures when they try to deliver mail to you. It is the reporting companion to MTA-STS: you enforce TLS via MTA-STS, and TLS-RPT tells you when senders cannot meet that requirement.</p>

  <div class="bd-card">
    <div class="bd-card-title">How to read a TLS-RPT record</div>
    <div class="bd-card-body">
      <p class="tier-text">The TLS-RPT record lives at <code>_smtp._tls.yourdomain.com</code> as a TXT record:</p>
      <pre class="learn-example"><code>v=TLSRPTv1; rua=mailto:tlsrpt@example.com</code></pre>
      <p class="tier-text">Multiple report destinations are comma-separated:</p>
      <pre class="learn-example"><code>v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://tlsrpt.example.com/upload</code></pre>
      <dl class="explainer-grid">
        <div><dt><code>v</code></dt><dd>Version. Must be <code>TLSRPTv1</code> — the only defined version. Records without this prefix or with a different version are ignored by sending MTAs.</dd></div>
        <div><dt><code>rua</code></dt><dd>Report URI for aggregates. Accepts <code>mailto:</code> addresses and <code>https:</code> endpoints. Sending MTAs POST JSON reports to HTTPS endpoints or email them as gzip attachments to <code>mailto:</code> addresses.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What the reports contain</div>
    <div class="bd-card-body">
      <p class="tier-text">Each TLS-RPT report is a JSON document (gzip-compressed) covering a 24-hour period. The key fields are:</p>
      <dl class="explainer-grid">
        <div><dt><code>organization-name</code></dt><dd>The sending MTA's organization — tells you which mail providers are attempting delivery.</dd></div>
        <div><dt><code>date-range</code></dt><dd>The reporting window: <code>start-datetime</code> and <code>end-datetime</code> in UTC.</dd></div>
        <div><dt><code>policies</code></dt><dd>An array of policy objects. Each one describes a policy type (<code>sts</code> for MTA-STS, <code>tlsa</code> for DANE, <code>no-policy-found</code>) and its outcome.</dd></div>
        <div><dt><code>summary</code></dt><dd>Inside each policy: <code>total-successful-session-count</code> and <code>total-failure-session-count</code> — the core delivery health signal.</dd></div>
        <div><dt><code>failure-details</code></dt><dd>An array of objects with a <code>result-type</code> (e.g. <code>certificate-expired</code>, <code>certificate-not-trusted</code>, <code>starttls-not-supported</code>), the sending/receiving MX IP, and the count. This is where you learn <em>why</em> TLS failed.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Why TLS-RPT matters alongside DMARC reporting</div>
    <div class="bd-card-body">
      <p class="tier-text">DMARC aggregate reports (via <code>rua=</code>) tell you whether messages are passing SPF/DKIM authentication at the receiving end. TLS-RPT fills a different gap: it tells you whether the <em>transport layer</em> between sending and receiving MTAs is healthy. A message can pass DMARC and still be at risk if the SMTP connection fell back to cleartext because of a TLS negotiation failure.</p>
      <p class="tier-text">Together, the two reporting streams give you end-to-end visibility: authentication posture (DMARC) and transport security posture (TLS-RPT). Both are worth monitoring continuously.</p>
      <p class="tier-text">TLS-RPT is particularly important during MTA-STS rollout. While your policy is in <code>testing</code> mode, senders will report failures without dropping the message. Once you switch to <code>enforce</code>, failures start causing deferrals, so you want to see a clean TLS-RPT baseline first.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>No record.</strong> Without <code>_smtp._tls.yourdomain.com</code>, you have no visibility into TLS delivery failures to your domain. If you have MTA-STS deployed, a missing TLS-RPT record means flying blind.</li>
        <li><strong>Record present but <code>rua</code> is missing.</strong> The <code>rua</code> tag is the only meaningful field after <code>v=TLSRPTv1</code>. A record without it is syntactically incomplete — sending MTAs will not know where to send reports.</li>
        <li><strong>Wrong subdomain.</strong> The record must be at <code>_smtp._tls.yourdomain.com</code>, not <code>_tls.yourdomain.com</code> or any other location. The double-underscore prefix is significant.</li>
        <li><strong>The <code>mailto:</code> address is not monitored.</strong> Reports arrive as <code>.gz</code>-compressed JSON attachments. If the alias goes to a ticket queue no one checks, failures will pile up silently. Set up an alert or use a third-party TLS-RPT processing service.</li>
        <li><strong>Using an HTTPS endpoint that rejects the report format.</strong> If you point <code>rua</code> at an HTTPS URL, the receiving server must accept POST requests with <code>Content-Type: application/tlsrpt+gzip</code> and respond 200-299. A webhook that returns 400 on unrecognized payloads will silently drop reports.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Publish the TXT record at <code>_smtp._tls.yourdomain.com</code> with at minimum <code>v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com</code>.</li>
        <li>Make sure the address in <code>rua</code> is monitored. For low-volume domains a simple inbox alias is enough; for high-volume domains, use a third-party SMTP TLS reporting service that parses and visualizes the JSON for you.</li>
        <li>If you also have an MTA-STS policy in <code>testing</code> mode, watch the TLS-RPT reports for a week or two before switching to <code>enforce</code>. Any <code>sts-policy-invalid</code> or <code>certificate-*</code> failure types need investigation first.</li>
        <li>Once you switch MTA-STS to <code>enforce</code>, continue monitoring TLS-RPT. A spike in <code>starttls-not-supported</code> from a major sender signals a configuration problem on their end that may require contacting their postmaster.</li>
        <li>Keep the TLS-RPT record even after your MTA-STS setup is stable — it provides ongoing assurance that TLS delivery is healthy and catches certificate renewals that were missed before they cause failures.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to scan for TLS-RPT")}
  `;

  return renderLearnPage({
    protocol: "TLS-RPT",
    slug: "tls-rpt",
    title: "What is TLS-RPT? SMTP TLS Reporting and RFC 8460 — dmarcheck",
    headline: "What is TLS-RPT? SMTP TLS Reporting for inbound mail",
    description:
      "A plain-English guide to TLS-RPT (RFC 8460): the _smtp._tls DNS record, the rua= report URI, what the JSON reports contain, and how TLS-RPT complements MTA-STS and DMARC reporting.",
    body,
  });
}

// ---------------------------------------------------------------------------
// DNSSEC
// ---------------------------------------------------------------------------

export function renderLearnDnssec(): string {
  const body = `
  <p class="rubric-intro">DNSSEC (DNS Security Extensions, RFCs 4033&ndash;4035) cryptographically signs your DNS zone so that resolvers can detect tampering. Without it, an attacker who can intercept or forge DNS answers can quietly redirect your mail, your MX records, or your SPF/DKIM/DMARC lookups. DNSSEC is the foundation the rest of your email security rests on &mdash; in particular, DANE/TLSA only becomes trustworthy once the zone serving the TLSA records is signed and validated.</p>

  <div class="bd-card">
    <div class="bd-card-title">How DNSSEC is checked</div>
    <div class="bd-card-body">
      <p class="tier-text">DNSSEC status is determined from two signals: the presence of <strong>DS (Delegation Signer) records</strong> in the parent zone, and the <strong>AD (Authenticated Data) flag</strong> set by a validating resolver.</p>
      <dl class="explainer-grid">
        <div><dt><code>DS</code> records</dt><dd>Published in the <em>parent</em> zone (e.g. <code>.com</code> holds the DS records for <code>example.com</code>). Their presence means the parent has signed the delegation to your zone &mdash; the standard way to tell a zone is DNSSEC-enabled without walking the entire chain of trust.</dd></div>
        <div><dt>AD flag</dt><dd>Set by a DNSSEC-aware resolver when it has successfully verified the full signature chain from the root down to the record you asked for. When DS records are present <em>and</em> the AD flag is set, the zone is signed and validated.</dd></div>
        <div><dt><code>DNSKEY</code> / <code>RRSIG</code></dt><dd>Inside your zone, the <code>DNSKEY</code> records hold the public keys and every record set carries an <code>RRSIG</code> signature. The DS record in the parent is a hash of your <code>DNSKEY</code>, which is what links your zone into the global chain of trust anchored at the DNS root.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Signed vs. validated</div>
    <div class="bd-card-body">
      <p class="tier-text">These are two distinct states, and the difference matters:</p>
      <dl class="explainer-grid">
        <div><dt>Signed and validated</dt><dd>DS records are present and a validating resolver returns the AD flag. The chain of trust is intact end to end &mdash; this is the healthy state.</dd></div>
        <div><dt>Signed but not validated</dt><dd>DS records exist, but the resolver did not set the AD flag. The zone has DNSSEC configured, yet validation is failing &mdash; commonly a broken or expired signature, a key rollover that didn't complete, or a DS record in the parent that no longer matches your current <code>DNSKEY</code>. A broken DNSSEC chain can make your domain <em>unreachable</em> to validating resolvers, which is often worse than having no DNSSEC at all.</dd></div>
        <div><dt>Not configured</dt><dd>No DS records in the parent zone. The zone is unsigned, so resolvers cannot detect forged answers for it.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Why DNSSEC matters for email</div>
    <div class="bd-card-body">
      <p class="tier-text">Every email-security record dmarcheck scans is a DNS lookup: your MX records, the SPF TXT record, DKIM public keys at <code>selector._domainkey</code>, the DMARC record at <code>_dmarc</code>, and MTA-STS policy. If an attacker can forge those answers, they can strip or weaken your protections without touching your servers. DNSSEC is what makes the answers tamper-evident.</p>
      <p class="tier-text">It is also a hard prerequisite for DANE: a TLSA record that pins your MX certificate is only meaningful if the resolver can prove the TLSA record itself wasn't forged &mdash; which requires the zone to be DNSSEC-signed and validated.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>Signed but not validated.</strong> The most dangerous state: DNSSEC is enabled but the chain is broken. Usually a stale DS record after a key rollover, or expired signatures. Validating resolvers will return SERVFAIL, making your domain unreachable for those users.</li>
        <li><strong>Missing DS record.</strong> You signed the zone at your DNS provider but never published the DS record at the registrar. The signatures exist but nothing in the parent zone vouches for them, so resolvers treat the zone as unsigned.</li>
        <li><strong>Key rollover gone wrong.</strong> Rotating your KSK without updating the parent DS record (or removing the old key too early) breaks validation until the DS catches up.</li>
        <li><strong>Provider transfer without re-signing.</strong> Moving DNS hosting and forgetting to re-enable DNSSEC and republish a matching DS leaves a dangling, invalid chain.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>If the scan shows <em>signed but not validated</em>, treat it as urgent &mdash; a broken chain can take your domain offline for validating resolvers. Verify the DS record at your registrar matches your current <code>DNSKEY</code>.</li>
        <li>If DNSSEC is <em>not configured</em>, enable zone signing at your DNS provider, then publish the generated DS record at your domain registrar so the parent zone signs your delegation.</li>
        <li>After enabling or repairing, confirm a validating resolver returns the AD flag for your domain before relying on it for DANE.</li>
        <li>Automate key rollovers where your provider supports it, and monitor the chain so an expired signature or stale DS is caught before it causes a SERVFAIL outage.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to check for DNSSEC")}
  `;

  return renderLearnPage({
    protocol: "DNSSEC",
    slug: "dnssec",
    title:
      "What is DNSSEC? Signed DNS zones and the chain of trust — dmarcheck",
    headline: "What is DNSSEC? Signing your DNS zone and the chain of trust",
    description:
      "A plain-English guide to DNSSEC: DS records in the parent zone, the AD flag from a validating resolver, the difference between signed and validated, and why DNSSEC underpins DANE and the rest of your email security.",
    body,
  });
}

// ---------------------------------------------------------------------------
// DANE / TLSA
// ---------------------------------------------------------------------------

export function renderLearnDane(): string {
  const body = `
  <p class="rubric-intro">DANE (DNS-Based Authentication of Named Entities, RFC 6698) lets you publish a <strong>TLSA record</strong> in DNS that pins the TLS certificate your mail servers present. A sending mail server that supports DANE checks the TLSA record before delivering, so it can detect a downgraded or substituted certificate. Because the proof lives in DNS, DANE is only trustworthy when the zone is DNSSEC-signed and validated &mdash; TLSA records without a DNSSEC chain can themselves be forged.</p>

  <div class="bd-card">
    <div class="bd-card-title">How to read a TLSA record</div>
    <div class="bd-card-body">
      <p class="tier-text">DANE for SMTP is queried <strong>per MX exchange</strong>. For each MX host, the TLSA record lives at <code>_25._tcp.&lt;mx-host&gt;</code> &mdash; port 25, TCP, prefixed to the mail server's hostname:</p>
      <pre class="learn-example"><code>_25._tcp.mx1.example.com.  IN TLSA  3 1 1 0f0c8e...d4</code></pre>
      <p class="tier-text">The first three numbers are the certificate-usage triple defined by RFC 6698:</p>
      <dl class="explainer-grid">
        <div><dt>Usage</dt><dd>How the association is used. <code>3</code> (DANE-EE) pins the server certificate directly &mdash; the common, recommended choice for SMTP. <code>2</code> (DANE-TA) pins a trust anchor / CA in your chain. <code>0</code> and <code>1</code> (PKIX-TA / PKIX-EE) additionally require public-CA validation and are rarely used for mail.</dd></div>
        <div><dt>Selector</dt><dd>Which part of the certificate is matched. <code>0</code> matches the full certificate; <code>1</code> matches just the SubjectPublicKeyInfo (the public key), which survives certificate renewal as long as you keep the same key.</dd></div>
        <div><dt>Matching type</dt><dd>How the data is compared. <code>0</code> is the raw bytes; <code>1</code> is a SHA-256 hash (the usual choice); <code>2</code> is SHA-512.</dd></div>
        <div><dt>Association data</dt><dd>The hex-encoded certificate, public key, or hash &mdash; whatever the selector and matching type select.</dd></div>
      </dl>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">DANE requires DNSSEC</div>
    <div class="bd-card-body">
      <p class="tier-text">A TLSA record is only a security control if a resolver can prove it wasn't tampered with. That proof comes from DNSSEC: the zone serving the TLSA record must be signed, and the resolver must validate the chain (return the AD flag). dmarcheck checks both &mdash; a TLSA record found on a host whose DNSSEC is <em>not</em> validated is reported as a warning, not a pass, because an attacker who can forge DNS could forge the TLSA record too.</p>
      <p class="tier-text">So the correct deployment order is: turn on DNSSEC for your zone first (see <a href="/learn/dnssec">our DNSSEC guide</a>), confirm it validates, then publish TLSA records for each MX host. Doing it the other way around gives you records that look configured but provide no real protection.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Per-MX-host configuration</div>
    <div class="bd-card-body">
      <p class="tier-text">Mail can be delivered to any of your MX exchanges, so each one needs its own TLSA record matching the certificate <em>that host</em> actually serves. dmarcheck queries <code>_25._tcp.&lt;exchange&gt;</code> for every MX host in your domain and reports them individually &mdash; it's common to have DANE correctly configured on a primary MX but missing or mismatched on a backup.</p>
      <p class="tier-text">If you have no MX records, DANE is not applicable &mdash; there's no SMTP endpoint to pin.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common misconfigurations</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">
        <li><strong>TLSA records without DNSSEC.</strong> The single most common mistake: publishing TLSA records on a zone that isn't DNSSEC-signed and validated. Sending MTAs will ignore them, and dmarcheck flags them as a warning rather than a pass.</li>
        <li><strong>Stale association after certificate renewal.</strong> If you use a selector of <code>0</code> (full certificate) or matching type <code>0</code>, renewing the certificate breaks the match unless you republish the TLSA record. Using selector <code>1</code> (public key) and reusing the key across renewals avoids this.</li>
        <li><strong>Missing on a backup MX.</strong> DANE configured on the primary but not the secondary MX leaves a hole &mdash; mail that fails over to the backup gets no certificate pinning.</li>
        <li><strong>Wrong owner name.</strong> The record must be at <code>_25._tcp.&lt;mx-host&gt;</code>, using the MX hostname, not the domain itself.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What to fix first</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li>Enable and validate DNSSEC for your zone first &mdash; DANE is meaningless without it.</li>
        <li>Generate a TLSA record for each MX host's certificate, preferring usage <code>3</code>, selector <code>1</code>, matching type <code>1</code> (DANE-EE, public-key, SHA-256) for renewal-safe pinning.</li>
        <li>Publish each record at <code>_25._tcp.&lt;mx-host&gt;</code> and re-scan to confirm every MX exchange shows DNSSEC-validated TLSA.</li>
        <li>Tie TLSA updates to your certificate-renewal process so the pin and the served certificate never drift apart, and keep DANE in sync across primary and backup MX hosts.</li>
      </ol>
    </div>
  </div>

  ${learnCta("Enter a domain to check for DANE/TLSA")}
  `;

  return renderLearnPage({
    protocol: "DANE/TLSA",
    slug: "dane",
    title: "What is DANE/TLSA? Pinning MX certificates over DNSSEC — dmarcheck",
    headline: "What is DANE? TLSA records that pin your MX certificates",
    description:
      "A plain-English guide to DANE/TLSA (RFC 6698): the _25._tcp TLSA record queried per MX host, the usage/selector/matching-type triple, and why DANE only works on a DNSSEC-signed and validated zone.",
    body,
  });
}
