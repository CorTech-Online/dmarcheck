import {
  getMxProvider,
  MX_PROVIDERS,
  type MxProvider,
  type MxProviderSection,
} from "../data/mx-providers.js";
import { esc, generateCreature } from "./components.js";
import { page, SITE_ORIGIN } from "./html.js";

// /mx — hub + per-provider pages. Modelled on /learn for visual parity (same
// .breakdown.learn CSS shell, same bd-card body cards) but the JSON-LD,
// breadcrumbs, and sibling lists are scoped to the /mx hub, not /learn.

// Original publication date of the /mx lane. Stable — never bump this on
// edits; search engines treat a moving datePublished as freshness gaming.
const MX_PUBLISHED = "2026-05-24";

// Bump when materially editing any /mx page prose. It lives here rather than
// per-provider so all pages stay in sync by default. Only this constant moves
// on edits; MX_PUBLISHED stays fixed.
export const MX_MODIFIED = "2026-05-24";

const MX_FOOTER = `<div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Free and open source &mdash; MIT License
    </a>
  </div>`;

// Promote markdown-style backticks to <code> tags. Input is escaped first so
// any literal `<` or `&` in the prose is rendered as text, not as HTML.
// Backticks themselves survive escaping unchanged, so the regex pass that
// follows operates on already-safe text — no double-escape, no HTML injection.
function proseToHtml(text: string): string {
  return esc(text).replace(/`([^`]+)`/g, "<code>$1</code>");
}

function renderSectionsHtml(sections: MxProviderSection[]): string {
  return sections
    .map((section) => {
      const paragraphs = section.paragraphs
        .map((p) => `<p class="tier-text">${proseToHtml(p)}</p>`)
        .join("");
      const list = section.list
        ? `<ul class="learn-pitfalls">${section.list
            .map((item) => `<li>${proseToHtml(item)}</li>`)
            .join("")}</ul>`
        : "";
      return `<div class="bd-card">
    <div class="bd-card-title">${esc(section.title)}</div>
    <div class="bd-card-body">
      ${paragraphs}
      ${list}
    </div>
  </div>`;
    })
    .join("");
}

function hostnameList(examples: string[]): string {
  return `<ul class="learn-pitfalls">${examples
    .map((h) => `<li><code>${esc(h)}</code></li>`)
    .join("")}</ul>`;
}

function scanLinks(domains: string[]): string {
  if (domains.length === 0) return "";
  const items = domains
    .map(
      (d) =>
        `<li><a href="/check?domain=${encodeURIComponent(d)}">Scan ${esc(d)} &rarr;</a></li>`,
    )
    .join("");
  return `<div class="bd-card">
    <div class="bd-card-title">Scan an example tenant</div>
    <div class="bd-card-body">
      <ul class="learn-pitfalls">${items}</ul>
    </div>
  </div>`;
}

function siblingLinks(currentSlug: string): string {
  const items = MX_PROVIDERS.filter((p) => p.slug !== currentSlug)
    .map(
      (p) =>
        `<li><a href="/mx/${p.slug}"><strong>${esc(p.shortName)}</strong> &mdash; ${esc(p.hostnameExamples[0] ?? "")}</a></li>`,
    )
    .join("");
  return `<ul class="learn-siblings">${items}</ul>`;
}

function providerJsonLd(provider: MxProvider): string {
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        headline: provider.headline,
        description: provider.description,
        datePublished: MX_PUBLISHED,
        dateModified: MX_MODIFIED,
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
        about: {
          "@type": "Thing",
          name: provider.displayName,
        },
        image: `${SITE_ORIGIN}/og-image.png`,
        mainEntityOfPage: `${SITE_ORIGIN}/mx/${provider.slug}`,
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
            name: "MX providers",
            item: `${SITE_ORIGIN}/mx`,
          },
          {
            "@type": "ListItem",
            position: 3,
            name: provider.shortName,
            item: `${SITE_ORIGIN}/mx/${provider.slug}`,
          },
        ],
      },
    ],
  });
}

export function renderMxProviderPage(slug: string): string | null {
  const provider = getMxProvider(slug);
  if (!provider) return null;

  const body = `<main class="breakdown learn">
  <nav class="report-nav" aria-label="Breadcrumb">
    <a href="/">${generateCreature("sm")} Home</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <a href="/mx">MX providers</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <span class="breadcrumb-current">${esc(provider.shortName)}</span>
  </nav>
  <h1 class="rubric-title">${esc(provider.headline)}</h1>
  <p class="rubric-intro">${proseToHtml(provider.intro)}</p>
  <div class="bd-card">
    <div class="bd-card-title">Hostnames in the catalog</div>
    <div class="bd-card-body">
      <p class="tier-text">Operated by ${esc(provider.operator)}. These are the MX hostnames you'll see in DNS:</p>
      ${hostnameList(provider.hostnameExamples)}
    </div>
  </div>
  ${renderSectionsHtml(provider.sections)}
  ${scanLinks(provider.parentExamples)}
  <div class="bd-card">
    <div class="bd-card-title">More MX providers</div>
    <div class="bd-card-body">
      ${siblingLinks(provider.slug)}
      <p class="tier-text" style="margin-top:12px">Want the full grading rubric? See <a href="/scoring">how dmarcheck calculates your score</a>.</p>
    </div>
  </div>
  ${MX_FOOTER}
</main>`;

  return page({
    title: `${provider.headline} — dmarcheck`,
    path: `/mx/${provider.slug}`,
    description: provider.description,
    jsonLd: providerJsonLd(provider),
    body,
  });
}

export function renderMxHub(): string {
  const hubJsonLd = JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "CollectionPage",
        name: "MX provider reference — dmarcheck",
        description:
          "Identify an inbound MX hostname: what it is, who runs it, and which domains use it. Covers Microsoft 365, Google Workspace, Mimecast, Proofpoint, Fastmail, Zoho, Amazon SES, and Cloudflare Email Routing.",
        url: `${SITE_ORIGIN}/mx`,
        mainEntity: {
          "@type": "ItemList",
          itemListElement: MX_PROVIDERS.map((p, i) => ({
            "@type": "ListItem",
            position: i + 1,
            url: `${SITE_ORIGIN}/mx/${p.slug}`,
            name: p.shortName,
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
            name: "MX providers",
            item: `${SITE_ORIGIN}/mx`,
          },
        ],
      },
    ],
  });

  const cards = MX_PROVIDERS.map(
    (p) =>
      `<li><a href="/mx/${p.slug}" class="learn-hub-card">
        <h2>${esc(p.shortName)}</h2>
        <p><code>${esc(p.hostnameExamples[0] ?? "")}</code></p>
      </a></li>`,
  ).join("");

  const body = `<main class="breakdown learn">
  <nav class="report-nav" aria-label="Breadcrumb">
    <a href="/">${generateCreature("sm")} Home</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <span class="breadcrumb-current">MX providers</span>
  </nav>
  <h1 class="rubric-title">Identify an MX hostname</h1>
  <p class="rubric-intro">If you've spotted an MX hostname in a DNS lookup or message header and want to know what runs it, start here. Each page covers what the service is, who operates it, how the MX hostname is structured, and which kinds of organisations use it.</p>
  <ul class="learn-hub-grid">${cards}</ul>
  ${MX_FOOTER}
</main>`;

  return page({
    title: "MX provider reference — identify an MX hostname | dmarcheck",
    path: "/mx",
    description:
      "Identify an inbound MX hostname: what it is, who runs it, and which domains use it. Microsoft 365, Google Workspace, Mimecast, Proofpoint, Fastmail, Zoho, Amazon SES, Cloudflare.",
    jsonLd: hubJsonLd,
    body,
  });
}
