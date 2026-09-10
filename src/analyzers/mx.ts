import { DnsLookupError, queryMx } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import type { EmailProvider, MxRecord, MxResult, Validation } from "./types.js";

interface ProviderSignature {
  pattern: RegExp;
  name: string;
  category: EmailProvider["category"];
}

const PROVIDER_SIGNATURES: ProviderSignature[] = [
  // Security gateways (check first — more specific)
  {
    pattern: /\.pphosted\.com$/,
    name: "Proofpoint",
    category: "security-gateway",
  },
  {
    pattern: /\.ppe-hosted\.com$/,
    name: "Proofpoint Essentials",
    category: "security-gateway",
  },
  {
    pattern: /\.mimecast\.com$/,
    name: "Mimecast",
    category: "security-gateway",
  },
  {
    pattern: /\.barracudanetworks\.com$/,
    name: "Barracuda",
    category: "security-gateway",
  },
  {
    pattern: /\.iphmx\.com$/,
    name: "Cisco Email Security",
    category: "security-gateway",
  },
  { pattern: /\.sophos\.com$/, name: "Sophos", category: "security-gateway" },
  {
    pattern: /\.messagelabs\.com$/,
    name: "Symantec/Broadcom",
    category: "security-gateway",
  },
  {
    // Formerly Area 1. Distinct from Cloudflare Email Routing
    // (*.mx.cloudflare.net), which forwards rather than filters and is
    // deliberately not listed here.
    pattern: /\.cf-emailsecurity\.net$/,
    name: "Cloudflare Email Security",
    category: "security-gateway",
  },
  {
    pattern: /\.junkemailfilter\.(com|net|org)$/,
    name: "MX Guarddog",
    category: "security-gateway",
  },

  // Email platforms
  {
    pattern: /\.google\.com$/,
    name: "Google Workspace",
    category: "email-platform",
  },
  {
    pattern: /\.googlemail\.com$/,
    name: "Google Workspace",
    category: "email-platform",
  },
  {
    pattern: /\.protection\.outlook\.com$/,
    name: "Microsoft 365",
    category: "email-platform",
  },
  {
    pattern: /\.olc\.protection\.outlook\.com$/,
    name: "Microsoft 365",
    category: "email-platform",
  },
  { pattern: /\.zoho\.com$/, name: "Zoho Mail", category: "email-platform" },
  {
    pattern: /\.yahoodns\.net$/,
    name: "Yahoo Mail",
    category: "email-platform",
  },
  { pattern: /\.fastmail\.com$/, name: "Fastmail", category: "email-platform" },
  {
    pattern: /\.protonmail\.ch$/,
    name: "Proton Mail",
    category: "email-platform",
  },

  // Hosting
  {
    pattern: /\.emailsrvr\.com$/,
    name: "Rackspace Email",
    category: "hosting",
  },
  { pattern: /\.secureserver\.net$/, name: "GoDaddy", category: "hosting" },
  { pattern: /\.ovh\.net$/, name: "OVH", category: "hosting" },
];

function matchProvider(exchange: string): EmailProvider | undefined {
  const normalized = exchange.toLowerCase().replace(/\.$/, "");
  for (const sig of PROVIDER_SIGNATURES) {
    if (sig.pattern.test(normalized)) {
      return { name: sig.name, category: sig.category };
    }
  }
  return undefined;
}

export function detectProviders(
  records: Array<{ exchange: string }>,
): EmailProvider[] {
  const seen = new Set<string>();
  const providers: EmailProvider[] = [];

  for (const record of records) {
    const provider = matchProvider(record.exchange);
    if (provider && !seen.has(provider.name)) {
      seen.add(provider.name);
      providers.push(provider);
    }
  }

  return providers;
}

export async function analyzeMx(
  domain: string,
  budget?: ScanBudget,
): Promise<MxResult> {
  let rawRecords: Awaited<ReturnType<typeof queryMx>>;
  try {
    rawRecords = await queryMx(domain, budget);
  } catch (err) {
    if (err instanceof DnsLookupError) {
      return {
        status: "warn",
        records: [],
        providers: [],
        lookup_error: { code: err.code, message: err.message },
        validations: [
          {
            status: "warn",
            message: `MX lookup failed (${err.code}) — result may be incomplete`,
          },
        ],
      };
    }
    throw err;
  }

  if (!rawRecords || rawRecords.length === 0) {
    return {
      status: "info",
      records: [],
      providers: [],
      validations: [{ status: "info", message: "No MX records found" }],
    };
  }

  // Null MX (RFC 7505): a single record whose exchange is the root (".") means
  // the domain explicitly sends and receives no mail. Detect it before the
  // trailing-dot strip below, which would otherwise render it as a blank host.
  if (rawRecords.length === 1) {
    const exchange = rawRecords[0].exchange.replace(/\.$/, "");
    if (exchange === "") {
      return {
        status: "info",
        records: [],
        providers: [],
        validations: [
          {
            status: "info",
            message:
              "Null MX (RFC 7505) — domain explicitly accepts no mail (no mail server configured by design)",
          },
        ],
      };
    }
  }

  const records: MxRecord[] = [...rawRecords]
    .sort((a, b) => a.priority - b.priority)
    .map((r) => {
      const exchange = r.exchange.replace(/\.$/, "");
      return {
        priority: r.priority,
        exchange,
        provider: matchProvider(exchange),
      };
    });

  const seen = new Set<string>();
  const providers: EmailProvider[] = [];
  for (const r of records) {
    if (r.provider && !seen.has(r.provider.name)) {
      seen.add(r.provider.name);
      providers.push(r.provider);
    }
  }
  const validations: Validation[] = [];

  validations.push({
    status: "info",
    message: `${records.length} MX record${records.length !== 1 ? "s" : ""} found`,
  });

  if (providers.length > 0) {
    validations.push({
      status: "info",
      message: `Detected: ${providers.map((p) => p.name).join(", ")}`,
    });
  }

  return { status: "info", records, providers, validations };
}
