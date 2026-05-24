import {
  getRegistrableDomain,
  normalizeHostname,
  parseUrlSafely
} from "./domainUtils.js";

const DNS_QUERY_TYPES = ["A", "AAAA", "NS", "MX"];
const DNS_TIMEOUT_MS = 5000;
const RDAP_TIMEOUT_MS = 7000;

export async function collectNetworkSignals(url) {
  const parsedUrl = parseUrlSafely(url);
  if (!parsedUrl) {
    return {
      ok: false,
      errors: ["URL не удалось разобрать для DNS/RDAP проверки."]
    };
  }

  const hostname = normalizeHostname(parsedUrl.hostname);
  const registrableDomain = getRegistrableDomain(hostname);
  const [dnsResult, rdapResult] = await Promise.allSettled([
    collectDnsSignals(hostname, registrableDomain),
    collectRdapSignals(registrableDomain)
  ]);

  return {
    ok: true,
    hostname,
    registrableDomain,
    dns:
      dnsResult.status === "fulfilled"
        ? dnsResult.value
        : { ok: false, errors: [dnsResult.reason?.message || "DNS lookup failed"] },
    rdap:
      rdapResult.status === "fulfilled"
        ? rdapResult.value
        : { ok: false, errors: [rdapResult.reason?.message || "RDAP lookup failed"] }
  };
}

async function collectDnsSignals(hostname, registrableDomain) {
  const queries = await Promise.allSettled(
    DNS_QUERY_TYPES.map((type) => queryDns(registrableDomain || hostname, type))
  );

  const byType = {};
  const errors = [];

  for (let index = 0; index < DNS_QUERY_TYPES.length; index += 1) {
    const type = DNS_QUERY_TYPES[index];
    const result = queries[index];

    if (result.status === "fulfilled") {
      byType[type] = result.value;
    } else {
      errors.push(`${type}: ${result.reason?.message || "lookup failed"}`);
    }
  }

  const addressRecords = [
    ...(byType.A?.answers || []),
    ...(byType.AAAA?.answers || [])
  ];
  const nsRecords = byType.NS?.answers || [];
  const mxRecords = byType.MX?.answers || [];
  const allAnswers = Object.values(byType).flatMap((item) => item.answers || []);
  const ttlValues = allAnswers
    .map((answer) => answer.TTL)
    .filter((ttl) => Number.isFinite(ttl));

  return {
    ok: errors.length < DNS_QUERY_TYPES.length,
    errors,
    hasAddress: addressRecords.length > 0,
    addressCount: addressRecords.length,
    hasNameServers: nsRecords.length > 0,
    nameServerCount: nsRecords.length,
    hasMx: mxRecords.length > 0,
    mxCount: mxRecords.length,
    minTtl: ttlValues.length ? Math.min(...ttlValues) : null,
    dnssecAuthenticated: Object.values(byType).some((item) => item.authenticated),
    statusCodes: Object.fromEntries(
      Object.entries(byType).map(([type, result]) => [type, result.status])
    )
  };
}

async function queryDns(name, type) {
  const queryUrl = new URL("https://cloudflare-dns.com/dns-query");
  queryUrl.searchParams.set("name", name);
  queryUrl.searchParams.set("type", type);

  const response = await fetchWithTimeout(queryUrl.href, DNS_TIMEOUT_MS, {
    accept: "application/dns-json"
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const payload = await response.json();

  return {
    status: payload.Status,
    authenticated: Boolean(payload.AD),
    answers: payload.Answer || []
  };
}

async function collectRdapSignals(registrableDomain) {
  if (!registrableDomain || /^\d/.test(registrableDomain)) {
    return {
      ok: false,
      errors: ["RDAP не применим к IP-адресу или пустому домену."]
    };
  }

  const response = await fetchWithTimeout(
    `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`,
    RDAP_TIMEOUT_MS,
    {
      accept: "application/rdap+json, application/json"
    }
  );

  if (!response.ok) {
    throw new Error(`RDAP HTTP ${response.status}`);
  }

  const payload = await response.json();
  const registrationDate = findEventDate(payload.events, [
    "registration",
    "registered"
  ]);
  const expirationDate = findEventDate(payload.events, ["expiration"]);
  const lastChangedDate = findEventDate(payload.events, ["last changed"]);
  const ageDays = registrationDate
    ? Math.floor((Date.now() - Date.parse(registrationDate)) / 86400000)
    : null;
  const lastChangedDays = lastChangedDate
    ? Math.floor((Date.now() - Date.parse(lastChangedDate)) / 86400000)
    : null;

  return {
    ok: true,
    registrationDate,
    expirationDate,
    lastChangedDate,
    ageDays,
    lastChangedDays,
    registrar: findRegistrar(payload.entities),
    nameserverCount: payload.nameservers?.length || 0,
    dnssecDelegationSigned: Boolean(payload.secureDNS?.delegationSigned),
    status: payload.status || []
  };
}

function findEventDate(events = [], actions) {
  const normalizedActions = new Set(actions);
  const event = events.find((item) =>
    normalizedActions.has(String(item.eventAction || "").toLowerCase())
  );

  return event?.eventDate || null;
}

function findRegistrar(entities = []) {
  const registrar = entities.find((entity) => entity.roles?.includes("registrar"));
  const vcardItems = registrar?.vcardArray?.[1];
  const nameItem = Array.isArray(vcardItems)
    ? vcardItems.find((item) => item?.[0] === "fn")
    : null;

  return nameItem?.[3] || null;
}

async function fetchWithTimeout(url, timeoutMs, headers) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      headers,
      signal: controller.signal,
      cache: "no-store"
    });
  } finally {
    clearTimeout(timeout);
  }
}
