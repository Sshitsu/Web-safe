import { NETWORK_MODEL } from "./networkModelWeights.js";

export function predictNetworkRisk(networkSignals) {
  const features = extractNetworkFeatures(networkSignals);
  let logit = NETWORK_MODEL.intercept;
  const contributions = [];

  for (const [name, value] of Object.entries(features)) {
    const weight = NETWORK_MODEL.weights[name] || 0;
    const contribution = weight * value;
    logit += contribution;

    if (value > 0 && weight > 0) {
      contributions.push({
        name,
        contribution
      });
    }
  }

  const probability = 1 / (1 + Math.exp(-logit));

  return {
    ok: true,
    probability,
    score: Math.round(probability * 100),
    modelVersion: NETWORK_MODEL.version,
    topFeatures: contributions
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 5)
      .map((item) => item.name)
  };
}

export function extractNetworkFeatures(networkSignals) {
  const dns = networkSignals?.dns;
  const rdap = networkSignals?.rdap;
  const domainAgeDays = rdap?.ageDays;
  const lastChangedDays = rdap?.lastChangedDays;
  const minTtl = dns?.minTtl;

  return {
    youngDomain7: Number.isFinite(domainAgeDays) && domainAgeDays < 7 ? 1 : 0,
    youngDomain30: Number.isFinite(domainAgeDays) && domainAgeDays >= 7 && domainAgeDays < 30 ? 1 : 0,
    youngDomain90: Number.isFinite(domainAgeDays) && domainAgeDays >= 30 && domainAgeDays < 90 ? 1 : 0,
    recentDomainChange7: Number.isFinite(lastChangedDays) && lastChangedDays < 7 ? 1 : 0,
    dnsNoAddress: dns?.ok && !dns.hasAddress ? 1 : 0,
    dnsNoNameServers: dns?.ok && !dns.hasNameServers ? 1 : 0,
    dnsShortTtl: dns?.ok && Number.isFinite(minTtl) && minTtl <= 180 ? 1 : 0,
    dnsUnavailable: networkSignals ? (dns?.ok === false ? 1 : 0) : 0,
    rdapUnavailable: networkSignals ? (rdap?.ok === false ? 1 : 0) : 0,
    noMxRecord: dns?.ok && !dns.hasMx ? 1 : 0
  };
}
