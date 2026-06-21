import { extractUrlFeatures } from "./urlFeatureModel.js";
import { SITE_MODEL } from "./siteModelWeights.js";

export function predictSiteRisk(input, derivedSignals = {}) {
  const features = extractSiteFeatures(input, derivedSignals);
  if (!features) {
    return {
      ok: false,
      probability: 1,
      score: 100,
      modelVersion: SITE_MODEL.version,
      topFeatures: ["invalidUrl"]
    };
  }

  let logit = SITE_MODEL.intercept;
  const contributions = [];

  for (const [name, value] of Object.entries(features)) {
    const weight = SITE_MODEL.weights[name] || 0;
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
    modelVersion: SITE_MODEL.version,
    topFeatures: contributions
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 6)
      .map((item) => item.name)
  };
}

export function extractSiteFeatures(input, derivedSignals = {}) {
  const urlFeatures = extractUrlFeatures(input.url);
  if (!urlFeatures) {
    return null;
  }

  const sensitiveInputCount = Number(input.sensitiveInputCount || 0);
  const passwordFieldCount = Number(input.passwordFieldCount || 0);
  const formCount = Number(input.formCount || 0);
  const scriptCount = Number(input.scriptCount || 0);
  const iframeCount = Number(input.iframeCount || 0);
  const externalScriptCount = Number(input.externalScriptCount || 0);
  const externalIframeCount = Number(input.externalIframeCount || 0);
  const hiddenInputCount = Number(input.hiddenInputCount || 0);
  const externalLinkRatio = Number(input.externalLinkRatio || 0);
  const domainAgeDays = input.networkSignals?.rdap?.ageDays;
  const lastChangedDays = input.networkSignals?.rdap?.lastChangedDays;
  const minTtl = input.networkSignals?.dns?.minTtl;

  return {
    ...urlFeatures,
    hasPasswordField: input.hasPasswordField ? 1 : 0,
    multiplePasswordFields: passwordFieldCount >= 2 ? 1 : 0,
    manySensitiveInputs: sensitiveInputCount >= 4 ? 1 : 0,
    externalPasswordForm: Number(derivedSignals.externalPasswordFormHostCount || 0) > 0 ? 1 : 0,
    externalSensitiveForm:
      Number(derivedSignals.externalFormHostCount || 0) > 0 && Number(input.sensitiveFormCount || 0) > 0
        ? 1
        : 0,
    autocompleteOffSensitiveForm:
      Number(input.autocompleteOffFormCount || 0) > 0 &&
      (input.hasPasswordField || sensitiveInputCount >= 2)
        ? 1
        : 0,
    hasIframe: input.hasIframe ? 1 : 0,
    manyForms: formCount >= 3 ? 1 : 0,
    manyExternalIframes: iframeCount >= 2 && externalIframeCount >= 2 ? 1 : 0,
    highExternalLinkRatio:
      Number(input.linkCount || 0) >= 10 && externalLinkRatio >= 0.85 ? 1 : 0,
    highExternalScriptRatio:
      scriptCount >= 8 && externalScriptCount / Math.max(scriptCount, 1) >= 0.75 ? 1 : 0,
    manyHiddenSensitiveInputs:
      hiddenInputCount >= 20 && (input.hasPasswordField || sensitiveInputCount >= 2) ? 1 : 0,
    brandImpersonation: Number(derivedSignals.brandImpersonationCount || 0) > 0 ? 1 : 0,
    urgencyWithSensitive:
      Boolean(derivedSignals.hasUrgencyLanguage) &&
      (input.hasPasswordField || sensitiveInputCount >= 2)
        ? 1
        : 0,
    youngDomain7: Number.isFinite(domainAgeDays) && domainAgeDays < 7 ? 1 : 0,
    youngDomain30: Number.isFinite(domainAgeDays) && domainAgeDays >= 7 && domainAgeDays < 30 ? 1 : 0,
    youngDomain90: Number.isFinite(domainAgeDays) && domainAgeDays >= 30 && domainAgeDays < 90 ? 1 : 0,
    recentDomainChange7: Number.isFinite(lastChangedDays) && lastChangedDays < 7 ? 1 : 0,
    dnsNoAddress: input.networkSignals?.dns?.ok && !input.networkSignals.dns.hasAddress ? 1 : 0,
    dnsNoNameServers:
      input.networkSignals?.dns?.ok && !input.networkSignals.dns.hasNameServers ? 1 : 0,
    dnsShortTtl: input.networkSignals?.dns?.ok && Number.isFinite(minTtl) && minTtl <= 180 ? 1 : 0
  };
}
