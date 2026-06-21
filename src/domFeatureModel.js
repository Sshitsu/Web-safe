import { DOM_MODEL } from "./domModelWeights.js";

export function predictDomRisk(input, derivedSignals = {}) {
  const features = extractDomFeatures(input, derivedSignals);
  let logit = DOM_MODEL.intercept;
  const contributions = [];

  for (const [name, value] of Object.entries(features)) {
    const weight = DOM_MODEL.weights[name] || 0;
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
    modelVersion: DOM_MODEL.version,
    topFeatures: contributions
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 5)
      .map((item) => item.name)
  };
}

export function extractDomFeatures(input, derivedSignals = {}) {
  const sensitiveInputCount = Number(input.sensitiveInputCount || 0);
  const passwordFieldCount = Number(input.passwordFieldCount || 0);
  const formCount = Number(input.formCount || 0);
  const scriptCount = Number(input.scriptCount || 0);
  const iframeCount = Number(input.iframeCount || 0);
  const externalScriptCount = Number(input.externalScriptCount || 0);
  const externalIframeCount = Number(input.externalIframeCount || 0);
  const hiddenInputCount = Number(input.hiddenInputCount || 0);
  const externalLinkRatio = Number(input.externalLinkRatio || 0);

  return {
    hasPasswordField: input.hasPasswordField ? 1 : 0,
    multiplePasswordFields: passwordFieldCount >= 2 ? 1 : 0,
    manySensitiveInputs: sensitiveInputCount >= 4 ? 1 : 0,
    externalPasswordForm: Number(derivedSignals.externalPasswordFormHostCount || 0) > 0 ? 1 : 0,
    externalSensitiveForm:
      Number(derivedSignals.externalFormHostCount || 0) > 0 &&
      Number(input.sensitiveFormCount || 0) > 0
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
        : 0
  };
}
