import assert from "node:assert/strict";

import { extractDomFeatures, predictDomRisk } from "../src/domFeatureModel.js";
import { getRegistrableDomain } from "../src/domainUtils.js";
import { extractNetworkFeatures, predictNetworkRisk } from "../src/networkFeatureModel.js";
import { analyzeSite } from "../src/riskEngine.js";
import { predictUrlRisk } from "../src/urlFeatureModel.js";

const cleanThreatIntel = {
  checkedAt: Date.now(),
  isKnownPhishing: false,
  matches: [],
  sources: [],
  errors: []
};

const cleanSafeBrowsing = {
  ok: true,
  checked: true,
  configured: true,
  isUnsafe: false,
  matches: []
};

const stableNetworkSignals = {
  ok: true,
  dns: {
    ok: true,
    hasAddress: true,
    addressCount: 2,
    hasNameServers: true,
    nameServerCount: 2,
    minTtl: 300
  },
  rdap: {
    ok: true,
    ageDays: 5000,
    lastChangedDays: 300
  }
};

let passed = 0;

function test(name, fn) {
  fn();
  passed += 1;
  console.log(`PASS ${name}`);
}

test("URL model returns low score for a stable HTTPS domain", () => {
  const prediction = predictUrlRisk("https://google.com/");
  assert.equal(prediction.ok, true);
  assert.ok(prediction.score <= 20, `Expected <= 20, got ${prediction.score}`);
});

test("URL model returns high score for an IP login over HTTP", () => {
  const prediction = predictUrlRisk("http://192.168.0.1/login");
  assert.equal(prediction.ok, true);
  assert.ok(prediction.score >= 90, `Expected >= 90, got ${prediction.score}`);
});

test("Public Suffix List extracts registrable domain for co.uk", () => {
  assert.equal(getRegistrableDomain("shop.example.co.uk"), "example.co.uk");
});

test("DOM model extracts page-structure features", () => {
  const features = extractDomFeatures(
    {
      hasPasswordField: true,
      passwordFieldCount: 1,
      sensitiveInputCount: 4,
      formCount: 1,
      linkCount: 20,
      externalLinkRatio: 0.9,
      scriptCount: 10,
      externalScriptCount: 8
    },
    {
      brandImpersonationCount: 1,
      externalFormHostCount: 1,
      externalPasswordFormHostCount: 1,
      hasUrgencyLanguage: true
    }
  );

  assert.equal(features.externalPasswordForm, 1);
  assert.equal(features.highExternalLinkRatio, 1);
  assert.equal(features.highExternalScriptRatio, 1);
  assert.equal(features.brandImpersonation, 1);
  assert.equal(features.urgencyWithSensitive, 1);
});

test("DNS/RDAP model extracts network and registration features", () => {
  const features = extractNetworkFeatures({
    dns: {
      ok: true,
      hasAddress: false,
      hasNameServers: false,
      hasMx: false,
      minTtl: 120
    },
    rdap: {
      ok: true,
      ageDays: 5,
      lastChangedDays: 2
    }
  });

  assert.equal(features.youngDomain7, 1);
  assert.equal(features.recentDomainChange7, 1);
  assert.equal(features.dnsNoAddress, 1);
  assert.equal(features.dnsNoNameServers, 1);
  assert.equal(features.dnsShortTtl, 1);
  assert.equal(features.noMxRecord, 1);
});

test("DOM model scores a phishing-like page structure as high risk", () => {
  const prediction = predictDomRisk(
    {
      hasPasswordField: true,
      passwordFieldCount: 1,
      sensitiveInputCount: 4,
      formCount: 1,
      linkCount: 20,
      externalLinkRatio: 0.9,
      scriptCount: 10,
      externalScriptCount: 8
    },
    {
      brandImpersonationCount: 1,
      externalFormHostCount: 1,
      externalPasswordFormHostCount: 1,
      hasUrgencyLanguage: true
    }
  );

  assert.equal(prediction.ok, true);
  assert.ok(prediction.score >= 80, `Expected >= 80, got ${prediction.score}`);
  assert.ok(prediction.topFeatures.includes("externalPasswordForm"));
});

test("DNS/RDAP model scores a young unstable domain as high risk", () => {
  const prediction = predictNetworkRisk({
    dns: {
      ok: true,
      hasAddress: false,
      hasNameServers: false,
      hasMx: false,
      minTtl: 120
    },
    rdap: {
      ok: true,
      ageDays: 5,
      lastChangedDays: 2
    }
  });

  assert.equal(prediction.ok, true);
  assert.ok(prediction.score >= 80, `Expected >= 80, got ${prediction.score}`);
  assert.ok(prediction.topFeatures.includes("youngDomain7"));
});

test("Risk engine returns low risk for a stable benign page", () => {
  const result = analyzeSite({
    url: "https://google.com/",
    title: "Google",
    pageText: "Search the world's information",
    threatIntel: cleanThreatIntel,
    safeBrowsing: cleanSafeBrowsing,
    networkSignals: stableNetworkSignals
  });

  assert.ok(result.score < 40, `Expected score < 40, got ${result.score}`);
});

test("Risk engine returns high risk for IP login over HTTP", () => {
  const result = analyzeSite({
    url: "http://192.168.0.1/login",
    title: "Login",
    pageText: "Please login to verify account",
    hasPasswordField: true,
    passwordFieldCount: 1,
    sensitiveInputCount: 2,
    threatIntel: cleanThreatIntel,
    safeBrowsing: cleanSafeBrowsing,
    networkSignals: stableNetworkSignals
  });

  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
});

test("Risk engine detects brand impersonation and external password form", () => {
  const result = analyzeSite({
    url: "https://account-security-check.example/login",
    title: "Google Account security verification",
    pageText: "Urgent: confirm now to avoid account suspension.",
    hasPasswordField: true,
    formCount: 1,
    passwordFieldCount: 1,
    sensitiveInputCount: 3,
    hiddenInputCount: 1,
    formActionHosts: ["evil.example"],
    passwordFormActionHosts: ["evil.example"],
    autocompleteOffFormCount: 1,
    sensitiveFormCount: 1,
    threatIntel: cleanThreatIntel,
    safeBrowsing: cleanSafeBrowsing,
    networkSignals: stableNetworkSignals
  });

  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
  assert.ok(result.facts.domModelTopFeatures.includes("externalPasswordForm"));
});

test("Risk engine raises high risk for a threat feed match", () => {
  const result = analyzeSite({
    url: "https://example.com/",
    threatIntel: {
      checkedAt: Date.now(),
      isKnownPhishing: true,
      matches: [
        {
          source: "Test threat feed",
          type: "domain",
          value: "example.com"
        }
      ],
      sources: [{ ok: true }],
      errors: []
    },
    safeBrowsing: cleanSafeBrowsing,
    networkSignals: stableNetworkSignals
  });

  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
});

test("Risk engine raises high risk for unsafe Safe Browsing response", () => {
  const result = analyzeSite({
    url: "https://example.com/",
    threatIntel: cleanThreatIntel,
    safeBrowsing: {
      ok: true,
      checked: true,
      configured: true,
      isUnsafe: true,
      matches: [{ threatType: "SOCIAL_ENGINEERING" }]
    },
    networkSignals: stableNetworkSignals
  });

  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
});

test("Risk engine records DNS failure as a reason", () => {
  const result = analyzeSite({
    url: "https://example.com/",
    threatIntel: cleanThreatIntel,
    safeBrowsing: cleanSafeBrowsing,
    networkSignals: {
      ok: true,
      dns: {
        ok: true,
        hasAddress: false,
        addressCount: 0,
        hasNameServers: true,
        nameServerCount: 2,
        minTtl: 300
      },
      rdap: {
        ok: true,
        ageDays: 5000,
        lastChangedDays: 300
      }
    }
  });

  assert.ok(result.score > 0);
  assert.equal(result.facts.dnsAddressCount, 0);
});

console.log(`requiredPassed=${passed}`);
