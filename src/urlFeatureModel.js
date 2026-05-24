import {
  getHostnameDepth,
  hasPunycode,
  isIpAddress,
  parseUrlSafely
} from "./domainUtils.js";
import { URL_MODEL } from "./urlModelWeights.js";

const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "wallet",
  "banking",
  "signin",
  "support",
  "bonus",
  "gift",
  "crypto",
  "airdrop",
  "free",
  "recovery",
  "confirm",
  "limited",
  "unlock"
];

export function predictUrlRisk(url) {
  const features = extractUrlFeatures(url);
  if (!features) {
    return {
      ok: false,
      probability: 1,
      score: 100,
      modelVersion: URL_MODEL.version,
      topFeatures: ["invalidUrl"]
    };
  }

  let logit = URL_MODEL.intercept;
  const contributions = [];

  for (const [name, value] of Object.entries(features)) {
    const weight = URL_MODEL.weights[name] || 0;
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
    modelVersion: URL_MODEL.version,
    topFeatures: contributions
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 4)
      .map((item) => item.name)
  };
}

export function extractUrlFeatures(url) {
  const parsedUrl = parseUrlSafely(url);
  if (!parsedUrl) {
    return null;
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const pathSegments = parsedUrl.pathname.split("/").filter(Boolean);
  const digitCount = (parsedUrl.href.match(/\d/g) || []).length;
  const keywordCount = SUSPICIOUS_KEYWORDS.filter((keyword) =>
    parsedUrl.href.toLowerCase().includes(keyword)
  ).length;

  return {
    noHttps: parsedUrl.protocol !== "https:" ? 1 : 0,
    hasIpAddress: isIpAddress(hostname) ? 1 : 0,
    hasPunycode: hasPunycode(hostname) ? 1 : 0,
    longUrl: parsedUrl.href.length > 90 ? 1 : 0,
    veryLongUrl: parsedUrl.href.length > 140 ? 1 : 0,
    manyDots: getHostnameDepth(hostname) >= 4 ? 1 : 0,
    manyHyphens: (hostname.match(/-/g) || []).length >= 2 ? 1 : 0,
    highDigitRatio: digitCount / Math.max(parsedUrl.href.length, 1) > 0.12 ? 1 : 0,
    suspiciousKeywordCount: Math.min(keywordCount, 4),
    encodedCharacters: /%[0-9a-f]{2}/i.test(parsedUrl.href) ? 1 : 0,
    hasAtSymbol: parsedUrl.href.includes("@") ? 1 : 0,
    deepPath: pathSegments.length >= 4 ? 1 : 0,
    highEntropyHostname: calculateEntropy(hostname.replace(/\./g, "")) > 3.8 ? 1 : 0
  };
}

function calculateEntropy(text) {
  if (!text) {
    return 0;
  }

  const counts = new Map();
  for (const char of text) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / text.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}
