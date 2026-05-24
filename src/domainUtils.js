import { PUBLIC_SUFFIX_RULES } from "./publicSuffixData.js";

const EXACT_PUBLIC_SUFFIXES = new Set(PUBLIC_SUFFIX_RULES.exact);
const WILDCARD_PUBLIC_SUFFIXES = new Set(PUBLIC_SUFFIX_RULES.wildcard);
const EXCEPTION_PUBLIC_SUFFIXES = new Set(PUBLIC_SUFFIX_RULES.exception);

export function parseUrlSafely(url) {
  try {
    return new URL(url);
  } catch (error) {
    return null;
  }
}

export function normalizeHostname(hostname = "") {
  return hostname.toLowerCase().replace(/\.$/, "");
}

export function isIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

export function getTld(hostname) {
  const parts = normalizeHostname(hostname).split(".").filter(Boolean);
  return parts[parts.length - 1] || "";
}

export function getHostnameDepth(hostname) {
  return normalizeHostname(hostname).split(".").filter(Boolean).length;
}

export function hasPunycode(hostname) {
  return normalizeHostname(hostname).includes("xn--");
}

export function getRegistrableDomain(hostname) {
  const normalized = normalizeHostname(hostname);
  if (!normalized || isIpAddress(normalized)) {
    return normalized;
  }

  const parts = normalized.split(".").filter(Boolean);
  const publicSuffixLabelCount = getPublicSuffixLabelCount(parts);

  if (parts.length <= publicSuffixLabelCount) {
    return normalized;
  }

  return parts.slice(-(publicSuffixLabelCount + 1)).join(".");
}

export function getDomainCandidates(hostname) {
  const normalized = normalizeHostname(hostname);
  const parts = normalized.split(".").filter(Boolean);
  const candidates = new Set();

  for (let index = 0; index < parts.length - 1; index += 1) {
    candidates.add(parts.slice(index).join("."));
  }

  if (normalized.startsWith("www.")) {
    candidates.add(normalized.slice(4));
  }

  const registrableDomain = getRegistrableDomain(normalized);
  if (registrableDomain) {
    candidates.add(registrableDomain);
  }

  return [...candidates];
}

export function getPublicSuffix(hostname) {
  const normalized = normalizeHostname(hostname);
  if (!normalized || isIpAddress(normalized)) {
    return normalized;
  }

  const parts = normalized.split(".").filter(Boolean);
  const labelCount = getPublicSuffixLabelCount(parts);

  return parts.slice(-labelCount).join(".");
}

export function normalizeUrlForMatch(url) {
  const parsedUrl = parseUrlSafely(url);
  if (!parsedUrl) {
    return "";
  }

  parsedUrl.hash = "";
  parsedUrl.hostname = normalizeHostname(parsedUrl.hostname);

  if (parsedUrl.pathname !== "/" && parsedUrl.pathname.endsWith("/")) {
    parsedUrl.pathname = parsedUrl.pathname.slice(0, -1);
  }

  return parsedUrl.href.toLowerCase();
}

function getPublicSuffixLabelCount(parts) {
  if (parts.length === 0) {
    return 0;
  }

  let bestMatchLabelCount = 1;

  for (let index = 0; index < parts.length; index += 1) {
    const candidate = parts.slice(index).join(".");

    if (EXCEPTION_PUBLIC_SUFFIXES.has(candidate)) {
      return Math.max(1, parts.length - index - 1);
    }

    if (EXACT_PUBLIC_SUFFIXES.has(candidate)) {
      bestMatchLabelCount = Math.max(bestMatchLabelCount, parts.length - index);
    }

    if (index < parts.length - 1) {
      const wildcardCandidate = parts.slice(index + 1).join(".");
      if (WILDCARD_PUBLIC_SUFFIXES.has(wildcardCandidate)) {
        bestMatchLabelCount = Math.max(bestMatchLabelCount, parts.length - index);
      }
    }
  }

  return bestMatchLabelCount;
}
