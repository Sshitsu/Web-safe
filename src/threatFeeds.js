import {
  getDomainCandidates,
  normalizeHostname,
  normalizeUrlForMatch,
  parseUrlSafely
} from "./domainUtils.js";

const CACHE_KEY = "webSafeThreatFeeds";
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;

const FEEDS = [
  {
    id: "openphish",
    name: "OpenPhish Community Feed",
    url: "https://openphish.com/feed.txt",
    type: "url"
  },
  {
    id: "phishingDatabaseDomains",
    name: "Phishing.Database active domains",
    url: "https://phish.co.za/latest/phishing-domains-ACTIVE.txt",
    type: "domain"
  }
];

let memoryCache = null;

export async function getThreatIntel(url, extensionApi) {
  const parsedUrl = parseUrlSafely(url);
  if (!parsedUrl) {
    return emptyThreatIntel("URL не удалось разобрать для проверки по базам.");
  }

  const cache = await getFreshFeedCache(extensionApi);
  const normalizedUrl = normalizeUrlForMatch(url);
  const hostname = normalizeHostname(parsedUrl.hostname);
  const domainCandidates = getDomainCandidates(hostname);
  const matches = [];

  for (const feed of cache.feeds) {
    if (feed.type === "url") {
      if (feed.urlSet.has(normalizedUrl)) {
        matches.push({
          source: feed.name,
          type: "url",
          value: normalizedUrl
        });
      }

      for (const candidate of domainCandidates) {
        if (feed.domainSet.has(candidate)) {
          matches.push({
            source: feed.name,
            type: "domain",
            value: candidate
          });
          break;
        }
      }
    }

    if (feed.type === "domain") {
      for (const candidate of domainCandidates) {
        if (feed.domainSet.has(candidate)) {
          matches.push({
            source: feed.name,
            type: "domain",
            value: candidate
          });
          break;
        }
      }
    }
  }

  return {
    checkedAt: Date.now(),
    isKnownPhishing: matches.length > 0,
    matches,
    sources: cache.sources,
    errors: cache.errors
  };
}

function emptyThreatIntel(message) {
  return {
    checkedAt: Date.now(),
    isKnownPhishing: false,
    matches: [],
    sources: [],
    errors: [message]
  };
}

async function getFreshFeedCache(extensionApi) {
  if (memoryCache && Date.now() - memoryCache.updatedAt < CACHE_TTL_MS) {
    return memoryCache;
  }

  const stored = await storageGet(extensionApi, CACHE_KEY);
  const storedCache = stored?.[CACHE_KEY];

  if (storedCache && Date.now() - storedCache.updatedAt < CACHE_TTL_MS) {
    memoryCache = hydrateCache(storedCache);
    return memoryCache;
  }

  const downloaded = await downloadFeeds();
  memoryCache = hydrateCache(downloaded);

  try {
    await storageSet(extensionApi, {
      [CACHE_KEY]: downloaded
    });
  } catch (error) {
    memoryCache.errors.push(
      `Кэш фидов не сохранен: ${error?.message || "storage error"}`
    );
  }

  return memoryCache;
}

async function downloadFeeds() {
  const results = await Promise.allSettled(FEEDS.map(downloadFeed));
  const feeds = [];
  const sources = [];
  const errors = [];

  for (let index = 0; index < results.length; index += 1) {
    const feed = FEEDS[index];
    const result = results[index];

    if (result.status === "fulfilled") {
      feeds.push(result.value);
      sources.push({
        id: feed.id,
        name: feed.name,
        count: result.value.items.length,
        updatedAt: Date.now(),
        ok: true
      });
    } else {
      errors.push(`${feed.name}: ${result.reason?.message || "не удалось загрузить"}`);
      sources.push({
        id: feed.id,
        name: feed.name,
        count: 0,
        updatedAt: Date.now(),
        ok: false
      });
    }
  }

  return {
    updatedAt: Date.now(),
    feeds,
    sources,
    errors
  };
}

async function downloadFeed(feed) {
  const response = await fetchWithTimeout(feed.url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const text = await response.text();
  const items = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));

  return {
    id: feed.id,
    name: feed.name,
    type: feed.type,
    items
  };
}

async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    return await fetch(url, {
      signal: controller.signal,
      cache: "no-store"
    });
  } finally {
    clearTimeout(timeout);
  }
}

function hydrateCache(cache) {
  return {
    updatedAt: cache.updatedAt,
    sources: cache.sources || [],
    errors: cache.errors || [],
    feeds: (cache.feeds || []).map((feed) => {
      const domainSet = new Set();
      const urlSet = new Set();

      for (const item of feed.items || []) {
        if (feed.type === "url") {
          const normalizedUrl = normalizeUrlForMatch(item);
          if (normalizedUrl) {
            urlSet.add(normalizedUrl);
          }

          const parsedUrl = parseUrlSafely(item);
          if (parsedUrl) {
            domainSet.add(normalizeHostname(parsedUrl.hostname));
          }
        } else {
          domainSet.add(normalizeHostname(item));
        }
      }

      return {
        ...feed,
        domainSet,
        urlSet
      };
    })
  };
}

function storageGet(extensionApi, key) {
  const result = extensionApi.storage.local.get(key);
  if (result && typeof result.then === "function") {
    return result;
  }

  return new Promise((resolve) => {
    extensionApi.storage.local.get(key, resolve);
  });
}

function storageSet(extensionApi, value) {
  const result = extensionApi.storage.local.set(value);
  if (result && typeof result.then === "function") {
    return result;
  }

  return new Promise((resolve) => {
    extensionApi.storage.local.set(value, resolve);
  });
}
