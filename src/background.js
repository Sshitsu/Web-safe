import { collectNetworkSignals } from "./networkSignals.js";
import { analyzeSite } from "./riskEngine.js";
import { checkSafeBrowsing } from "./safeBrowsing.js";
import { getThreatIntel } from "./threatFeeds.js";

const extensionApi = globalThis.browser ?? globalThis.chrome;
const HISTORY_KEY = "webSafeAnalysisHistory";
const MAX_HISTORY_ITEMS = 10;
const PAGE_SIGNAL_TIMEOUT_MS = 4000;
const THREAT_FEED_TIMEOUT_MS = 9000;
const NETWORK_SIGNAL_TIMEOUT_MS = 9000;
const SAFE_BROWSING_TIMEOUT_MS = 4500;
const usesPromiseRuntime =
  typeof globalThis.browser !== "undefined" && extensionApi === globalThis.browser;

extensionApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const responsePromise = handleRuntimeMessage(message);

  if (!responsePromise) {
    return false;
  }

  if (usesPromiseRuntime) {
    return responsePromise;
  }

  responsePromise.then(sendResponse);
  return true;
});

function handleRuntimeMessage(message) {
  if (message?.type === "ANALYZE_ACTIVE_TAB") {
    return analyzeActiveTab()
      .then((result) => ({ ok: true, result }))
      .catch((error) => ({ ok: false, error: getErrorMessage(error) }));
  }

  if (message?.type === "GET_ANALYSIS_HISTORY") {
    return getAnalysisHistory()
      .then((history) => ({ ok: true, history }))
      .catch((error) => ({ ok: false, error: getErrorMessage(error) }));
  }

  if (message?.type === "CLEAR_ANALYSIS_HISTORY") {
    return clearAnalysisHistory()
      .then(() => ({ ok: true }))
      .catch((error) => ({ ok: false, error: getErrorMessage(error) }));
  }

  return null;
}

async function analyzeActiveTab() {
  const [tab] = await extensionApi.tabs.query({
    active: true,
    currentWindow: true
  });

  if (!tab?.id || !tab.url) {
    throw new Error("Не удалось получить активную вкладку.");
  }

  if (!/^https?:/.test(tab.url)) {
    throw new Error("Расширение анализирует только обычные веб-страницы.");
  }

  const threatIntelPromise = withTimeout(
    getThreatIntel(tab.url, extensionApi),
    THREAT_FEED_TIMEOUT_MS,
    (error) => createThreatIntelFallback(error, "Проверка фидов заняла слишком много времени.")
  );
  const networkSignalsPromise = withTimeout(
    collectNetworkSignals(tab.url),
    NETWORK_SIGNAL_TIMEOUT_MS,
    (error) => createNetworkSignalsFallback(error, "DNS/RDAP проверка заняла слишком много времени.")
  );
  const safeBrowsingPromise = withTimeout(
    checkSafeBrowsing(tab.url),
    SAFE_BROWSING_TIMEOUT_MS,
    (error) => createSafeBrowsingFallback(error, "Google Safe Browsing backend не ответил вовремя.")
  );

  const [injectionResult] = await withTimeout(
    extensionApi.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectPageSignals
    }),
    PAGE_SIGNAL_TIMEOUT_MS,
    () => []
  );

  const pageSignals = injectionResult?.result || {};

  const [threatIntel, networkSignals, safeBrowsing] = await Promise.all([
    threatIntelPromise,
    networkSignalsPromise,
    safeBrowsingPromise
  ]);

  const result = analyzeSite({
    url: tab.url,
    ...pageSignals,
    threatIntel,
    networkSignals,
    safeBrowsing
  });

  const checkedAt = Date.now();
  const enrichedResult = {
    ...result,
    checkedAt,
    url: tab.url
  };

  await saveAnalysisHistory(enrichedResult);
  updateActionBadge(tab.id, enrichedResult);

  return enrichedResult;
}

function collectPageSignals() {
  const bodyText = document.body?.innerText || "";
  const pageText = bodyText.replace(/\s+/g, " ").trim().slice(0, 1500);
  const currentHost = location.hostname.toLowerCase();
  const readHost = (value) => {
    try {
      return new URL(value, location.href).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  };
  const sensitiveInputKeywords = ["card", "cvv", "pin", "code"];
  const isSensitiveInput = (input) => {
    const type = (input.getAttribute("type") || "").toLowerCase();
    if (["email", "password", "tel"].includes(type)) {
      return true;
    }

    const markers = `${input.getAttribute("name") || ""} ${input.id || ""}`.toLowerCase();
    return sensitiveInputKeywords.some((keyword) => markers.includes(keyword));
  };
  const countSensitiveInputs = (root) =>
    [...root.querySelectorAll("input")].filter(isSensitiveInput).length;
  const links = [...document.querySelectorAll("a[href]")].map((link) =>
    readHost(link.href)
  );
  const scripts = [...document.querySelectorAll("script[src]")].map((script) =>
    readHost(script.src)
  );
  const iframes = [...document.querySelectorAll("iframe[src]")].map((iframe) =>
    readHost(iframe.src)
  );
  const forms = [...document.querySelectorAll("form")].map((form) => ({
    actionHost: readHost(form.getAttribute("action") || location.href),
    autocomplete: form.getAttribute("autocomplete") || "",
    hasPasswordField: Boolean(form.querySelector("input[type='password']")),
    sensitiveInputCount: countSensitiveInputs(form)
  }));
  const externalLinks = links.filter((host) => host && host !== currentHost);
  const externalScripts = scripts.filter((host) => host && host !== currentHost);
  const externalIframes = iframes.filter((host) => host && host !== currentHost);

  return {
    title: document.title || "",
    pageText,
    hasPasswordField: Boolean(document.querySelector('input[type="password"]')),
    hasIframe: document.querySelectorAll("iframe").length > 0,
    formCount: forms.length,
    passwordFieldCount: document.querySelectorAll("input[type='password']").length,
    sensitiveInputCount: countSensitiveInputs(document),
    hiddenInputCount: document.querySelectorAll("input[type='hidden']").length,
    linkCount: links.length,
    scriptCount: scripts.length,
    iframeCount: iframes.length,
    externalLinkRatio: links.length ? externalLinks.length / links.length : 0,
    externalScriptCount: externalScripts.length,
    externalIframeCount: externalIframes.length,
    formActionHosts: [...new Set(forms.map((form) => form.actionHost).filter(Boolean))],
    passwordFormActionHosts: [
      ...new Set(
        forms
          .filter((form) => form.hasPasswordField)
          .map((form) => form.actionHost)
          .filter(Boolean)
      )
    ],
    autocompleteOffFormCount: forms.filter(
      (form) => form.autocomplete.toLowerCase() === "off"
    ).length,
    sensitiveFormCount: forms.filter((form) => form.sensitiveInputCount >= 2).length
  };
}

async function getAnalysisHistory() {
  const stored = await storageGet(HISTORY_KEY);
  return stored?.[HISTORY_KEY] || [];
}

async function saveAnalysisHistory(result) {
  const history = await getAnalysisHistory();
  const item = {
    checkedAt: result.checkedAt,
    url: result.url,
    hostname: result.facts.hostname,
    score: result.score,
    label: result.label,
    threatMatches: result.facts.threatMatches,
    safeBrowsingStatus: result.facts.safeBrowsingStatus,
    domainAgeDays: result.facts.domainAgeDays,
    urlModelScore: result.facts.urlModelScore
  };

  const nextHistory = [
    item,
    ...history.filter((historyItem) => historyItem.url !== result.url)
  ].slice(0, MAX_HISTORY_ITEMS);

  await storageSet({
    [HISTORY_KEY]: nextHistory
  });
}

async function clearAnalysisHistory() {
  await storageSet({
    [HISTORY_KEY]: []
  });
}

function updateActionBadge(tabId, result) {
  if (!extensionApi.action) {
    return;
  }

  const color = result.score >= 70 ? "#cf3f2e" : result.score >= 40 ? "#d48b17" : "#2f8f5b";
  const text = result.score >= 70 ? "!" : String(result.score);

  try {
    extensionApi.action.setBadgeText({
      tabId,
      text
    });
    extensionApi.action.setBadgeBackgroundColor({
      tabId,
      color
    });
  } catch (error) {
    // Some browsers expose action APIs with small differences. The popup still shows the result.
  }
}

function withTimeout(promise, timeoutMs, fallbackFactory) {
  let settled = false;

  return new Promise((resolve) => {
    const timeoutId = setTimeout(() => {
      if (settled) {
        return;
      }

      settled = true;
      resolve(fallbackFactory(new Error("timeout")));
    }, timeoutMs);

    Promise.resolve(promise)
      .then((value) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutId);
        resolve(value);
      })
      .catch((error) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutId);
        resolve(fallbackFactory(error));
      });
  });
}

function createThreatIntelFallback(error, fallbackMessage) {
  return {
    checkedAt: Date.now(),
    isKnownPhishing: false,
    matches: [],
    sources: [],
    errors: [getErrorMessage(error, fallbackMessage)]
  };
}

function createNetworkSignalsFallback(error, fallbackMessage) {
  return {
    ok: false,
    errors: [getErrorMessage(error, fallbackMessage)]
  };
}

function createSafeBrowsingFallback(error, fallbackMessage) {
  return {
    ok: false,
    checked: false,
    configured: false,
    isUnsafe: false,
    matches: [],
    error: getErrorMessage(error, fallbackMessage)
  };
}

function getErrorMessage(error, fallback = "Unknown error") {
  if (error instanceof Error && error.message && error.message !== "timeout") {
    return error.message;
  }

  return fallback;
}

function storageGet(key) {
  const result = extensionApi.storage.local.get(key);
  if (result && typeof result.then === "function") {
    return result;
  }

  return new Promise((resolve) => {
    extensionApi.storage.local.get(key, resolve);
  });
}

function storageSet(value) {
  const result = extensionApi.storage.local.set(value);
  if (result && typeof result.then === "function") {
    return result;
  }

  return new Promise((resolve) => {
    extensionApi.storage.local.set(value, resolve);
  });
}
