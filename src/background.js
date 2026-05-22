import { collectNetworkSignals } from "./networkSignals.js";
import { analyzeSite } from "./riskEngine.js";
import { checkSafeBrowsing } from "./safeBrowsing.js";
import { getThreatIntel } from "./threatFeeds.js";

const extensionApi = globalThis.browser ?? globalThis.chrome;
const HISTORY_KEY = "webSafeAnalysisHistory";
const MAX_HISTORY_ITEMS = 10;

extensionApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ANALYZE_ACTIVE_TAB") {
    analyzeActiveTab()
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => {
        sendResponse({
          ok: false,
          error: error instanceof Error ? error.message : "Unknown error"
        });
      });

    return true;
  }

  if (message?.type === "GET_ANALYSIS_HISTORY") {
    getAnalysisHistory()
      .then((history) => sendResponse({ ok: true, history }))
      .catch((error) => {
        sendResponse({
          ok: false,
          error: error instanceof Error ? error.message : "Unknown error"
        });
      });

    return true;
  }

  if (message?.type === "CLEAR_ANALYSIS_HISTORY") {
    clearAnalysisHistory()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => {
        sendResponse({
          ok: false,
          error: error instanceof Error ? error.message : "Unknown error"
        });
      });

    return true;
  }
});

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

  const [injectionResult] = await extensionApi.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
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
      const inputSelector = [
        "input[type='email']",
        "input[type='password']",
        "input[type='tel']",
        "input[name*='card' i]",
        "input[id*='card' i]",
        "input[name*='cvv' i]",
        "input[id*='cvv' i]",
        "input[name*='pin' i]",
        "input[id*='pin' i]",
        "input[name*='code' i]",
        "input[id*='code' i]"
      ].join(",");
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
        sensitiveInputCount: form.querySelectorAll(inputSelector).length
      }));
      const externalLinks = links.filter((host) => host && host !== currentHost);
      const externalScripts = scripts.filter((host) => host && host !== currentHost);
      const externalIframes = iframes.filter((host) => host && host !== currentHost);

      return {
        title: document.title || "",
        pageText,
        hasPasswordField: Boolean(
          document.querySelector('input[type="password"]')
        ),
        hasIframe: document.querySelectorAll("iframe").length > 0,
        formCount: forms.length,
        passwordFieldCount: document.querySelectorAll("input[type='password']").length,
        sensitiveInputCount: document.querySelectorAll(inputSelector).length,
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
  });

  const pageSignals = injectionResult?.result || {};

  const [threatIntelResult, networkSignalsResult, safeBrowsingResult] = await Promise.allSettled([
    getThreatIntel(tab.url, extensionApi),
    collectNetworkSignals(tab.url),
    checkSafeBrowsing(tab.url)
  ]);

  const result = analyzeSite({
    url: tab.url,
    ...pageSignals,
    threatIntel:
      threatIntelResult.status === "fulfilled"
        ? threatIntelResult.value
        : {
            isKnownPhishing: false,
            matches: [],
            sources: [],
            errors: [threatIntelResult.reason?.message || "Ошибка проверки фидов."]
          },
    networkSignals:
      networkSignalsResult.status === "fulfilled"
        ? networkSignalsResult.value
        : {
            ok: false,
            errors: [networkSignalsResult.reason?.message || "Ошибка DNS/RDAP проверки."]
          },
    safeBrowsing:
      safeBrowsingResult.status === "fulfilled"
        ? safeBrowsingResult.value
        : {
            ok: false,
            checked: false,
            configured: false,
            isUnsafe: false,
            matches: [],
            error: safeBrowsingResult.reason?.message || "Ошибка Google Safe Browsing проверки."
          }
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
