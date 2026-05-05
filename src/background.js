const extensionApi = globalThis.browser ?? globalThis.chrome;

import { analyzeSite } from "./riskEngine.js";

extensionApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "ANALYZE_ACTIVE_TAB") {
    return;
  }

  analyzeActiveTab()
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => {
      sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : "Unknown error"
      });
    });

  return true;
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

      return {
        title: document.title || "",
        pageText,
        hasPasswordField: Boolean(
          document.querySelector('input[type="password"]')
        ),
        hasIframe: document.querySelectorAll("iframe").length > 0,
        formCount: document.querySelectorAll("form").length
      };
    }
  });

  const pageSignals = injectionResult?.result || {};

  return analyzeSite({
    url: tab.url,
    ...pageSignals
  });
}
