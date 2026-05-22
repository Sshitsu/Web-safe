const extensionApi = globalThis.browser ?? globalThis.chrome;

const analyzeButton = document.getElementById("analyzeButton");
const scoreValue = document.getElementById("scoreValue");
const scoreRing = document.getElementById("scoreRing");
const riskLabel = document.getElementById("riskLabel");
const hostname = document.getElementById("hostname");
const protocolValue = document.getElementById("protocolValue");
const tldValue = document.getElementById("tldValue");
const threatValue = document.getElementById("threatValue");
const safeBrowsingValue = document.getElementById("safeBrowsingValue");
const domainAgeValue = document.getElementById("domainAgeValue");
const modelValue = document.getElementById("modelValue");
const pageSignalsValue = document.getElementById("pageSignalsValue");
const dnsValue = document.getElementById("dnsValue");
const reasonsList = document.getElementById("reasonsList");
const historyList = document.getElementById("historyList");
const clearHistoryButton = document.getElementById("clearHistoryButton");

analyzeButton.addEventListener("click", runAnalysis);
clearHistoryButton.addEventListener("click", clearHistory);

loadHistory();
runAnalysis();

async function runAnalysis() {
  setLoadingState(true);

  try {
    const response = await extensionApi.runtime.sendMessage({
      type: "ANALYZE_ACTIVE_TAB"
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Не удалось выполнить анализ.");
    }

    renderResult(response.result);
    await loadHistory();
  } catch (error) {
    renderError(error instanceof Error ? error.message : "Ошибка анализа.");
  } finally {
    setLoadingState(false);
  }
}

async function loadHistory() {
  try {
    const response = await extensionApi.runtime.sendMessage({
      type: "GET_ANALYSIS_HISTORY"
    });

    renderHistory(response?.ok ? response.history : []);
  } catch (error) {
    renderHistory([]);
  }
}

async function clearHistory() {
  clearHistoryButton.disabled = true;

  try {
    await extensionApi.runtime.sendMessage({
      type: "CLEAR_ANALYSIS_HISTORY"
    });
    renderHistory([]);
  } finally {
    clearHistoryButton.disabled = false;
  }
}

function setLoadingState(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading
    ? "Проверяем сайт..."
    : "Повторить проверку";
}

function renderResult(result) {
  scoreValue.textContent = String(result.score);
  riskLabel.textContent = result.label;
  hostname.textContent = result.facts.hostname;
  protocolValue.textContent = result.facts.protocol.toUpperCase();
  tldValue.textContent = result.facts.tld ? `.${result.facts.tld}` : "-";
  threatValue.textContent = result.facts.threatMatches
    ? `${result.facts.threatMatches} совп.`
    : `${result.facts.threatSources || 0} ист.`;
  safeBrowsingValue.textContent = formatSafeBrowsingStatus(
    result.facts.safeBrowsingStatus,
    result.facts.safeBrowsingMatches
  );
  domainAgeValue.textContent = formatDomainAge(result.facts.domainAgeDays);
  modelValue.textContent = Number.isFinite(result.facts.urlModelScore)
    ? `${result.facts.urlModelScore}%`
    : "-";
  pageSignalsValue.textContent = formatPageSignals(result.facts);
  dnsValue.textContent = Number.isFinite(result.facts.dnsAddressCount)
    ? String(result.facts.dnsAddressCount)
    : "-";
  renderReasons(result.reasons);
  updateScoreRing(result.score);
}

function renderError(message) {
  scoreValue.textContent = "!!";
  riskLabel.textContent = "Ошибка";
  hostname.textContent = message;
  protocolValue.textContent = "-";
  tldValue.textContent = "-";
  threatValue.textContent = "-";
  safeBrowsingValue.textContent = "-";
  domainAgeValue.textContent = "-";
  modelValue.textContent = "-";
  pageSignalsValue.textContent = "-";
  dnsValue.textContent = "-";
  renderReasons([message]);
  scoreRing.style.background = "conic-gradient(#777 360deg, #d9d9d9 0deg)";
}

function renderReasons(reasons) {
  reasonsList.replaceChildren();
  for (const reason of reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonsList.appendChild(li);
  }
}

function renderHistory(history) {
  historyList.replaceChildren();
  clearHistoryButton.disabled = history.length === 0;

  if (history.length === 0) {
    const li = document.createElement("li");
    li.className = "empty-state";
    li.textContent = "Проверок пока нет.";
    historyList.appendChild(li);
    return;
  }

  for (const item of history.slice(0, 5)) {
    const li = document.createElement("li");
    li.className = "history-item";

    const score = document.createElement("span");
    score.className = `history-score ${getRiskClass(item.score)}`;
    score.textContent = String(item.score);

    const copy = document.createElement("span");
    const host = document.createElement("strong");
    host.className = "history-host";
    host.textContent = item.hostname || item.url;

    const meta = document.createElement("span");
    meta.className = "history-meta";
    meta.textContent = `${item.label} · ${formatRelativeTime(item.checkedAt)}`;

    copy.append(host, meta);
    li.append(score, copy);
    historyList.appendChild(li);
  }
}

function updateScoreRing(score) {
  const degrees = Math.round((score / 100) * 360);
  const color = score >= 70 ? "#cf3f2e" : score >= 40 ? "#d48b17" : "#2f8f5b";
  scoreRing.style.background = `conic-gradient(${color} ${degrees}deg, #dfdfdf 0deg)`;
}

function getRiskClass(score) {
  if (score >= 70) {
    return "danger";
  }

  if (score >= 40) {
    return "medium";
  }

  return "safe";
}

function formatDomainAge(days) {
  if (!Number.isFinite(days)) {
    return "нет данных";
  }

  if (days < 1) {
    return "сегодня";
  }

  if (days < 31) {
    return `${days} дн.`;
  }

  if (days < 365) {
    return `${Math.round(days / 30)} мес.`;
  }

  return `${(days / 365).toFixed(1)} г.`;
}

function formatSafeBrowsingStatus(status, matches) {
  if (status === "unsafe") {
    return `${matches || 1} совп.`;
  }

  if (status === "clean") {
    return "чисто";
  }

  if (status === "not_configured") {
    return "нет ключа";
  }

  return "недоступно";
}

function formatPageSignals(facts) {
  if (facts.brandMatches?.length) {
    return "бренд";
  }

  if (facts.externalFormHosts?.length) {
    return "внеш. форма";
  }

  if (facts.sensitiveInputCount > 0) {
    return `${facts.sensitiveInputCount} полей`;
  }

  if (Number.isFinite(facts.externalLinkRatio) && facts.externalLinkRatio >= 85) {
    return `${facts.externalLinkRatio}% внеш.`;
  }

  return "норма";
}

function formatRelativeTime(timestamp) {
  const diffMs = Date.now() - timestamp;
  const diffMinutes = Math.max(0, Math.floor(diffMs / 60000));

  if (diffMinutes < 1) {
    return "только что";
  }

  if (diffMinutes < 60) {
    return `${diffMinutes} мин. назад`;
  }

  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours} ч. назад`;
  }

  return `${Math.floor(diffHours / 24)} дн. назад`;
}
