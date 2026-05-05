const extensionApi = globalThis.browser ?? globalThis.chrome;

const analyzeButton = document.getElementById("analyzeButton");
const scoreValue = document.getElementById("scoreValue");
const scoreRing = document.getElementById("scoreRing");
const riskLabel = document.getElementById("riskLabel");
const hostname = document.getElementById("hostname");
const protocolValue = document.getElementById("protocolValue");
const tldValue = document.getElementById("tldValue");
const reasonsList = document.getElementById("reasonsList");

analyzeButton.addEventListener("click", async () => {
  setLoadingState(true);

  try {
    const response = await extensionApi.runtime.sendMessage({
      type: "ANALYZE_ACTIVE_TAB"
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Не удалось выполнить анализ.");
    }

    renderResult(response.result);
  } catch (error) {
    renderError(error instanceof Error ? error.message : "Ошибка анализа.");
  } finally {
    setLoadingState(false);
  }
});

function setLoadingState(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading
    ? "Проверяем сайт..."
    : "Проверить текущий сайт";
}

function renderResult(result) {
  scoreValue.textContent = String(result.score);
  riskLabel.textContent = result.label;
  hostname.textContent = result.facts.hostname;
  protocolValue.textContent = result.facts.protocol.toUpperCase();
  tldValue.textContent = result.facts.tld ? `.${result.facts.tld}` : "-";
  renderReasons(result.reasons);
  updateScoreRing(result.score);
}

function renderError(message) {
  scoreValue.textContent = "!!";
  riskLabel.textContent = "Ошибка";
  hostname.textContent = message;
  protocolValue.textContent = "-";
  tldValue.textContent = "-";
  renderReasons([message]);
  scoreRing.style.background = "conic-gradient(#777 360deg, #d9d9d9 0deg)";
}

function renderReasons(reasons) {
  reasonsList.innerHTML = "";
  for (const reason of reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonsList.appendChild(li);
  }
}

function updateScoreRing(score) {
  const degrees = Math.round((score / 100) * 360);
  const color = score >= 70 ? "#cf3f2e" : score >= 40 ? "#d48b17" : "#2f8f5b";
  scoreRing.style.background = `conic-gradient(${color} ${degrees}deg, #dfdfdf 0deg)`;
}
