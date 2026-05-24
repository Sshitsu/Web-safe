const DEFAULT_BACKEND_URL = "http://127.0.0.1:8787";
const REQUEST_TIMEOUT_MS = 3500;

export async function checkSafeBrowsing(url, options = {}) {
  const backendUrl = (options.backendUrl || DEFAULT_BACKEND_URL).replace(/\/$/, "");

  try {
    const response = await fetchWithTimeout(`${backendUrl}/safe-browsing/check`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Backend HTTP ${response.status}`);
    }

    const payload = await response.json();

    return {
      ok: Boolean(payload.ok),
      checked: Boolean(payload.checked),
      configured: Boolean(payload.configured),
      isUnsafe: Boolean(payload.isUnsafe),
      matches: payload.matches || [],
      source: "Google Safe Browsing",
      backendUrl
    };
  } catch (error) {
    return {
      ok: false,
      checked: false,
      configured: false,
      isUnsafe: false,
      matches: [],
      source: "Google Safe Browsing",
      backendUrl,
      error: error instanceof Error ? error.message : "Safe Browsing backend unavailable"
    };
  }
}

async function fetchWithTimeout(url, options) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      cache: "no-store"
    });
  } finally {
    clearTimeout(timeout);
  }
}
