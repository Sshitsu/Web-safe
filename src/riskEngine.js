const SUSPICIOUS_TLDS = new Set([
  "zip",
  "review",
  "country",
  "kim",
  "cricket",
  "science",
  "work",
  "party",
  "gq",
  "tk",
  "ml",
  "cf",
  "ga"
]);

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
  "free"
];

function isIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function getHostnameDepth(hostname) {
  return hostname.split(".").filter(Boolean).length;
}

function hasPunycode(hostname) {
  return hostname.includes("xn--");
}

function getTld(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  return parts[parts.length - 1] || "";
}

function findKeywordMatches(text) {
  const lowerText = text.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((keyword) => lowerText.includes(keyword));
}

export function analyzeSite(input) {
  const {
    url,
    title = "",
    pageText = "",
    hasPasswordField = false,
    hasIframe = false,
    formCount = 0
  } = input;

  const reasons = [];
  let score = 0;

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return {
      score: 100,
      label: "Высокий риск",
      reasons: ["Не удалось корректно разобрать URL сайта."],
      facts: {
        hostname: "unknown",
        protocol: "unknown"
      }
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const pathname = parsedUrl.pathname.toLowerCase();
  const protocol = parsedUrl.protocol;
  const keywordMatches = findKeywordMatches(
    `${hostname} ${pathname} ${title} ${pageText.slice(0, 1000)}`
  );

  if (protocol !== "https:") {
    score += 30;
    reasons.push("Сайт не использует HTTPS.");
  }

  if (isIpAddress(hostname)) {
    score += 20;
    reasons.push("Вместо доменного имени используется IP-адрес.");
  }

  if (hasPunycode(hostname)) {
    score += 20;
    reasons.push("В домене обнаружен punycode, это может скрывать подмену символов.");
  }

  const depth = getHostnameDepth(hostname);
  if (depth >= 5) {
    score += 15;
    reasons.push("У домена слишком много уровней поддоменов.");
  }

  const tld = getTld(hostname);
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 10;
    reasons.push(`Доменная зона .${tld} часто встречается в сомнительных сайтах.`);
  }

  if (parsedUrl.href.length > 120) {
    score += 10;
    reasons.push("URL слишком длинный, это часто используют для маскировки.");
  }

  if (keywordMatches.length >= 2) {
    score += 10;
    reasons.push(`Есть подозрительные слова: ${keywordMatches.slice(0, 4).join(", ")}.`);
  }

  if (hasPasswordField && protocol !== "https:") {
    score += 20;
    reasons.push("На странице есть поле пароля, но соединение не защищено.");
  }

  if (hasIframe) {
    score += 5;
    reasons.push("На странице есть iframe, это не всегда опасно, но стоит учитывать.");
  }

  if (formCount >= 3) {
    score += 5;
    reasons.push("На странице много форм для ввода данных.");
  }

  const normalizedScore = Math.max(0, Math.min(100, score));

  let label = "Низкий риск";
  if (normalizedScore >= 70) {
    label = "Высокий риск";
  } else if (normalizedScore >= 40) {
    label = "Средний риск";
  }

  if (reasons.length === 0) {
    reasons.push("Явных подозрительных признаков по базовым эвристикам не найдено.");
  }

  return {
    score: normalizedScore,
    label,
    reasons,
    facts: {
      hostname,
      protocol: protocol.replace(":", ""),
      tld,
      title: title.slice(0, 120)
    }
  };
}
