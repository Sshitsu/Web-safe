import {
  getHostnameDepth,
  getRegistrableDomain,
  getTld,
  hasPunycode,
  isIpAddress
} from "./domainUtils.js";
import { predictUrlRisk } from "./urlFeatureModel.js";

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
    formCount = 0,
    threatIntel = null,
    networkSignals = null,
    safeBrowsing = null
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
  const registrableDomain = getRegistrableDomain(hostname);
  const pathname = parsedUrl.pathname.toLowerCase();
  const protocol = parsedUrl.protocol;
  const urlPrediction = predictUrlRisk(url);
  const keywordMatches = findKeywordMatches(
    `${hostname} ${pathname} ${title} ${pageText.slice(0, 1000)}`
  );

  if (threatIntel?.isKnownPhishing) {
    score += 85;
    const match = threatIntel.matches[0];
    reasons.push(
      `Совпадение с базой известных фишинговых сайтов: ${match.source} (${match.type}: ${match.value}).`
    );
  }

  if (safeBrowsing?.isUnsafe) {
    score += 90;
    const match = safeBrowsing.matches[0];
    const threatType = match?.threatType || "unsafe";
    reasons.push(`Google Safe Browsing пометил URL как опасный: ${threatType}.`);
  }

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

  if (urlPrediction.ok && urlPrediction.probability >= 0.85) {
    score += 25;
    reasons.push(
      `URL-модель оценила адрес как очень подозрительный (${Math.round(
        urlPrediction.probability * 100
      )}%).`
    );
  } else if (urlPrediction.ok && urlPrediction.probability >= 0.65) {
    score += 15;
    reasons.push(
      `URL-модель видит повышенный риск в структуре адреса (${Math.round(
        urlPrediction.probability * 100
      )}%).`
    );
  } else if (urlPrediction.ok && urlPrediction.probability >= 0.45) {
    score += 8;
    reasons.push(
      `URL-модель нашла слабые подозрительные признаки (${Math.round(
        urlPrediction.probability * 100
      )}%).`
    );
  }

  const domainAgeDays = networkSignals?.rdap?.ageDays;
  if (Number.isFinite(domainAgeDays)) {
    if (domainAgeDays < 7) {
      score += 35;
      reasons.push("Домен зарегистрирован меньше недели назад.");
    } else if (domainAgeDays < 30) {
      score += 25;
      reasons.push("Домен зарегистрирован меньше месяца назад.");
    } else if (domainAgeDays < 90) {
      score += 12;
      reasons.push("Домену меньше 90 дней, для фишинга это частый признак.");
    }
  }

  const lastChangedDays = networkSignals?.rdap?.lastChangedDays;
  if (Number.isFinite(lastChangedDays) && lastChangedDays < 7) {
    score += 6;
    reasons.push("Регистрационные данные домена менялись в последние 7 дней.");
  }

  if (networkSignals?.dns?.ok && !networkSignals.dns.hasAddress) {
    score += 25;
    reasons.push("DNS не вернул A/AAAA адреса для домена.");
  }

  if (networkSignals?.dns?.ok && !networkSignals.dns.hasNameServers) {
    score += 8;
    reasons.push("DNS не вернул NS-записи для домена.");
  }

  if (
    networkSignals?.dns?.ok &&
    Number.isFinite(networkSignals.dns.minTtl) &&
    networkSignals.dns.minTtl <= 180
  ) {
    score += 5;
    reasons.push("У DNS-записей очень короткий TTL, это бывает у быстро меняющейся инфраструктуры.");
  }

  const normalizedScore = Math.max(0, Math.min(100, score));

  let label = "Низкий риск";
  if (normalizedScore >= 70) {
    label = "Высокий риск";
  } else if (normalizedScore >= 40) {
    label = "Средний риск";
  }

  if (reasons.length === 0) {
    reasons.push("Явных подозрительных признаков по доступным сигналам не найдено.");
  }

  return {
    score: normalizedScore,
    label,
    reasons,
    facts: {
      hostname,
      registrableDomain,
      protocol: protocol.replace(":", ""),
      tld,
      title: title.slice(0, 120),
      domainAgeDays: Number.isFinite(domainAgeDays) ? domainAgeDays : null,
      threatMatches: threatIntel?.matches?.length || 0,
      threatSources: threatIntel?.sources?.filter((source) => source.ok).length || 0,
      safeBrowsingStatus: getSafeBrowsingStatus(safeBrowsing),
      safeBrowsingMatches: safeBrowsing?.matches?.length || 0,
      urlModelScore: urlPrediction.ok ? urlPrediction.score : null,
      dnsAddressCount: networkSignals?.dns?.addressCount ?? null,
      dnsNameServerCount: networkSignals?.dns?.nameServerCount ?? null
    }
  };
}

function getSafeBrowsingStatus(safeBrowsing) {
  if (!safeBrowsing?.ok) {
    return "unavailable";
  }

  if (!safeBrowsing.configured) {
    return "not_configured";
  }

  if (!safeBrowsing.checked) {
    return "not_checked";
  }

  return safeBrowsing.isUnsafe ? "unsafe" : "clean";
}
