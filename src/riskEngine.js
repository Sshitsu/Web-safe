import {
  getHostnameDepth,
  getRegistrableDomain,
  getTld,
  hasPunycode,
  isIpAddress
} from "./domainUtils.js";
import { predictDomRisk } from "./domFeatureModel.js";
import { predictNetworkRisk } from "./networkFeatureModel.js";
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

const URGENCY_WORDS = [
  "urgent",
  "immediately",
  "suspended",
  "blocked",
  "limited",
  "verify now",
  "confirm now",
  "подтверд",
  "срочно",
  "заблок",
  "огранич",
  "приостанов"
];

const BRAND_PROFILES = [
  {
    name: "Google",
    terms: ["google", "gmail"],
    domains: ["google.com", "gmail.com"]
  },
  {
    name: "Microsoft",
    terms: ["microsoft", "office 365", "outlook", "onedrive"],
    domains: ["microsoft.com", "office.com", "live.com", "outlook.com", "onedrive.com"]
  },
  {
    name: "Apple",
    terms: ["apple", "icloud", "apple id"],
    domains: ["apple.com", "icloud.com"]
  },
  {
    name: "PayPal",
    terms: ["paypal"],
    domains: ["paypal.com"]
  },
  {
    name: "Meta/Facebook",
    terms: ["facebook", "meta business", "meta ads"],
    domains: ["facebook.com", "fb.com", "meta.com"]
  },
  {
    name: "Instagram",
    terms: ["instagram"],
    domains: ["instagram.com"]
  },
  {
    name: "Netflix",
    terms: ["netflix"],
    domains: ["netflix.com"]
  },
  {
    name: "Steam",
    terms: ["steam"],
    domains: ["steampowered.com", "steamcommunity.com"]
  },
  {
    name: "Roblox",
    terms: ["roblox"],
    domains: ["roblox.com"]
  },
  {
    name: "Discord",
    terms: ["discord"],
    domains: ["discord.com", "discord.gg"]
  },
  {
    name: "Telegram",
    terms: ["telegram"],
    domains: ["telegram.org", "t.me"]
  },
  {
    name: "Coinbase",
    terms: ["coinbase"],
    domains: ["coinbase.com"]
  },
  {
    name: "Binance",
    terms: ["binance"],
    domains: ["binance.com"]
  },
  {
    name: "MetaMask",
    terms: ["metamask"],
    domains: ["metamask.io"]
  },
  {
    name: "Ledger",
    terms: ["ledger live", "ledger"],
    domains: ["ledger.com"]
  }
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
    passwordFieldCount = 0,
    sensitiveInputCount = 0,
    hiddenInputCount = 0,
    linkCount = 0,
    scriptCount = 0,
    iframeCount = 0,
    externalLinkRatio = 0,
    externalScriptCount = 0,
    externalIframeCount = 0,
    formActionHosts = [],
    passwordFormActionHosts = [],
    autocompleteOffFormCount = 0,
    sensitiveFormCount = 0,
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
  const pageTextForSignals = `${title} ${pageText}`.toLowerCase();
  const brandImpersonationMatches = findBrandImpersonationMatches(
    pageTextForSignals,
    registrableDomain
  );
  const externalFormHosts = getExternalHosts(formActionHosts, registrableDomain);
  const externalPasswordFormHosts = getExternalHosts(
    passwordFormActionHosts,
    registrableDomain
  );
  const hasUrgencyLanguage = URGENCY_WORDS.some((word) =>
    pageTextForSignals.includes(word)
  );
  const domPrediction = predictDomRisk(input, {
    brandImpersonationCount: brandImpersonationMatches.length,
    externalFormHostCount: externalFormHosts.length,
    externalPasswordFormHostCount: externalPasswordFormHosts.length,
    hasUrgencyLanguage,
    keywordMatchCount: keywordMatches.length
  });
  const networkPrediction = predictNetworkRisk(networkSignals);

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

  if (brandImpersonationMatches.length > 0) {
    const brandNames = brandImpersonationMatches.map((brand) => brand.name).join(", ");
    const brandScore = hasPasswordField || sensitiveInputCount >= 2 ? 25 : 14;
    score += brandScore;
    reasons.push(
      `Страница упоминает известный бренд (${brandNames}), но домен не похож на официальный.`
    );
  }

  if (hasPasswordField && protocol !== "https:") {
    score += 20;
    reasons.push("На странице есть поле пароля, но соединение не защищено.");
  }

  if (externalPasswordFormHosts.length > 0) {
    score += 35;
    reasons.push(
      `Форма с паролем отправляет данные на внешний домен: ${externalPasswordFormHosts[0]}.`
    );
  } else if (externalFormHosts.length > 0 && sensitiveFormCount > 0) {
    score += 18;
    reasons.push(
      `Форма с чувствительными полями отправляет данные на внешний домен: ${externalFormHosts[0]}.`
    );
  }

  if (sensitiveInputCount >= 4) {
    score += 10;
    reasons.push("На странице много полей для чувствительных данных.");
  }

  if (passwordFieldCount >= 2) {
    score += 6;
    reasons.push("На странице несколько полей пароля.");
  }

  if (hasIframe) {
    score += 5;
    reasons.push("На странице есть iframe, это не всегда опасно, но стоит учитывать.");
  }

  if (formCount >= 3) {
    score += 5;
    reasons.push("На странице много форм для ввода данных.");
  }

  if ((hasPasswordField || sensitiveInputCount >= 2) && hasUrgencyLanguage) {
    score += 12;
    reasons.push("Страница сочетает сбор данных с формулировками срочности или блокировки.");
  }

  if (autocompleteOffFormCount > 0 && (hasPasswordField || sensitiveInputCount >= 2)) {
    score += 5;
    reasons.push("Для формы с чувствительными данными отключено автозаполнение.");
  }

  if (linkCount >= 10 && externalLinkRatio >= 0.85) {
    score += 6;
    reasons.push("Большая часть ссылок ведет на внешние домены.");
  }

  if (scriptCount >= 8 && externalScriptCount / Math.max(scriptCount, 1) >= 0.75) {
    score += 6;
    reasons.push("Большая часть скриптов загружается с внешних доменов.");
  }

  if (iframeCount >= 2 && externalIframeCount >= 2) {
    score += 8;
    reasons.push("Страница содержит несколько внешних iframe.");
  }

  if (hiddenInputCount >= 20 && (hasPasswordField || sensitiveInputCount >= 2)) {
    score += 5;
    reasons.push("В форме много скрытых полей вместе со сбором чувствительных данных.");
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

  score = applySeparateModelSignal(
    score,
    reasons,
    domPrediction,
    "DOM-модель",
    "структуре страницы"
  );
  score = applySeparateModelSignal(
    score,
    reasons,
    networkPrediction,
    "DNS/RDAP-модель",
    "сетевым и регистрационным признакам домена"
  );

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
      domModelScore: domPrediction.ok ? domPrediction.score : null,
      networkModelScore: networkPrediction.ok ? networkPrediction.score : null,
      mlModelScore: getMaxModelScore(urlPrediction, domPrediction, networkPrediction),
      urlModelTopFeatures: urlPrediction.topFeatures,
      domModelTopFeatures: domPrediction.topFeatures,
      networkModelTopFeatures: networkPrediction.topFeatures,
      dnsAddressCount: networkSignals?.dns?.addressCount ?? null,
      dnsNameServerCount: networkSignals?.dns?.nameServerCount ?? null,
      brandMatches: brandImpersonationMatches.map((brand) => brand.name),
      externalFormHosts,
      sensitiveInputCount,
      externalLinkRatio: Number.isFinite(externalLinkRatio)
        ? Math.round(externalLinkRatio * 100)
        : null
    }
  };
}

function getExternalHosts(hosts, registrableDomain) {
  return [...new Set(hosts)]
    .map((host) => ({
      host,
      registrableDomain: getRegistrableDomain(host)
    }))
    .filter((item) => item.host && item.registrableDomain !== registrableDomain)
    .map((item) => item.host);
}

function applySeparateModelSignal(score, reasons, prediction, modelName, signalName) {
  if (!prediction.ok || prediction.probability < 0.45) {
    return score;
  }

  const percent = Math.round(prediction.probability * 100);
  if (prediction.probability >= 0.85) {
    reasons.push(`${modelName} оценила риск по ${signalName} как высокий (${percent}%).`);
    return score + 18;
  }

  if (prediction.probability >= 0.65) {
    reasons.push(`${modelName} видит повышенный риск по ${signalName} (${percent}%).`);
    return score + 10;
  }

  reasons.push(`${modelName} нашла слабые признаки риска по ${signalName} (${percent}%).`);
  return score + 5;
}

function getMaxModelScore(...predictions) {
  const scores = predictions
    .filter((prediction) => prediction.ok && Number.isFinite(prediction.score))
    .map((prediction) => prediction.score);

  return scores.length ? Math.max(...scores) : null;
}

function findBrandImpersonationMatches(text, registrableDomain) {
  return BRAND_PROFILES.filter((brand) => {
    const mentionsBrand = brand.terms.some((term) => text.includes(term));
    const officialDomain = brand.domains.some(
      (domain) => getRegistrableDomain(domain) === registrableDomain
    );

    return mentionsBrand && !officialDomain;
  });
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
