#!/usr/bin/env python3
import argparse
import csv
import io
import json
import math
import random
import re
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PSL_RULES_PATH = Path("data/public_suffix_rules.json")
FALLBACK_PSL_RULES = {
    "exact": {
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "com.br",
        "com.tr",
        "com.ua",
        "co.za",
        "com.mx",
        "com.ar",
        "co.jp",
        "com.cn",
        "com.hk",
        "com.sg",
        "co.kr",
        "com.kz",
        "co.nz",
    },
    "wildcard": set(),
    "exception": set(),
}

PHISHING_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://phish.co.za/latest/phishing-links-ACTIVE.txt",
]
TRANCO_TOP_1M = "https://tranco-list.eu/top-1m.csv.zip"

FEATURE_NAMES = [
    "noHttps",
    "hasIpAddress",
    "hasPunycode",
    "longUrl",
    "veryLongUrl",
    "manyDots",
    "manyHyphens",
    "highDigitRatio",
    "suspiciousKeywordCount",
    "encodedCharacters",
    "hasAtSymbol",
    "deepPath",
    "highEntropyHostname",
]

SUSPICIOUS_KEYWORDS = [
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
    "free",
    "recovery",
    "confirm",
    "limited",
    "unlock",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive-limit", type=int, default=8000)
    parser.add_argument("--negative-limit", type=int, default=8000)
    parser.add_argument("--epochs", type=int, default=120)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="src/urlModelWeights.js")
    args = parser.parse_args()

    random.seed(args.seed)
    psl_rules = load_public_suffix_rules()

    phishing_urls = load_phishing_urls(args.positive_limit)
    benign_urls = load_tranco_urls(args.negative_limit)
    examples = [(url, 1) for url in phishing_urls] + [(url, 0) for url in benign_urls]
    train_rows, test_rows = split_by_domain(examples, test_ratio=0.2, psl_rules=psl_rules)

    weights, intercept = train_logistic_regression(
        train_rows,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
    )
    metrics = evaluate(test_rows, weights, intercept)

    write_model(Path(args.output), weights, intercept, metrics, len(phishing_urls), len(benign_urls))

    print(f"trained on {len(train_rows)} rows, tested on {len(test_rows)} rows")
    print(json.dumps(metrics, indent=2, sort_keys=True))


def load_phishing_urls(limit):
    urls = []
    seen = set()

    for feed_url in PHISHING_FEEDS:
        for line in download_text(feed_url).splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#") or candidate in seen:
                continue
            if not candidate.startswith(("http://", "https://")):
                continue
            seen.add(candidate)
            urls.append(candidate)
            if len(urls) >= limit:
                return urls

    return urls


def load_tranco_urls(limit):
    payload = download_bytes(TRANCO_TOP_1M)
    urls = []

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        csv_name = archive.namelist()[0]
        with archive.open(csv_name) as file:
            rows = csv.reader(io.TextIOWrapper(file, encoding="utf-8"))
            for row in rows:
                if len(row) < 2:
                    continue
                domain = row[1].strip().lower()
                if domain:
                    urls.append(f"https://{domain}/")
                if len(urls) >= limit:
                    break

    return urls


def train_logistic_regression(rows, epochs, learning_rate):
    weights = {name: 0.0 for name in FEATURE_NAMES}
    intercept = 0.0
    l2 = 0.001

    for _ in range(epochs):
        random.shuffle(rows)
        for url, label in rows:
            features = extract_features(url)
            logit = intercept + sum(weights[name] * features[name] for name in FEATURE_NAMES)
            prediction = sigmoid(logit)
            error = prediction - label
            intercept -= learning_rate * error

            for name in FEATURE_NAMES:
                gradient = error * features[name] + l2 * weights[name]
                weights[name] -= learning_rate * gradient

    return weights, intercept


def split_by_domain(examples, test_ratio, psl_rules):
    train_rows = []
    test_rows = []

    for label in (0, 1):
        groups = {}
        for url, item_label in examples:
            if item_label != label:
                continue
            groups.setdefault(registrable_domain(url, psl_rules), []).append((url, item_label))

        group_keys = list(groups.keys())
        random.shuffle(group_keys)
        target_test_count = int(sum(len(groups[key]) for key in group_keys) * test_ratio)
        current_test_count = 0

        for key in group_keys:
            if current_test_count < target_test_count:
                test_rows.extend(groups[key])
                current_test_count += len(groups[key])
            else:
                train_rows.extend(groups[key])

    random.shuffle(train_rows)
    random.shuffle(test_rows)

    return train_rows, test_rows


def load_public_suffix_rules():
    if not PSL_RULES_PATH.exists():
        return FALLBACK_PSL_RULES

    payload = json.loads(PSL_RULES_PATH.read_text(encoding="utf-8"))
    return {
        "exact": set(payload.get("exact", [])),
        "wildcard": set(payload.get("wildcard", [])),
        "exception": set(payload.get("exception", [])),
    }


def registrable_domain(url, psl_rules):
    hostname = (urlparse(url).hostname or "").lower().strip(".")
    parts = [part for part in hostname.split(".") if part]
    public_suffix_label_count = public_suffix_label_count_for(parts, psl_rules)

    if len(parts) <= public_suffix_label_count:
        return hostname

    return ".".join(parts[-(public_suffix_label_count + 1):])


def public_suffix_label_count_for(parts, psl_rules):
    if not parts:
        return 0

    best_match_label_count = 1

    for index in range(len(parts)):
        candidate = ".".join(parts[index:])

        if candidate in psl_rules["exception"]:
            return max(1, len(parts) - index - 1)

        if candidate in psl_rules["exact"]:
            best_match_label_count = max(best_match_label_count, len(parts) - index)

        if index < len(parts) - 1:
            wildcard_candidate = ".".join(parts[index + 1:])
            if wildcard_candidate in psl_rules["wildcard"]:
                best_match_label_count = max(best_match_label_count, len(parts) - index)

    return best_match_label_count


def evaluate(rows, weights, intercept):
    tp = fp = tn = fn = 0
    losses = []

    for url, label in rows:
        features = extract_features(url)
        logit = intercept + sum(weights[name] * features[name] for name in FEATURE_NAMES)
        probability = sigmoid(logit)
        predicted = 1 if probability >= 0.5 else 0
        losses.append(-(label * math.log(probability + 1e-9) + (1 - label) * math.log(1 - probability + 1e-9)))

        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "logLoss": round(sum(losses) / max(len(losses), 1), 4),
        "truePositive": tp,
        "falsePositive": fp,
        "trueNegative": tn,
        "falseNegative": fn,
    }


def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    href = url
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    digit_count = len(re.findall(r"\d", href))
    keyword_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in href.lower())

    return {
        "noHttps": 1 if parsed.scheme != "https" else 0,
        "hasIpAddress": 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname) else 0,
        "hasPunycode": 1 if "xn--" in hostname else 0,
        "longUrl": 1 if len(href) > 90 else 0,
        "veryLongUrl": 1 if len(href) > 140 else 0,
        "manyDots": 1 if len([part for part in hostname.split(".") if part]) >= 4 else 0,
        "manyHyphens": 1 if hostname.count("-") >= 2 else 0,
        "highDigitRatio": 1 if digit_count / max(len(href), 1) > 0.12 else 0,
        "suspiciousKeywordCount": min(keyword_count, 4),
        "encodedCharacters": 1 if re.search(r"%[0-9a-f]{2}", href, re.IGNORECASE) else 0,
        "hasAtSymbol": 1 if "@" in href else 0,
        "deepPath": 1 if len(path_segments) >= 4 else 0,
        "highEntropyHostname": 1 if entropy(hostname.replace(".", "")) > 3.8 else 0,
    }


def entropy(text):
    if not text:
        return 0.0

    result = 0.0
    for char in set(text):
        probability = text.count(char) / len(text)
        result -= probability * math.log2(probability)
    return result


def write_model(path, weights, intercept, metrics, positive_count, negative_count):
    payload = {
        "version": "url-linear-trained-v1",
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "trainingData": {
            "phishingSamples": positive_count,
            "benignSamples": negative_count,
            "sources": [
                "OpenPhish Community Feed",
                "Phishing.Database active links",
                "Tranco top domains",
            ],
        },
        "metrics": metrics,
        "intercept": round(intercept, 6),
        "weights": {name: round(weights[name], 6) for name in FEATURE_NAMES},
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "export const URL_MODEL = "
        + json.dumps(payload, indent=2, sort_keys=True)
        + ";\n",
        encoding="utf-8",
    )


def download_text(url):
    return download_bytes(url).decode("utf-8", errors="replace")


def download_bytes(url):
    assert_https_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "WebSafeModelTrainer/0.1"})
    # Training data URLs are validated as HTTPS above.
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return response.read()


def assert_https_url(url):
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError(f"Only HTTPS URLs are allowed for downloads: {url}")


def sigmoid(value):
    if value < -50:
        return 0.0
    if value > 50:
        return 1.0
    return 1 / (1 + math.exp(-value))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
