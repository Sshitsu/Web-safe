#!/usr/bin/env python3
import argparse
import csv
import json
import math
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

from train_url_model import (
    FEATURE_NAMES as URL_FEATURE_NAMES,
    extract_features as extract_url_features,
    load_phishing_urls,
    load_public_suffix_rules,
    load_tranco_urls,
    registrable_domain,
)

RUNTIME_FEATURE_NAMES = [
    "hasPasswordField",
    "multiplePasswordFields",
    "manySensitiveInputs",
    "externalPasswordForm",
    "externalSensitiveForm",
    "autocompleteOffSensitiveForm",
    "hasIframe",
    "manyForms",
    "manyExternalIframes",
    "highExternalLinkRatio",
    "highExternalScriptRatio",
    "manyHiddenSensitiveInputs",
    "brandImpersonation",
    "urgencyWithSensitive",
    "youngDomain7",
    "youngDomain30",
    "youngDomain90",
    "recentDomainChange7",
    "dnsNoAddress",
    "dnsNoNameServers",
    "dnsShortTtl",
]

FEATURE_NAMES = URL_FEATURE_NAMES + RUNTIME_FEATURE_NAMES
DEFAULT_RUNTIME_EXAMPLES = Path("data/site_model_training_examples.csv")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive-limit", type=int, default=8000)
    parser.add_argument("--negative-limit", type=int, default=8000)
    parser.add_argument("--epochs", type=int, default=120)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--runtime-examples", default=str(DEFAULT_RUNTIME_EXAMPLES))
    parser.add_argument("--runtime-example-weight", type=int, default=25)
    parser.add_argument("--output", default="src/siteModelWeights.js")
    args = parser.parse_args()

    random.seed(args.seed)
    psl_rules = load_public_suffix_rules()

    rows = []
    phishing_urls = load_phishing_urls(args.positive_limit)
    benign_urls = load_tranco_urls(args.negative_limit)
    rows.extend(make_rows(phishing_urls, 1, zero_runtime_features()))
    rows.extend(make_rows(benign_urls, 0, zero_runtime_features()))

    runtime_rows = load_runtime_example_rows(Path(args.runtime_examples))
    rows.extend(repeat_rows(runtime_rows, args.runtime_example_weight))

    train_rows, test_rows = split_rows_by_domain(rows, test_ratio=0.2, psl_rules=psl_rules)
    weights, intercept = train_logistic_regression(
        train_rows,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
    )
    metrics = evaluate(test_rows, weights, intercept)

    write_model(
        Path(args.output),
        weights,
        intercept,
        metrics,
        phishing_count=len(phishing_urls),
        benign_count=len(benign_urls),
        runtime_count=len(runtime_rows),
        runtime_weight=args.runtime_example_weight,
    )

    print(f"trained site model on {len(train_rows)} rows, tested on {len(test_rows)} rows")
    print(json.dumps(metrics, indent=2, sort_keys=True))


def zero_runtime_features():
    return {name: 0 for name in RUNTIME_FEATURE_NAMES}


def make_rows(urls, label, runtime_features):
    return [
        {
            "url": url,
            "label": label,
            "features": {
                **extract_url_features(url),
                **runtime_features,
            },
        }
        for url in urls
    ]


def load_runtime_example_rows(path):
    if not path.exists():
        return []

    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as file:
      reader = csv.DictReader(file)
      for item in reader:
          url = item["url"].strip()
          label = int(item["label"])
          runtime_features = {
              name: int(float(item.get(name, "0") or 0))
              for name in RUNTIME_FEATURE_NAMES
          }
          rows.append(
              {
                  "url": url,
                  "label": label,
                  "features": {
                      **extract_url_features(url),
                      **runtime_features,
                  },
              }
          )

    return rows


def repeat_rows(rows, count):
    return [
        {
            "url": row["url"],
            "label": row["label"],
            "features": dict(row["features"]),
        }
        for row in rows
        for _ in range(max(1, count))
    ]


def split_rows_by_domain(rows, test_ratio, psl_rules):
    train_rows = []
    test_rows = []

    for label in (0, 1):
        groups = {}
        for row in rows:
            if row["label"] != label:
                continue
            groups.setdefault(registrable_domain(row["url"], psl_rules), []).append(row)

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


def train_logistic_regression(rows, epochs, learning_rate):
    weights = {name: 0.0 for name in FEATURE_NAMES}
    intercept = 0.0
    l2 = 0.001

    for _ in range(epochs):
        random.shuffle(rows)
        for row in rows:
            features = row["features"]
            label = row["label"]
            logit = intercept + sum(weights[name] * features[name] for name in FEATURE_NAMES)
            prediction = sigmoid(logit)
            error = prediction - label
            intercept -= learning_rate * error

            for name in FEATURE_NAMES:
                gradient = error * features[name] + l2 * weights[name]
                weights[name] -= learning_rate * gradient

    return weights, intercept


def evaluate(rows, weights, intercept):
    tp = fp = tn = fn = 0
    losses = []

    for row in rows:
        features = row["features"]
        label = row["label"]
        logit = intercept + sum(weights[name] * features[name] for name in FEATURE_NAMES)
        probability = sigmoid(logit)
        predicted = 1 if probability >= 0.5 else 0
        losses.append(
            -(label * math.log(probability + 1e-9) + (1 - label) * math.log(1 - probability + 1e-9))
        )

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


def write_model(path, weights, intercept, metrics, phishing_count, benign_count, runtime_count, runtime_weight):
    payload = {
        "version": "site-linear-runtime-v1",
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "trainingData": {
            "phishingSamples": phishing_count,
            "benignSamples": benign_count,
            "runtimeFeatureSamples": runtime_count,
            "runtimeFeatureWeight": runtime_weight,
            "sources": [
                "OpenPhish Community Feed",
                "Phishing.Database active links",
                "Tranco top domains",
                "data/site_model_training_examples.csv",
            ],
        },
        "metrics": metrics,
        "intercept": round(intercept, 6),
        "weights": {name: round(weights[name], 6) for name in FEATURE_NAMES},
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "export const SITE_MODEL = "
        + json.dumps(payload, indent=2, sort_keys=True)
        + ";\n",
        encoding="utf-8",
    )


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
