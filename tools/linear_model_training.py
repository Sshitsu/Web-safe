import csv
import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path


def load_binary_feature_rows(path, feature_names):
    rows = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        for item in reader:
            rows.append(
                {
                    "label": int(item["label"]),
                    "features": {
                        name: int(float(item.get(name, "0") or 0))
                        for name in feature_names
                    },
                }
            )

    return rows


def split_rows(rows, test_ratio, seed):
    # Deterministic dataset splitting for reproducible training, not cryptography.
    rng = random.Random(seed)  # nosec B311
    train_rows = []
    test_rows = []

    for label in (0, 1):
        label_rows = [row for row in rows if row["label"] == label]
        rng.shuffle(label_rows)
        test_count = max(1, int(len(label_rows) * test_ratio)) if len(label_rows) > 1 else 0
        test_rows.extend(label_rows[:test_count])
        train_rows.extend(label_rows[test_count:])

    rng.shuffle(train_rows)
    rng.shuffle(test_rows)
    return train_rows, test_rows


def train_logistic_regression(rows, feature_names, epochs, learning_rate, seed):
    # Deterministic SGD shuffling for reproducible training, not cryptography.
    rng = random.Random(seed)  # nosec B311
    weights = {name: 0.0 for name in feature_names}
    intercept = 0.0
    l2 = 0.001

    for _ in range(epochs):
        rng.shuffle(rows)
        for row in rows:
            features = row["features"]
            label = row["label"]
            logit = intercept + sum(weights[name] * features[name] for name in feature_names)
            prediction = sigmoid(logit)
            error = prediction - label
            intercept -= learning_rate * error

            for name in feature_names:
                gradient = error * features[name] + l2 * weights[name]
                weights[name] -= learning_rate * gradient

    return weights, intercept


def evaluate(rows, weights, intercept, feature_names):
    tp = fp = tn = fn = 0
    losses = []

    for row in rows:
        features = row["features"]
        label = row["label"]
        logit = intercept + sum(weights[name] * features[name] for name in feature_names)
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


def write_js_model(path, export_name, version, sources, rows, weights, intercept, metrics):
    payload = {
        "version": version,
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "trainingData": {
            "samples": len(rows),
            "sources": sources,
        },
        "metrics": metrics,
        "intercept": round(intercept, 6),
        "weights": {name: round(value, 6) for name, value in weights.items()},
    }

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"export const {export_name} = "
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
