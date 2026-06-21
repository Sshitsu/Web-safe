#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

from linear_model_training import (
    evaluate,
    load_binary_feature_rows,
    split_rows,
    train_logistic_regression,
    write_js_model,
)

FEATURE_NAMES = [
    "youngDomain7",
    "youngDomain30",
    "youngDomain90",
    "recentDomainChange7",
    "dnsNoAddress",
    "dnsNoNameServers",
    "dnsShortTtl",
    "dnsUnavailable",
    "rdapUnavailable",
    "noMxRecord",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        action="append",
        help="CSV with label and DNS/RDAP feature columns. Can be passed multiple times.",
    )
    parser.add_argument("--output", default="src/networkModelWeights.js")
    parser.add_argument("--epochs", type=int, default=180)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--test-ratio", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    input_paths = args.input or default_input_paths()
    rows = load_rows_from_inputs(input_paths)
    train_rows, test_rows = split_rows(rows, args.test_ratio, args.seed)
    weights, intercept = train_logistic_regression(
        train_rows,
        FEATURE_NAMES,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        seed=args.seed,
    )
    metrics = evaluate(test_rows, weights, intercept, FEATURE_NAMES)
    write_js_model(
        Path(args.output),
        "NETWORK_MODEL",
        "network-linear-v1",
        input_paths,
        rows,
        weights,
        intercept,
        metrics,
    )

    print(f"trained DNS/RDAP model on {len(train_rows)} rows, tested on {len(test_rows)} rows")
    print(json.dumps(metrics, indent=2, sort_keys=True))


def default_input_paths():
    paths = ["data/network_model_training_examples.csv"]
    generated = Path("data/generated/network_runtime_features.csv")
    if generated.exists():
        paths.append(str(generated))
    return paths


def load_rows_from_inputs(paths):
    rows = []
    for path in paths:
        rows.extend(load_binary_feature_rows(path, FEATURE_NAMES))
    return rows


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
