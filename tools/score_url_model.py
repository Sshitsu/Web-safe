#!/usr/bin/env python3
import argparse
import json
import math
import re
from pathlib import Path

from train_url_model import FEATURE_NAMES, extract_features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("urls", nargs="+")
    parser.add_argument("--weights", default="src/urlModelWeights.js")
    args = parser.parse_args()

    model = load_model(Path(args.weights))

    for url in args.urls:
        features = extract_features(url)
        logit = model["intercept"] + sum(
            model["weights"].get(name, 0) * features[name] for name in FEATURE_NAMES
        )
        probability = sigmoid(logit)
        active_features = [
            name for name in FEATURE_NAMES if features[name] and model["weights"].get(name, 0) > 0
        ]

        print(f"{round(probability * 100):>3}%  {url}")
        print(f"     features: {', '.join(active_features) or 'none'}")


def load_model(path):
    text = path.read_text(encoding="utf-8")
    match = re.search(r"export const URL_MODEL = (\{.*\});\s*$", text, re.S)
    if not match:
        raise RuntimeError(f"Cannot parse model file: {path}")
    return json.loads(match.group(1))


def sigmoid(value):
    if value < -50:
        return 0.0
    if value > 50:
        return 1.0
    return 1 / (1 + math.exp(-value))


if __name__ == "__main__":
    main()
