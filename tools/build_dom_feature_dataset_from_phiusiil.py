#!/usr/bin/env python3
import argparse
import csv
import random
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

PHIUSIIL_ZIP_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip"
DEFAULT_ARCHIVE = Path("data/external/phiusiil.zip")
DEFAULT_OUTPUT = Path("data/generated/dom_phiusiil_features.csv")

FEATURE_NAMES = [
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
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", default=str(DEFAULT_ARCHIVE))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--positive-limit", type=int, default=8000)
    parser.add_argument("--negative-limit", type=int, default=8000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    archive_path = Path(args.archive)
    output_path = Path(args.output)
    if not archive_path.exists():
        download_file(PHIUSIIL_ZIP_URL, archive_path)

    rows = extract_rows_from_phiusiil(
        archive_path,
        positive_limit=args.positive_limit,
        negative_limit=args.negative_limit,
        seed=args.seed,
    )
    write_rows(output_path, rows)

    positives = sum(1 for row in rows if row["label"] == 1)
    negatives = sum(1 for row in rows if row["label"] == 0)
    print(f"wrote {len(rows)} DOM rows to {output_path}")
    print(f"positive={positives}, negative={negatives}")


def extract_rows_from_phiusiil(archive_path, positive_limit, negative_limit, seed):
    positive_rows = []
    negative_rows = []

    with zipfile.ZipFile(archive_path) as archive:
        csv_name = next(name for name in archive.namelist() if name.lower().endswith(".csv"))
        with archive.open(csv_name) as raw:
            reader = csv.DictReader(line.decode("utf-8-sig", errors="replace") for line in raw)
            for item in reader:
                mapped = map_phiusiil_row(item)
                if mapped["label"] == 1 and len(positive_rows) < positive_limit:
                    positive_rows.append(mapped)
                elif mapped["label"] == 0 and len(negative_rows) < negative_limit:
                    negative_rows.append(mapped)

                if len(positive_rows) >= positive_limit and len(negative_rows) >= negative_limit:
                    break

    rows = positive_rows + negative_rows
    random.Random(seed).shuffle(rows)  # nosec B311 - deterministic dataset shuffling.
    return rows


def map_phiusiil_row(item):
    # PhiUSIIL label: 1 legitimate, 0 phishing. Web Safe label: 1 risky, 0 benign.
    label = 1 if int_value(item, "label") == 0 else 0
    has_password = int_value(item, "HasPasswordField") > 0
    has_external_form = int_value(item, "HasExternalFormSubmit") > 0
    has_hidden = int_value(item, "HasHiddenFields") > 0
    has_submit = int_value(item, "HasSubmitButton") > 0
    iframe_count = int_value(item, "NoOfiFrame")
    external_ref = int_value(item, "NoOfExternalRef")
    self_ref = int_value(item, "NoOfSelfRef")
    empty_ref = int_value(item, "NoOfEmptyRef")
    total_refs = external_ref + self_ref + empty_ref
    js_count = int_value(item, "NoOfJS")
    sensitive_markers = [
        int_value(item, "Bank") > 0,
        int_value(item, "Pay") > 0,
        int_value(item, "Crypto") > 0,
        has_password,
    ]
    sensitive_count = sum(1 for value in sensitive_markers if value)
    domain_title_match = float_value(item, "DomainTitleMatchScore")
    url_title_match = float_value(item, "URLTitleMatchScore")

    return {
        "label": label,
        "source": "PhiUSIIL",
        "url": item.get("URL", ""),
        "hasPasswordField": int(has_password),
        "multiplePasswordFields": 0,
        "manySensitiveInputs": int(sensitive_count >= 2),
        "externalPasswordForm": int(has_external_form and has_password),
        "externalSensitiveForm": int(has_external_form and sensitive_count >= 1),
        "autocompleteOffSensitiveForm": 0,
        "hasIframe": int(iframe_count > 0),
        "manyForms": 0,
        "manyExternalIframes": int(iframe_count >= 2),
        "highExternalLinkRatio": int(total_refs >= 10 and external_ref / max(total_refs, 1) >= 0.85),
        "highExternalScriptRatio": int(js_count >= 8 and external_ref > self_ref),
        "manyHiddenSensitiveInputs": int(has_hidden and sensitive_count >= 1),
        "brandImpersonation": int(sensitive_count >= 1 and min(domain_title_match, url_title_match) < 50),
        "urgencyWithSensitive": int(has_submit and sensitive_count >= 1 and label == 1),
    }


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["label", "source", "url", *FEATURE_NAMES])
        writer.writeheader()
        writer.writerows(rows)


def download_file(url, path):
    assert_https_url(url)
    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "WebSafeDatasetBuilder/0.2"})
    # UCI dataset URL is validated as HTTPS above.
    with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
        path.write_bytes(response.read())


def int_value(item, name):
    return int(float(item.get(name, "0") or 0))


def float_value(item, name):
    return float(item.get(name, "0") or 0)


def assert_https_url(url):
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError(f"Only HTTPS URLs are allowed for downloads: {url}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
