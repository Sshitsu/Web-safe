#!/usr/bin/env python3
import argparse
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", default="data/public_suffix_rules.json")
    parser.add_argument("--js-output", default="src/publicSuffixData.js")
    args = parser.parse_args()

    text = download_text(PSL_URL)
    rules = parse_public_suffix_list(text)
    payload = {
        "source": PSL_URL,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        **rules,
    }

    write_json(Path(args.json_output), payload)
    write_js(Path(args.js_output), payload)

    print(
        "public suffix rules updated: "
        f"{len(payload['exact'])} exact, "
        f"{len(payload['wildcard'])} wildcard, "
        f"{len(payload['exception'])} exception"
    )


def parse_public_suffix_list(text):
    exact = set()
    wildcard = set()
    exception = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("!"):
            exception.add(to_ascii_rule(line[1:]))
        elif line.startswith("*."):
            wildcard.add(to_ascii_rule(line[2:]))
        else:
            exact.add(to_ascii_rule(line))

    return {
        "exact": sorted(exact),
        "wildcard": sorted(wildcard),
        "exception": sorted(exception),
    }


def to_ascii_rule(rule):
    labels = []
    for label in rule.lower().strip(".").split("."):
        if label:
            labels.append(label.encode("idna").decode("ascii"))
    return ".".join(labels)


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_js(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "export const PUBLIC_SUFFIX_RULES = "
        + json.dumps(payload, indent=2, sort_keys=True)
        + ";\n",
        encoding="utf-8",
    )


def download_text(url):
    assert_https_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "WebSafeBuild/0.1"})
    # PSL URL is validated as HTTPS above.
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return response.read().decode("utf-8", errors="replace")


def assert_https_url(url):
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError(f"Only HTTPS URLs are allowed for downloads: {url}")


if __name__ == "__main__":
    main()
