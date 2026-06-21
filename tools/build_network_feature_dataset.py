#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from train_url_model import (
    load_phishing_urls,
    load_public_suffix_rules,
    load_tranco_urls,
    registrable_domain,
)

DEFAULT_OUTPUT = Path("data/generated/network_runtime_features.csv")
DNS_TYPES = ["A", "AAAA", "NS", "MX"]
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
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--positive-limit", type=int, default=50)
    parser.add_argument("--negative-limit", type=int, default=50)
    parser.add_argument("--sleep", type=float, default=0.1)
    args = parser.parse_args()

    psl_rules = load_public_suffix_rules()
    phishing_urls = load_phishing_urls(args.positive_limit)
    benign_urls = load_tranco_urls(args.negative_limit)
    rows = []

    for url, label in [(url, 1) for url in phishing_urls] + [(url, 0) for url in benign_urls]:
        try:
            row = build_feature_row(url, label, psl_rules)
            rows.append(row)
            print(f"ok {label} {row['domain']}")
        except Exception as error:
            print(f"warn {url}: {error}")
        if args.sleep > 0:
            time.sleep(args.sleep)

    write_rows(Path(args.output), rows)
    positives = sum(1 for row in rows if row["label"] == 1)
    negatives = sum(1 for row in rows if row["label"] == 0)
    print(f"wrote {len(rows)} DNS/RDAP rows to {args.output}")
    print(f"positive={positives}, negative={negatives}")


def build_feature_row(url, label, psl_rules):
    domain = registrable_domain(url, psl_rules)
    dns = collect_dns(domain)
    rdap = collect_rdap(domain)
    features = extract_network_features(dns, rdap)

    return {
        "label": label,
        "source": "runtime-enrichment",
        "url": url,
        "domain": domain,
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        **features,
    }


def collect_dns(domain):
    results = {}
    errors = []
    for query_type in DNS_TYPES:
        try:
            results[query_type] = query_dns(domain, query_type)
        except Exception as error:
            errors.append(f"{query_type}: {error}")

    address_answers = (results.get("A", {}).get("Answer") or []) + (results.get("AAAA", {}).get("Answer") or [])
    ns_answers = results.get("NS", {}).get("Answer") or []
    mx_answers = results.get("MX", {}).get("Answer") or []
    all_answers = [
        answer
        for result in results.values()
        for answer in result.get("Answer", [])
    ]
    ttl_values = [
        answer.get("TTL")
        for answer in all_answers
        if isinstance(answer.get("TTL"), int)
    ]

    return {
        "ok": len(errors) < len(DNS_TYPES),
        "errors": errors,
        "hasAddress": len(address_answers) > 0,
        "hasNameServers": len(ns_answers) > 0,
        "hasMx": len(mx_answers) > 0,
        "minTtl": min(ttl_values) if ttl_values else None,
    }


def query_dns(domain, query_type):
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode(
        {"name": domain, "type": query_type}
    )
    request = urllib.request.Request(
        url,
        headers={
            "accept": "application/dns-json",
            "user-agent": "WebSafeDatasetBuilder/0.2",
        },
    )
    with urllib.request.urlopen(request, timeout=8) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8") or "{}")


def collect_rdap(domain):
    if not domain or is_ip_address(domain):
        return {"ok": False}

    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    request = urllib.request.Request(
        url,
        headers={
            "accept": "application/rdap+json, application/json",
            "user-agent": "WebSafeDatasetBuilder/0.2",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except Exception:
        return {"ok": False}

    registration_date = find_event_date(payload.get("events", []), {"registration", "registered"})
    last_changed_date = find_event_date(payload.get("events", []), {"last changed"})
    return {
        "ok": True,
        "ageDays": days_since(registration_date),
        "lastChangedDays": days_since(last_changed_date),
    }


def extract_network_features(dns, rdap):
    age_days = rdap.get("ageDays")
    last_changed_days = rdap.get("lastChangedDays")
    min_ttl = dns.get("minTtl")

    return {
        "youngDomain7": int(is_number(age_days) and age_days < 7),
        "youngDomain30": int(is_number(age_days) and 7 <= age_days < 30),
        "youngDomain90": int(is_number(age_days) and 30 <= age_days < 90),
        "recentDomainChange7": int(is_number(last_changed_days) and last_changed_days < 7),
        "dnsNoAddress": int(dns.get("ok") and not dns.get("hasAddress")),
        "dnsNoNameServers": int(dns.get("ok") and not dns.get("hasNameServers")),
        "dnsShortTtl": int(dns.get("ok") and is_number(min_ttl) and min_ttl <= 180),
        "dnsUnavailable": int(dns.get("ok") is False),
        "rdapUnavailable": int(rdap.get("ok") is False),
        "noMxRecord": int(dns.get("ok") and not dns.get("hasMx")),
    }


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["label", "source", "url", "domain", "collectedAt", *FEATURE_NAMES],
        )
        writer.writeheader()
        writer.writerows(rows)


def find_event_date(events, actions):
    for event in events:
        if str(event.get("eventAction", "")).lower() in actions:
            return event.get("eventDate")
    return None


def days_since(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int((datetime.now(timezone.utc) - parsed).total_seconds() // 86400)


def is_number(value):
    return isinstance(value, (int, float))


def is_ip_address(hostname):
    parts = hostname.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
