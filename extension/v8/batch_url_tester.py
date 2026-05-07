#!/usr/bin/env python3
"""Batch test URLs against the phishing detector backend and save results to CSV.

This CLI uses the same backend endpoint the browser extension relies on:
/domain_status on the local Flask server. It prints live progress so you can
watch the URLs being tested and writes the final results to a CSV file.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Iterable

import requests


DEFAULT_BASE_URL = "http://localhost:5000"


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
    if raw_url.startswith(("http://", "https://")):
        return raw_url
    return f"http://{raw_url}"


def load_urls_from_file(file_path: Path) -> list[str]:
    urls: list[str] = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def load_rows_from_csv(file_path: Path, url_column: str, label_column: str | None) -> list[dict]:
    rows: list[dict] = []
    with file_path.open("r", newline="", encoding="utf-8-sig") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames:
            return rows

        available_columns = [name.strip() for name in reader.fieldnames if name]
        normalized_lookup = {name.lower(): name for name in available_columns}

        chosen_url_column = normalized_lookup.get(url_column.lower())
        if chosen_url_column is None:
            chosen_url_column = available_columns[0]

        chosen_label_column = None
        if label_column:
            chosen_label_column = normalized_lookup.get(label_column.lower())

        for row in reader:
            raw_url = (row.get(chosen_url_column) or "").strip()
            if not raw_url:
                continue
            rows.append(
                {
                    "url": raw_url,
                    "expected_label": (row.get(chosen_label_column) or "").strip() if chosen_label_column else "",
                }
            )
    return rows


def load_urls(args: argparse.Namespace) -> list[str]:
    urls: list[str] = []

    if args.url:
        urls.extend(args.url)

    if args.file:
        urls.extend(load_urls_from_file(Path(args.file)))

    if not urls and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    normalized = [normalize_url(url) for url in urls]
    return [url for url in normalized if url]


def load_items(args: argparse.Namespace) -> list[dict]:
    if args.csv_input:
        return load_rows_from_csv(Path(args.csv_input), args.url_column, args.label_column)

    urls = load_urls(args)
    return [{"url": url, "expected_label": ""} for url in urls]


def submit_url(base_url: str, url: str, timeout: float) -> dict:
    endpoint = f"{base_url.rstrip('/')}/domain_status"
    response = requests.post(endpoint, json={"url": url}, timeout=timeout)
    response.raise_for_status()
    return response.json()


def summarize_verdict(payload: dict) -> str:
    if payload.get("google_flagged"):
        return "blocked by Google Safe Browsing"

    model_prediction = str(payload.get("model_prediction", "UNKNOWN")).upper()
    model_status = payload.get("model_status")
    if model_status == 0 or model_prediction == "PHISHING":
        return "blocked by model"
    if model_status == 1 or model_prediction in {"LEGITIMATE", "TRUSTED DOMAIN"}:
        return "allowed"
    return "unknown"


def summarize_google_verdict(payload: dict) -> str:
    if not payload.get("google_available"):
        return "unavailable"
    if payload.get("google_flagged"):
        return "flagged"
    return "clean"


def summarize_expected_label(expected_label: str) -> str:
    label = expected_label.strip().lower()
    if not label:
        return ""
    if label in {"1", "phishing", "phish", "malicious", "bad", "unsafe"}:
        return "phishing"
    if label in {"0", "legitimate", "legit", "safe", "clean", "benign"}:
        return "legitimate"
    return expected_label


def format_reasoning(reasoning: Iterable[dict]) -> str:
    parts = []
    for item in reasoning:
        feature = item.get("feature", "feature")
        value = item.get("value", "?")
        impact = item.get("impact", "impact")
        parts.append(f"{feature}={value} ({impact})")
    return " | ".join(parts)


def build_row(url: str, payload: dict, error: str = "") -> dict:
    reasoning = payload.get("model_reasoning") or []
    return {
        "url": url,
        "verdict": summarize_verdict(payload) if not error else "error",
        "expected_label": "",
        "label_match": "",
        "google_available": payload.get("google_available", ""),
        "google_verdict": summarize_google_verdict(payload) if not error else "unavailable",
        "google_safe_browsing": json.dumps(payload.get("google_safe_browsing", {}), ensure_ascii=True, sort_keys=True),
        "model_prediction": payload.get("model_prediction", ""),
        "model_status": payload.get("model_status", ""),
        "model_confidence": payload.get("model_confidence", ""),
        "google_flagged": payload.get("google_flagged", ""),
        "reasoning": format_reasoning(reasoning) if reasoning else "",
        "error": error,
        "raw_json": json.dumps(payload, ensure_ascii=True, sort_keys=True),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch test multiple URLs against the phishing detector backend and save CSV output."
    )
    parser.add_argument("url", nargs="*", help="One or more URLs/domains to test")
    parser.add_argument("-f", "--file", help="Read URLs from a text file, one per line")
    parser.add_argument("--csv-input", help="Read URLs from a CSV file instead of plain text")
    parser.add_argument("--url-column", default="url", help="CSV column containing the URL to test")
    parser.add_argument("--label-column", help="Optional CSV column containing the expected label")
    parser.add_argument("-o", "--output", default="results.csv", help="CSV file to write results to")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Backend base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print the raw backend response after each URL")
    args = parser.parse_args()

    items = load_items(args)
    if not items:
        parser.error("provide URLs as arguments, via --file, --csv-input, or through stdin")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "url",
        "google_verdict",
        "verdict",
        "expected_label",
        "label_match",
        "google_available",
        "google_safe_browsing",
        "model_prediction",
        "model_status",
        "model_confidence",
        "google_flagged",
        "reasoning",
        "error",
        "raw_json",
    ]

    rows: list[dict] = []
    total = len(items)
    failures = 0

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for index, item in enumerate(items, start=1):
            url = item["url"]
            expected_label = summarize_expected_label(item.get("expected_label", ""))
            prefix = f"[{index}/{total}]"
            try:
                payload = submit_url(args.base_url, url, args.timeout)
                row = build_row(url, payload)
                row["expected_label"] = expected_label
                if expected_label:
                    row["label_match"] = "yes" if summarize_verdict(payload) == expected_label else "no"
                writer.writerow(row)
                rows.append(row)

                verdict = row["verdict"]
                google_verdict = row["google_verdict"]
                model_prediction = row["model_prediction"]
                confidence = row["model_confidence"]
                confidence_text = "n/a" if confidence in (None, "") else f"{float(confidence):.2f}%"
                expected_text = f" | expected={expected_label}" if expected_label else ""
                match_text = f" | match={row['label_match']}" if row["label_match"] else ""
                print(f"{prefix} {url} -> google={google_verdict} | final={verdict}{expected_text}{match_text} | model={model_prediction} | confidence={confidence_text}")

                if row["reasoning"]:
                    print(f"    reasoning: {row['reasoning']}")
                if row["google_available"]:
                    print(f"    google_safe_browsing: {row['google_safe_browsing']}")

                if args.json:
                    print("    raw:")
                    print(json.dumps(payload, indent=2, sort_keys=True))

            except requests.HTTPError as exc:
                failures += 1
                response_text = exc.response.text if exc.response is not None else ""
                row = build_row(url, {}, error=f"HTTPError: {exc}; response={response_text}")
                row["expected_label"] = expected_label
                writer.writerow(row)
                rows.append(row)
                print(f"{prefix} {url} -> error | HTTP {exc.response.status_code if exc.response is not None else 'n/a'}")
                if response_text:
                    print(f"    {response_text}")

            except requests.RequestException as exc:
                failures += 1
                row = build_row(url, {}, error=f"RequestException: {exc}")
                row["expected_label"] = expected_label
                writer.writerow(row)
                rows.append(row)
                print(f"{prefix} {url} -> error | {exc}")

    print(f"Saved {len(rows)} results to {output_path}")
    if failures:
        print(f"Completed with {failures} failed request(s).")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
