#!/usr/bin/env python3
"""Batch test URLs against the phishing detector backend and save results to CSV.

Endpoint: /domain_status on the local Flask server.
Dependencies: pip install requests rich
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Iterable

import requests

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        MofNCompleteColumn,
    )
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


DEFAULT_BASE_URL = "http://localhost:5000"
console = Console(highlight=False) if RICH_AVAILABLE else None


# ── Styles ────────────────────────────────────────────────────────────────────

def verdict_style(v: str) -> str:
    v = v.lower()
    if "blocked" in v: return "bold red"
    if "allowed" in v: return "bold green"
    if "error"   in v: return "bold red"
    return "bold yellow"

def verdict_icon(v: str) -> str:
    v = v.lower()
    if "blocked" in v: return "✘"
    if "allowed" in v: return "✔"
    if "error"   in v: return "!"
    return "?"

def google_style(g: str) -> str:
    return {"flagged": "bold red", "clean": "green"}.get(g, "dim white")

def google_icon(g: str) -> str:
    return {"flagged": "⚑", "clean": "✔", "unavailable": "–"}.get(g, "?")

def conf_bar(conf) -> Text:
    if conf is None:
        return Text("n/a", style="dim white")
    c = float(conf)
    filled = int(c / 10)
    bar = "█" * filled + "░" * (10 - filled)
    color = "green" if c >= 75 else ("yellow" if c >= 50 else "red")
    t = Text()
    t.append(bar, style=color)
    t.append(f" {c:5.1f}%", style=f"bold {color}")
    return t


# ── Input helpers ─────────────────────────────────────────────────────────────

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u: return ""
    return u if u.startswith(("http://", "https://")) else f"http://{u}"

def load_urls_from_file(p: Path) -> list[str]:
    return [l.strip() for l in p.read_text("utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")]

def load_rows_from_csv(p: Path, url_col: str, lbl_col: str | None) -> list[dict]:
    rows = []
    with p.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames: return rows
        avail  = [n.strip() for n in reader.fieldnames if n]
        lookup = {n.lower(): n for n in avail}
        col_u  = lookup.get(url_col.lower(), avail[0])
        col_l  = lookup.get(lbl_col.lower()) if lbl_col else None
        for row in reader:
            raw = (row.get(col_u) or "").strip()
            if raw:
                rows.append({"url": raw,
                             "expected_label": (row.get(col_l) or "").strip() if col_l else ""})
    return rows

def load_items(args: argparse.Namespace) -> list[dict]:
    if args.csv_input:
        return load_rows_from_csv(Path(args.csv_input), args.url_column, args.label_column)
    urls: list[str] = list(args.url or [])
    if args.file:
        urls.extend(load_urls_from_file(Path(args.file)))
    if not urls and not sys.stdin.isatty():
        urls.extend(l.strip() for l in sys.stdin if l.strip() and not l.strip().startswith("#"))
    return [{"url": u, "expected_label": ""} for u in (normalize_url(u) for u in urls) if u]


# ── API ───────────────────────────────────────────────────────────────────────

def submit_url(base_url: str, url: str, timeout: float) -> dict:
    r = requests.post(f"{base_url.rstrip('/')}/domain_status", json={"url": url}, timeout=timeout)
    r.raise_for_status()
    return r.json()


# ── Result helpers ────────────────────────────────────────────────────────────

def summarize_verdict(p: dict) -> str:
    if p.get("google_flagged"): return "blocked by Google Safe Browsing"
    pred = str(p.get("model_prediction", "UNKNOWN")).upper()
    st   = p.get("model_status")
    if st == 0 or pred == "PHISHING":                       return "blocked by model"
    if st == 1 or pred in {"LEGITIMATE", "TRUSTED DOMAIN"}:  return "allowed"
    return "unknown"

def summarize_google(p: dict) -> str:
    if not p.get("google_available"): return "unavailable"
    return "flagged" if p.get("google_flagged") else "clean"

def normalize_label(label: str) -> str:
    l = label.strip().lower()
    if l in {"1","phishing","phish","malicious","bad","unsafe"}: return "phishing"
    if l in {"0","legitimate","legit","safe","clean","benign"}:  return "legitimate"
    return label

def fmt_reasoning(items: Iterable[dict | str]) -> str:
    parts = []
    for i in items:
        if isinstance(i, dict):
            parts.append(f"{i.get('feature','?')}={i.get('value','?')} ({i.get('impact','?')})")
        else:
            parts.append(str(i))
    return " | ".join(parts)

def build_row(url: str, payload: dict, error: str = "") -> dict:
    reasoning = payload.get("model_reasoning") or []
    return {
        "url":                  url,
        "verdict":              summarize_verdict(payload) if not error else "error",
        "expected_label":       "",
        "label_match":          "",
        "google_available":     payload.get("google_available", ""),
        "google_verdict":       summarize_google(payload) if not error else "unavailable",
        "google_safe_browsing": json.dumps(payload.get("google_safe_browsing", {}), sort_keys=True),
        "model_prediction":     payload.get("model_prediction", ""),
        "model_status":         payload.get("model_status", ""),
        "model_confidence":     payload.get("model_confidence", ""),
        "google_flagged":       payload.get("google_flagged", ""),
        "reasoning":            fmt_reasoning(reasoning),
        "error":                error,
        "raw_json":             json.dumps(payload, sort_keys=True),
    }


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = """\
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝███████║██║███████╗███████║██║     ███████║█████╗  ██║     █████╔╝ 
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
  ██║     ██║  ██║██║███████║██║  ██║╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝"""

def print_banner(n: int, base_url: str) -> None:
    console.print(Text(BANNER, style="bold red"))
    console.print(
        Align.center(
            Text(
                f"  URL Phishing Detector  ·  {n} URL{'s' if n != 1 else ''}  ·  {base_url}  ",
                style="bold white on red",
            )
        )
    )
    console.print()


# ── Summary table ─────────────────────────────────────────────────────────────

def make_summary_table(rows: list[dict]) -> Table:
    t = Table(
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
        border_style="dim white",
        show_edge=False,
        expand=True,
    )
    t.add_column("#",          style="dim white",  width=4,  no_wrap=True)
    t.add_column("URL",        style="white",       ratio=5,  no_wrap=True, overflow="fold")
    t.add_column("VERDICT",                         ratio=2,  no_wrap=True)
    t.add_column("GOOGLE",                          width=12, no_wrap=True)
    t.add_column("MODEL",      style="white",       width=14, no_wrap=True)
    t.add_column("CONFIDENCE",                      width=19, no_wrap=True)
    t.add_column("MATCH",                           width=5,  no_wrap=True)

    for i, row in enumerate(rows, 1):
        verdict = row["verdict"]
        google  = row["google_verdict"]
        model   = row["model_prediction"] or "—"
        conf_r  = row["model_confidence"]
        conf    = float(conf_r) if conf_r not in (None, "") else None
        match   = row.get("label_match", "")
        t.add_row(
            str(i),
            row["url"],
            Text(f"{verdict_icon(verdict)} {verdict}", style=verdict_style(verdict)),
            Text(f"{google_icon(google)} {google}",    style=google_style(google)),
            model,
            conf_bar(conf),
            Text("YES", style="bold green") if match == "yes" else
            Text("NO",  style="bold red")   if match == "no"  else
            Text("—",   style="dim white"),
        )
    return t


def stat_panel(total: int, allowed: int, blocked: int, errors: int, elapsed: float) -> Panel:
    t = Text(justify="center")
    t.append("  TOTAL ",     style="bold white");  t.append(f"{total}   ",   style="bold cyan")
    t.append(" ✔ ALLOWED ",  style="bold white");  t.append(f"{allowed}   ", style="bold green")
    t.append(" ✘ BLOCKED ",  style="bold white");  t.append(f"{blocked}   ", style="bold red")
    t.append(" ! ERRORS ",   style="bold white");  t.append(f"{errors}   ",  style="bold yellow")
    t.append(" ⏱ TIME ",     style="bold white");  t.append(f"{elapsed:.1f}s", style="bold magenta")
    return Panel(t, border_style="dim white", padding=(0, 1))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch-test URLs against the phishing detector backend."
    )
    parser.add_argument("url",            nargs="*")
    parser.add_argument("-f", "--file")
    parser.add_argument("--csv-input")
    parser.add_argument("--url-column",   default="url")
    parser.add_argument("--label-column", default=None)
    parser.add_argument("-o", "--output", default="results.csv")
    parser.add_argument("--base-url",     default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout",      type=float, default=10.0)
    parser.add_argument("--json",         action="store_true")
    parser.add_argument("--no-color",     action="store_true")
    args = parser.parse_args()

    items = load_items(args)
    if not items:
        parser.error("provide URLs via arguments, --file, --csv-input, or stdin")

    if not RICH_AVAILABLE or args.no_color:
        return _run_plain(args, items)

    return _run_rich(args, items)


def _run_rich(args: argparse.Namespace, items: list[dict]) -> int:
    total   = len(items)
    allowed = blocked = errors = 0
    rows: list[dict] = []
    start = time.monotonic()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    FIELDNAMES = [
        "url", "google_verdict", "verdict", "expected_label", "label_match",
        "google_available", "google_safe_browsing", "model_prediction",
        "model_status", "model_confidence", "google_flagged",
        "reasoning", "error", "raw_json",
    ]

    print_banner(total, args.base_url)

    # KEY FIX: use Progress as a context manager so it owns its own Live
    # and actually re-renders on each advance(). transient=True wipes it
    # after the loop so the final table renders cleanly below.
    progress = Progress(
        SpinnerColumn(spinner_name="dots2", style="bold red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=36, style="dim red", complete_style="bold green",
                  finished_style="bold green"),
        MofNCompleteColumn(),
        TextColumn("[dim white]{task.fields[url]}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    task = progress.add_task("Scanning", total=total, url="")

    with progress:
        with out.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
            writer.writeheader()

            for idx, item in enumerate(items, 1):
                url   = item["url"]
                label = normalize_label(item.get("expected_label", ""))
                short = (url[:52] + "…") if len(url) > 53 else url

                progress.update(task, url=short)

                try:
                    payload = submit_url(args.base_url, url, args.timeout)
                    row     = build_row(url, payload)
                    row["expected_label"] = label
                    verdict = row["verdict"]
                    google  = row["google_verdict"]
                    model   = row["model_prediction"] or "—"
                    conf_r  = row["model_confidence"]
                    conf    = float(conf_r) if conf_r not in (None, "") else None

                    if "blocked" in verdict: blocked += 1
                    elif "allowed" in verdict: allowed += 1

                    if label:
                        match = "yes" if summarize_verdict(payload) == label else "no"
                        row["label_match"] = match

                    writer.writerow(row)
                    rows.append(row)

                    conf_str = f"{conf:5.1f}%" if conf is not None else "  n/a "
                    vstyle   = verdict_style(verdict)
                    gstyle   = google_style(google)
                    match_s  = ""
                    if row.get("label_match"):
                        match_s = (
                            "  [bold green]MATCH[/bold green]"
                            if row["label_match"] == "yes"
                            else "  [bold red]WRONG[/bold red]"
                        )

                    progress.console.print(
                        f"  [{vstyle}]{verdict_icon(verdict)}[/{vstyle}]"
                        f"  [dim white]{idx:>3}/{total}[/dim white]"
                        f"  [white]{url[:60]:<60}[/white]"
                        f"  [dim white]g=[/dim white][{gstyle}]{google:<11}[/{gstyle}]"
                        f"  [{vstyle}]{verdict:<28}[/{vstyle}]"
                        f"  [bold]{conf_str}[/bold]"
                        + match_s
                    )

                    if row.get("reasoning"):
                        progress.console.print(
                            f"    [dim white]↳ {row['reasoning']}[/dim white]"
                        )
                    if args.json:
                        progress.console.print(json.dumps(payload, indent=2), style="dim")

                except requests.HTTPError as exc:
                    errors += 1
                    code = exc.response.status_code if exc.response else "n/a"
                    row  = build_row(url, {}, error=f"HTTP {code}")
                    row["expected_label"] = label
                    writer.writerow(row)
                    rows.append(row)
                    progress.console.print(
                        f"  [bold red]![/bold red]"
                        f"  [dim white]{idx:>3}/{total}[/dim white]"
                        f"  [white]{url[:60]:<60}[/white]"
                        f"  [bold red]HTTP {code}[/bold red]"
                    )

                except requests.RequestException as exc:
                    errors += 1
                    row = build_row(url, {}, error=str(exc))
                    row["expected_label"] = label
                    writer.writerow(row)
                    rows.append(row)
                    progress.console.print(
                        f"  [bold red]![/bold red]"
                        f"  [dim white]{idx:>3}/{total}[/dim white]"
                        f"  [white]{url[:60]:<60}[/white]"
                        f"  [bold red]connection failed[/bold red]"
                    )

                progress.advance(task)

    elapsed = time.monotonic() - start

    console.print()
    console.print(Rule("[dim white]RESULTS[/dim white]", style="dim white"))
    console.print()
    console.print(make_summary_table(rows))
    console.print()
    console.print(stat_panel(total, allowed, blocked, errors, elapsed))

    labelled = [r for r in rows if r.get("label_match")]
    if labelled:
        correct = sum(1 for r in labelled if r["label_match"] == "yes")
        acc     = correct / len(labelled) * 100
        color   = "green" if acc >= 90 else ("yellow" if acc >= 70 else "red")
        console.print()
        console.print(Panel(
            Align.center(
                Text(f"Accuracy  {correct}/{len(labelled)}  ({acc:.1f}%)", style=f"bold {color}")
            ),
            title="[bold white]Label Accuracy[/bold white]",
            border_style=color,
            padding=(0, 4),
        ))

    console.print()
    console.print(f"  [dim]Saved →[/dim] [bold cyan]{out.resolve()}[/bold cyan]")
    console.print()

    return 1 if errors else 0


def _run_plain(args: argparse.Namespace, items: list[dict]) -> int:
    total    = len(items)
    failures = 0
    rows: list[dict] = []
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    FIELDNAMES = [
        "url", "google_verdict", "verdict", "expected_label", "label_match",
        "google_available", "google_safe_browsing", "model_prediction",
        "model_status", "model_confidence", "google_flagged",
        "reasoning", "error", "raw_json",
    ]

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for idx, item in enumerate(items, 1):
            url   = item["url"]
            label = normalize_label(item.get("expected_label", ""))
            try:
                payload = submit_url(args.base_url, url, args.timeout)
                row     = build_row(url, payload)
                row["expected_label"] = label
                if label:
                    row["label_match"] = "yes" if summarize_verdict(payload) == label else "no"
                writer.writerow(row)
                rows.append(row)
                conf  = row["model_confidence"]
                conf_s = "n/a" if conf in (None, "") else f"{float(conf):.1f}%"
                print(f"[{idx}/{total}] {url} -> {row['verdict']} | google={row['google_verdict']} | conf={conf_s}")
            except requests.RequestException as exc:
                failures += 1
                row = build_row(url, {}, error=str(exc))
                row["expected_label"] = label
                writer.writerow(row)
                rows.append(row)
                print(f"[{idx}/{total}] {url} -> ERROR: {exc}")

    print(f"\nSaved {len(rows)} results to {out}")
    if failures:
        print(f"{failures} request(s) failed.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())