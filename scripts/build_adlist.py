#!/usr/bin/env python3
"""
Build a combined, deduplicated, MikroTik-ready ad-block hosts file.

Reads source URLs from sources.yaml, downloads each, parses hosts-file
syntax, deduplicates, filters against an allowlist, sorts, and writes
one hosts-format file per output defined in sources.yaml.

The output file is suitable for the RouterOS 7 /ip/dns/adlist feature.
"""

import os
import re
import sys
import time
import gzip
import argparse
import urllib.request
import urllib.error
from pathlib import Path

import yaml


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z]{2,63}$"
)

HARD_BUILTIN_ALLOWLIST = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
}

IP_PREFIX_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def fetch_url(url: str, timeout: int = 60, retries: int = 3) -> str:
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "mikrotik-adlist-builder/1.0 (+https://github.com)",
                    "Accept-Encoding": "gzip",
                },
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                if response.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return raw.decode("utf-8-sig", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as err:
            last_err = err
            print(f"  ! attempt {attempt}/{retries} failed: {err}", file=sys.stderr)
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


def parse_hosts_text(text: str) -> set:
    domains = set()
    for line_raw in text.splitlines():
        line = line_raw.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if tokens and (
            tokens[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}
            or IP_PREFIX_REGEX.match(tokens[0])
        ):
            tokens = tokens[1:]
        for token in tokens:
            domain = token.lower().rstrip(".")
            if domain.startswith("*."):
                domain = domain[2:]
            if domain.startswith("||"):
                domain = domain[2:].split("^", 1)[0].split("/", 1)[0]
            if not domain or domain in HARD_BUILTIN_ALLOWLIST:
                continue
            if IP_PREFIX_REGEX.match(domain):
                continue
            if DOMAIN_REGEX.match(domain):
                domains.add(domain)
    return domains


def load_allowlist(path: Path) -> set:
    allowed = set()
    if not path.exists():
        return allowed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower().rstrip(".")
        if line:
            allowed.add(line)
    return allowed


def apply_allowlist(domains: set, allowlist: set) -> set:
    if not allowlist:
        return domains
    result = set()
    for domain in domains:
        keep = True
        parts = domain.split(".")
        for index in range(len(parts) - 1):
            candidate = ".".join(parts[index:])
            if candidate in allowlist:
                keep = False
                break
        if keep:
            result.add(domain)
    return result


def write_output(path: Path, domains: set, header_lines: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file_handle:
        for header_line in header_lines:
            file_handle.write(f"# {header_line}\n")
        file_handle.write("#\n")
        for domain in sorted(domains):
            file_handle.write(f"0.0.0.0 {domain}\n")


def build_one_output(name: str, config: dict, repo_root: Path, allowlist: set) -> dict:
    print(f"\n=== Building {name} ===")
    sources = config.get("sources", [])
    if not sources:
        raise ValueError(f"Output '{name}' has no sources")

    combined = set()
    per_source_counts = []  # (url, parsed, new, dup)

    for url in sources:
        print(f"  -> fetching {url}")
        text = fetch_url(url)
        domains_from_source = parse_hosts_text(text)
        parsed_count = len(domains_from_source)
        new_domains = len(domains_from_source - combined)
        dup_count = parsed_count - new_domains
        per_source_counts.append((url, parsed_count, new_domains, dup_count))
        combined |= domains_from_source
        print(f"     {parsed_count:>8} parsed,"
              f" {new_domains:>8} new,"
              f" {dup_count:>8} dup"
              f"  (running total {len(combined)})")

    total_raw_parsed = sum(parsed for _u, parsed, _n, _d in per_source_counts)
    unique_before_allowlist = len(combined)
    removed_by_dedupe = total_raw_parsed - unique_before_allowlist
    overlap_pct = (
        (removed_by_dedupe / total_raw_parsed * 100.0) if total_raw_parsed else 0.0
    )

    combined = apply_allowlist(combined, allowlist)
    removed_by_allowlist = unique_before_allowlist - len(combined)

    output_path = repo_root / config.get("output", name)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    header_lines = [
        f"MikroTik Adlist - {name}",
        f"Description         : {config.get('description', '')}",
        f"Generated           : {timestamp}",
        f"Sources             : {len(sources)}",
        f"Total raw parsed    : {total_raw_parsed}",
        f"Unique after dedupe : {unique_before_allowlist}",
        f"Removed by dedupe   : {removed_by_dedupe}  ({overlap_pct:.1f}% overlap)",
        f"Removed by allowlist: {removed_by_allowlist}",
        f"Final entries       : {len(combined)}",
        "",
        "Per-source breakdown (parsed / added / dup-against-earlier):",
    ]
    for url, parsed, new_count, dup_count in per_source_counts:
        header_lines.append(
            f"  - {url}  (parsed {parsed}, added {new_count}, dup {dup_count})"
        )
    header_lines.append("")

    write_output(output_path, combined, header_lines)
    print(f"  written: {output_path}  ({len(combined)} entries)")
    print(f"  dedupe : {total_raw_parsed} parsed -> {unique_before_allowlist} unique"
          f"  ({removed_by_dedupe} dups, {overlap_pct:.1f}% overlap)")
    if removed_by_allowlist:
        print(f"  allowlist: removed {removed_by_allowlist} domains")

    return {
        "name": name,
        "output_path": str(output_path.relative_to(repo_root)),
        "entries": len(combined),
        "total_raw_parsed": total_raw_parsed,
        "unique_after_dedupe": unique_before_allowlist,
        "removed_by_dedupe": removed_by_dedupe,
        "overlap_pct": overlap_pct,
        "removed_by_allowlist": removed_by_allowlist,
        "sources": per_source_counts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="sources.yaml")
    parser.add_argument("--allowlist", default="allowlist.txt")
    parser.add_argument("--repo-root", default=".")
    arguments = parser.parse_args()

    repo_root = Path(arguments.repo_root).resolve()
    config_path = (repo_root / arguments.config).resolve()
    allowlist_path = (repo_root / arguments.allowlist).resolve()

    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    with config_path.open("r", encoding="utf-8") as file_handle:
        config = yaml.safe_load(file_handle)

    allowlist = load_allowlist(allowlist_path)
    if allowlist:
        print(f"Loaded {len(allowlist)} allowlist entries from {allowlist_path}")

    outputs = config.get("outputs") or {}
    if not outputs:
        print("No outputs defined in config", file=sys.stderr)
        return 1

    summaries = []
    for output_name, output_config in outputs.items():
        try:
            summary = build_one_output(output_name, output_config, repo_root, allowlist)
            summaries.append(summary)
        except Exception as exception:
            print(f"  FAILED: {exception}", file=sys.stderr)
            return 2

    print("\n=== Summary ===")
    header = (
        f"  {'Output':<28}"
        f" {'Final':>10}"
        f" {'Unique':>10}"
        f" {'Raw':>10}"
        f" {'Dups':>10}"
        f" {'Overlap':>9}"
        f" {'Allow-rm':>9}"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for summary in summaries:
        print(
            f"  {summary['name']:<28}"
            f" {summary['entries']:>10}"
            f" {summary['unique_after_dedupe']:>10}"
            f" {summary['total_raw_parsed']:>10}"
            f" {summary['removed_by_dedupe']:>10}"
            f" {summary['overlap_pct']:>8.1f}%"
            f" {summary['removed_by_allowlist']:>9}"
        )
    print()
    print("  Final  = entries written to file (after dedupe AND allowlist)")
    print("  Unique = unique domains after dedupe, before allowlist")
    print("  Raw    = total parsed across all sources (sum)")
    print("  Dups   = Raw - Unique  (overlap removed by dedupe)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
