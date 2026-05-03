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

# PyYAML is the only third-party dep (installed by the workflow).
import yaml


# Hosts-file parsing
# Each line in a hosts file looks like:
#   0.0.0.0 ads.example.com  # optional comment
# or sometimes just a bare domain:
#   ads.example.com
# We accept both. Any number of domains per line is allowed.

# Strict-ish domain validator. Lowercased. ASCII or punycode (xn--).
# Rejects IPs, IPv6, localhost, and obviously broken entries.
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z]{2,63}$"
)

# Things we should never block even if a source list contains them.
HARD_BUILTIN_ALLOWLIST = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
}

# Lines that are "0.0.0.0 something" but the something is not a domain
# (e.g. an IP address) get silently dropped.
IP_PREFIX_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def fetch_url(url: str, timeout: int = 60, retries: int = 3) -> str:
    """Fetch a URL and return its decoded text. Handles gzip transparently."""
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
                # Hosts files are normally UTF-8 or ASCII; tolerate BOMs.
                return raw.decode("utf-8-sig", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as err:
            last_err = err
            print(f"  ! attempt {attempt}/{retries} failed: {err}", file=sys.stderr)
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


def parse_hosts_text(text: str) -> set[str]:
    """Parse hosts-file (or bare-domain) text into a set of lowercased domains."""
    domains: set[str] = set()

    for line_raw in text.splitlines():
        # Strip inline comments (anything after '#')
        line = line_raw.split("#", 1)[0].strip()
        if not line:
            continue

        # Tokenize on any whitespace.
        tokens = line.split()

        # If the line starts with a hosts-file IP prefix, drop it.
        if tokens and (
            tokens[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}
            or IP_PREFIX_REGEX.match(tokens[0])
        ):
            tokens = tokens[1:]

        for token in tokens:
            domain = token.lower().rstrip(".")
            # Strip leading wildcards like "*." or "||" (AdGuard syntax).
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


def load_allowlist(path: Path) -> set[str]:
    """Load user-managed allowlist (one domain per line, '#' comments)."""
    allowed: set[str] = set()
    if not path.exists():
        return allowed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower().rstrip(".")
        if line:
            allowed.add(line)
    return allowed


def apply_allowlist(domains: set[str], allowlist: set[str]) -> set[str]:
    """
    Remove any domain that exactly matches an allowlist entry, or that is a
    sub-domain of an allowlist entry. So 'apis.google.com' is removed if
    'google.com' is in the allowlist.
    """
    if not allowlist:
        return domains

    result: set[str] = set()
    # Sort allowlist by length descending, but we use suffix match anyway.
    for domain in domains:
        keep = True
        # Check exact match and parent matches.
        parts = domain.split(".")
        for index in range(len(parts) - 1):
            candidate = ".".join(parts[index:])
            if candidate in allowlist:
                keep = False
                break
        if keep:
            result.add(domain)
    return result


def write_output(path: Path, domains: set[str], header_lines: list[str]) -> None:
    """Write a sorted hosts-format file. RouterOS Adlist parses 0.0.0.0 prefix."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as file_handle:
        for header_line in header_lines:
            file_handle.write(f"# {header_line}\n")
        file_handle.write("#\n")

        for domain in sorted(domains):
            file_handle.write(f"0.0.0.0 {domain}\n")


def build_one_output(name: str, config: dict, repo_root: Path, allowlist: set[str]) -> dict:
    """Fetch all sources for one output, merge, write, and return stats."""
    print(f"\n=== Building {name} ===")
    sources = config.get("sources", [])
    if not sources:
        raise ValueError(f"Output '{name}' has no sources")

    combined: set[str] = set()
    per_source_counts: list[tuple[str, int, int]] = []

    for url in sources:
        print(f"  -> fetching {url}")
        text = fetch_url(url)
        domains_from_source = parse_hosts_text(text)
        new_domains = len(domains_from_source - combined)
        per_source_counts.append((url, len(domains_from_source), new_domains))
        combined |= domains_from_source
        print(f"     {len(domains_from_source):>8} parsed,"
              f" {new_domains:>8} new (running total {len(combined)})")

    before_allowlist = len(combined)
    combined = apply_allowlist(combined, allowlist)
    removed_by_allowlist = before_allowlist - len(combined)

    output_path = repo_root / config.get("output", name)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    header_lines = [
        f"MikroTik Adlist - {name}",
        f"Description : {config.get('description', '')}",
        f"Generated   : {timestamp}",
        f"Entries     : {len(combined)}",
        f"Sources     : {len(sources)}",
        "",
    ]
    for url, total, new_count in per_source_counts:
        header_lines.append(f"  - {url}  (parsed {total}, added {new_count})")
    header_lines.append("")
    if removed_by_allowlist:
        header_lines.append(f"Removed by allowlist: {removed_by_allowlist}")

    write_output(output_path, combined, header_lines)
    print(f"  written: {output_path}  ({len(combined)} entries)")

    return {
        "name": name,
        "output_path": str(output_path.relative_to(repo_root)),
        "entries": len(combined),
        "removed_by_allowlist": removed_by_allowlist,
        "sources": per_source_counts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="sources.yaml",
        help="Path to sources.yaml (default: sources.yaml in repo root)",
    )
    parser.add_argument(
        "--allowlist",
        default="allowlist.txt",
        help="Path to allowlist.txt (default: allowlist.txt in repo root)",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root where outputs are written (default: current dir)",
    )
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
    for summary in summaries:
        print(f"  {summary['name']:<24} {summary['entries']:>8} entries"
              f"  ->  {summary['output_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
