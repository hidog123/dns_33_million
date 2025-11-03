#!/usr/bin/env python3
import sys
import os
import tempfile
import subprocess
import urllib.request
from itertools import product

# === CONFIG ===
MASSDNS_BIN = "massdns"
RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
RESOLVERS_PATH = "/tmp/resolvers.txt"
RESULT_FILE = "result_dns.txt"

WORDLISTS = {
    "{fuzz_number}": "/root/subdomain-enum/wordlists/numbers.txt",
    "{fuzz_all}": "/root/subdomain-enum/wordlists/2m-subdomains.txt",
    "{region}": "/root/subdomain-enum/wordlists/regions.txt",
}

MASSDNS_OPTS = ["--processes", "6", "--socket-count", "3"]
MAX_EXPAND = 10_000_000  # safety cap


def download_resolvers():
    """Always download fresh resolvers before each test."""
    print(f"[+] Downloading resolvers from {RESOLVERS_URL}")
    try:
        with urllib.request.urlopen(RESOLVERS_URL) as r:
            with open(RESOLVERS_PATH, "wb") as f:
                f.write(r.read())
        print(f"[+] Resolvers saved to {RESOLVERS_PATH}")
    except Exception as e:
        print(f"[!] Failed to download resolvers: {e}")
        sys.exit(1)


def load_wordlist(path):
    if not os.path.exists(path):
        print(f"[!] Missing wordlist: {path}")
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def expand_pattern(pattern, wordlists):
    tokens = [t for t in wordlists if t in pattern]
    if not tokens:
        yield pattern
        return
    lists = [wordlists[t] for t in tokens]
    total = 1
    for lst in lists:
        total *= len(lst)
    if MAX_EXPAND and total > MAX_EXPAND:
        raise RuntimeError(f"Expansion too large ({total} > {MAX_EXPAND})")
    for combo in product(*lists):
        s = pattern
        for t, w in zip(tokens, combo):
            s = s.replace(t, w)
        yield s


def run_massdns(input_file):
    output_file = "/tmp/massdns_out.txt"
    if os.path.exists(output_file):
        os.remove(output_file)

    cmd = [MASSDNS_BIN, "-r", RESOLVERS_PATH, "-o", "S", "-w", output_file] + MASSDNS_OPTS + [input_file]
    print(f"[+] Running: {' '.join(cmd)}")
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return output_file if os.path.exists(output_file) else None


def parse_massdns_output(output_file):
    """Return set of unique resolved domains."""
    results = set()
    if not os.path.exists(output_file):
        return results
    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            domain = parts[0].rstrip(".")
            results.add(domain)
    return results


def append_results(domains):
    if not domains:
        return
    with open(RESULT_FILE, "a", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(d + "\n")
    print(f"[+] {len(domains)} domains added to {RESULT_FILE}")


def main(fuzz_file):
    if not os.path.exists(fuzz_file):
        print(f"[!] File not found: {fuzz_file}")
        sys.exit(1)

    with open(fuzz_file, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            pattern = line.strip()
            if not pattern or pattern.startswith("#"):
                continue

            print(f"\n[+] Processing line {i}: {pattern}")

            # Download resolvers for each line
            download_resolvers()

            # Load relevant wordlists
            token_lists = {}
            for token, path in WORDLISTS.items():
                if token in pattern:
                    token_lists[token] = load_wordlist(path)

            # Create temp list of targets
            tmp_fd, tmp_path = tempfile.mkstemp(prefix="massdns_", suffix=".txt")
            os.close(tmp_fd)
            try:
                with open(tmp_path, "w", encoding="utf-8") as tmpf:
                    count = 0
                    for expanded in expand_pattern(pattern, token_lists):
                        tmpf.write(expanded + "\n")
                        count += 1
                print(f"[+] Generated {count} targets in {tmp_path}")
            except Exception as e:
                print(f"[!] Expansion error: {e}")
                os.remove(tmp_path)
                continue

            # Run massdns and parse results
            output_file = run_massdns(tmp_path)
            if not output_file:
                print("[!] Massdns output not found!")
                os.remove(tmp_path)
                continue

            domains = parse_massdns_output(output_file)
            if domains:
                append_results(domains)
            else:
                print("[!] No valid results found, but massdns may have resolved some.")

            # Cleanup
            os.remove(tmp_path)
            if os.path.exists(output_file):
                os.remove(output_file)
            print("[+] Cleaned temporary files.")

    print("\n[+] All done! Results saved in:", RESULT_FILE)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 fuzz_runner.py fuzz.text")
        sys.exit(1)
    main(sys.argv[1])
