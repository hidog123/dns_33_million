#!/usr/bin/env python3
"""
fuzz_runner.py

Usage:
    python3 fuzz_runner.py fuzz.text

Requirements:
    - Python 3.8+
    - massdns installed and in PATH (or set MASSDNS_BIN)
"""
import sys
import os
import tempfile
import subprocess
import urllib.request
from itertools import product

# Config (edit paths if needed)
MASSDNS_BIN = "massdns"  # or full path to massdns binary
RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
RESOLVERS_PATH = "/tmp/resolvers.txt"
RESULT_FILE = "result_dns.txt"

# Wordlist mapping for tokens
WORDLISTS = {
    "{fuzz_number}": "/root/subdomain-enum/wordlists/numbers.txt",
    "{fuzz_all}": "/root/subdomain-enum/wordlists/2m-subdomains.txt",
    "{region}": "/root/subdomain-enum/wordlists/regions.txt",
}

# Safety cap: if total expanded lines for a single pattern exceed this, abort that pattern.
# Set to None to disable cap. Default is high but protective.
MAX_EXPAND = 10_000_000  # adjust or set to None

# Massdns options
MASSDNS_OPTS = ["--processes", "6", "--socket-count", "3"]
# We will ask massdns to output in "simple" format (-o S) and write output to a temp file (-w)
MASSDNS_OUTPUT_TMP = "/tmp/massdns_out.txt"


def download_resolvers(url: str, target_path: str):
    try:
        with urllib.request.urlopen(url) as resp:
            data = resp.read()
            with open(target_path, "wb") as f:
                f.write(data)
        print(f"[+] Resolvers downloaded to {target_path}")
    except Exception as e:
        print(f"[!] Failed to download resolvers from {url}: {e}")
        raise


def load_wordlist(path: str):
    if not os.path.isfile(path):
        print(f"[!] Wordlist not found: {path}")
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        # strip and ignore empty lines
        return [line.strip() for line in f if line.strip()]


def expand_pattern(pattern: str, token_lists: dict):
    """
    token_lists: dict mapping token -> list_of_strings
    Return generator yielding expanded strings (pattern with tokens replaced)
    If no tokens present, yield pattern itself.
    """
    # Find tokens present in the pattern (preserve order in which we will substitute)
    tokens = [tok for tok in token_lists.keys() if tok in pattern]
    if not tokens:
        yield pattern
        return

    lists = [token_lists[t] for t in tokens]
    # If any list is empty, expansion yields nothing
    if any(len(lst) == 0 for lst in lists):
        return

    # check caps
    total = 1
    for lst in lists:
        total *= len(lst)
    if MAX_EXPAND is not None and total > MAX_EXPAND:
        raise RuntimeError(f"Expansion size {total} exceeds MAX_EXPAND ({MAX_EXPAND}). Aborting this pattern.")

    for combo in product(*lists):
        s = pattern
        for tok, repl in zip(tokens, combo):
            s = s.replace(tok, repl)
        yield s


def run_massdns(input_file: str, resolvers_file: str, massdns_out: str):
    """
    Runs massdns and writes its output to massdns_out.
    Returns True if massdns executed (exit code 0), False otherwise.
    """
    cmd = [MASSDNS_BIN, "-r", resolvers_file, "-o", "S", "-w", massdns_out] + MASSDNS_OPTS + [input_file]
    print(f"[+] Running massdns: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        print("[+] massdns finished with returncode", proc.returncode)
        if proc.stderr:
            print("[massdns stderr] ", proc.stderr.strip())
        return proc.returncode == 0 or proc.returncode == 1  # massdns sometimes returns 1 when some queries fail; still parse output
    except FileNotFoundError:
        print(f"[!] massdns not found at '{MASSDNS_BIN}'. Install or set MASSDNS_BIN path.")
        return False


def parse_massdns_simple_output(massdns_out_path: str):
    """
    massdns -o S output format: lines like:
    example.com. A 1.2.3.4
    sub.example.com. CNAME ... 
    We'll parse domain and the record part after the type to log something useful.
    Returns list of strings to append to result file.
    """
    results = []
    if not os.path.isfile(massdns_out_path):
        return results
    with open(massdns_out_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # massdns prints domain with trailing dot; remove it
            parts = line.split()
            if len(parts) < 3:
                continue
            name = parts[0].rstrip(".")
            rtype = parts[1]
            rdata = " ".join(parts[2:])
            # We append only resolved A/AAAA/CNAME records (but keep generic)
            results.append(f"{name} {rtype} {rdata}")
    return results


def append_results(result_lines, result_file=RESULT_FILE):
    with open(result_file, "a", encoding="utf-8") as f:
        for ln in result_lines:
            f.write(ln.rstrip() + "\n")
    print(f"[+] Appended {len(result_lines)} lines to {result_file}")


def main(fuzz_file_path):
    if not os.path.isfile(fuzz_file_path):
        print(f"[!] fuzz file not found: {fuzz_file_path}")
        sys.exit(1)

    # download resolvers (once)
    try:
        download_resolvers(RESOLVERS_URL, RESOLVERS_PATH)
    except Exception:
        print("[!] Unable to obtain resolvers. Exiting.")
        sys.exit(1)

    # pre-load wordlists for speed (but only those actually used in a pattern)
    cached_wordlists = {}

    with open(fuzz_file_path, "r", encoding="utf-8", errors="ignore") as fuzzfile:
        for lineno, raw_line in enumerate(fuzzfile, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            print(f"\n[+] Processing line {lineno}: {line}")

            # determine tokens present and load necessary wordlists
            token_lists = {}
            for token, path in WORDLISTS.items():
                if token in line:
                    if token not in cached_wordlists:
                        print(f"[+] Loading wordlist for {token} from {path} ...")
                        cached_wordlists[token] = load_wordlist(path)
                        print(f"    -> {len(cached_wordlists[token])} entries")
                    token_lists[token] = cached_wordlists[token]

            # Expand pattern and write to tmp file (streaming)
            tmp_fd, tmp_path = tempfile.mkstemp(prefix="massdns_tmp_", suffix=".txt", dir=".")
            os.close(tmp_fd)  # will open normally
            written = 0
            try:
                with open(tmp_path, "w", encoding="utf-8") as tmpf:
                    for expanded in expand_pattern(line, token_lists):
                        tmpf.write(expanded + "\n")
                        written += 1
                print(f"[+] Wrote {written} entries to {tmp_path}")
            except RuntimeError as e:
                print(f"[!] Expansion aborted for pattern on line {lineno}: {e}")
                os.remove(tmp_path)
                continue
            except Exception as e:
                print(f"[!] Failed while expanding/writing tmp file: {e}")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                continue

            if written == 0:
                print("[!] No domains generated for this pattern, skipping massdns run.")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                continue

            # run massdns
            # ensure previous massdns output is removed
            try:
                if os.path.exists(MASSDNS_OUTPUT_TMP):
                    os.remove(MASSDNS_OUTPUT_TMP)
            except Exception:
                pass

            ok = run_massdns(tmp_path, RESOLVERS_PATH, MASSDNS_OUTPUT_TMP)
            if not ok:
                print("[!] massdns failed to start or execute correctly. Results may be incomplete.")

            # parse massdns output and append to result file
            found = parse_massdns_simple_output(MASSDNS_OUTPUT_TMP)
            if found:
                append_results(found, RESULT_FILE)
            else:
                print("[+] No results from massdns for this pattern.")

            # cleanup
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                    print(f"[+] Removed tmp file {tmp_path}")
                if os.path.exists(MASSDNS_OUTPUT_TMP):
                    os.remove(MASSDNS_OUTPUT_TMP)
            except Exception as e:
                print(f"[!] Cleanup error: {e}")

    print("\n[+] All lines processed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 fuzz_runner.py fuzz.text")
        sys.exit(2)
    main(sys.argv[1])
