#!/usr/bin/env python3
"""
Streamed DNS fuzzing runner - strict main-wordlist behavior for {fuzz*}
When a pattern contains {fuzz_all}, {fuzz} or {fuzz_number} and no explicit
wordlist was provided, the script will use ./wordlists/2m-subdomains.txt.
If that file is missing the script aborts (unless --skip-missing is given).
"""
import argparse
import os
import sys
import requests
import subprocess
import tempfile
from typing import Iterator, List, Optional

RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
OUTPUT_DIR = "dns_fuzz_results"
ALIVE_FILE = os.path.join(OUTPUT_DIR, "alive.txt")
DEFAULT_MAIN_WORDLIST = "./wordlists/2m-subdomains.txt"

def download_resolvers(output_path: str):
    try:
        r = requests.get(RESOLVERS_URL, timeout=10)
        r.raise_for_status()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(r.text)
    except Exception as e:
        print(f"[!] Failed to download resolvers: {e}")
        sys.exit(1)

def read_small_list(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def pattern_needs_main(pattern: str) -> bool:
    return any(x in pattern for x in ("{fuzz_all}", "{fuzz}", "{fuzz_number}"))

def pattern_domain_generator(
    pattern: str,
    main_wordlist_path: Optional[str],
    number_words: List[str],
    region_words: List[str],
) -> Iterator[str]:
    needs_main = pattern_needs_main(pattern)
    needs_number = "{number}" in pattern
    needs_region = "{region}" in pattern

    if needs_main and not main_wordlist_path:
        return

    if not needs_main:
        if needs_number and needs_region:
            for n in number_words:
                for r in region_words:
                    yield pattern.replace("{number}", n).replace("{region}", r)
        elif needs_number:
            for n in number_words:
                yield pattern.replace("{number}", n)
        elif needs_region:
            for r in region_words:
                yield pattern.replace("{region}", r)
        else:
            return
    else:
        main_placeholders = []
        if "{fuzz_all}" in pattern:
            main_placeholders.append("{fuzz_all}")
        if "{fuzz}" in pattern:
            main_placeholders.append("{fuzz}")
        if "{fuzz_number}" in pattern:
            main_placeholders.append("{fuzz_number}")

        with open(main_wordlist_path, "r", encoding="utf-8", errors="ignore") as mf:
            for main_word in (w.strip() for w in mf if w.strip()):
                base = pattern
                for ph in main_placeholders:
                    base = base.replace(ph, main_word)

                if needs_number and needs_region:
                    for n in number_words:
                        for r in region_words:
                            yield base.replace("{number}", n).replace("{region}", r)
                elif needs_number:
                    for n in number_words:
                        yield base.replace("{number}", n)
                elif needs_region:
                    for r in region_words:
                        yield base.replace("{region}", r)
                else:
                    yield base

def run_massdns_on_targets(resolvers_file: str, targets_list: List[str], tmp_results_path: str) -> bool:
    if not targets_list:
        return True
    with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8", prefix="md_targets_", dir=OUTPUT_DIR) as tf:
        tmp_targets_path = tf.name
        for t in targets_list:
            tf.write(t + "\n")

    cmd = ["massdns", "-r", resolvers_file, "-t", "A", "-o", "S", "-w", tmp_results_path, tmp_targets_path]
    try:
        subprocess.run(cmd, check=True)
        try:
            os.remove(tmp_targets_path)
        except OSError:
            pass
        return True
    except subprocess.CalledProcessError:
        print("[!] massdns failed on this batch.")
        return False

def parse_massdns_results_for_alive(results_path: str) -> List[str]:
    alive = []
    if not os.path.exists(results_path):
        return alive
    with open(results_path, "r", encoding="utf-8", errors="ignore") as rf:
        for line in rf:
            parts = line.split()
            if len(parts) >= 3 and parts[1].upper() == "A":
                alive.append(parts[0].rstrip("."))
    return alive

def append_alive(alive_list: List[str], seen_alive: set):
    if not alive_list:
        return
    with open(ALIVE_FILE, "a", encoding="utf-8") as af:
        for d in alive_list:
            if d not in seen_alive:
                af.write(d + "\n")
                seen_alive.add(d)
    print(f"[+] Found {len(alive_list)} alive (this batch). Total unique alive so far: {len(seen_alive)}")

def process_patterns_stream(
    patterns_file: str,
    main_wordlist: Optional[str],
    resolvers_file: str,
    number_file: str,
    region_file: str,
    batch_size: int = 1000,
    max_per_pattern: Optional[int] = None,
    skip_missing_main: bool = False,
):
    number_words = read_small_list(number_file)
    region_words = read_small_list(region_file)

    seen_alive = set()
    if os.path.exists(ALIVE_FILE):
        with open(ALIVE_FILE, "r", encoding="utf-8") as af:
            for l in af:
                seen_alive.add(l.strip())

    with open(patterns_file, "r", encoding="utf-8") as pf:
        patterns = [p.strip() for p in pf if p.strip()]

    for pattern in patterns:
        print(f"[+] Processing pattern: {pattern}")
        needs_main = pattern_needs_main(pattern)
        if needs_main and not main_wordlist:
            msg = f"[!] Pattern requires main wordlist but none found: {pattern}"
            if skip_missing_main:
                print(msg + " (skipping due to --skip-missing)")
                continue
            else:
                print(msg)
                print(f"[!] Expected main wordlist at: {DEFAULT_MAIN_WORDLIST} (or pass explicit path as 2nd arg). Aborting.")
                sys.exit(2)

        gen = pattern_domain_generator(pattern, main_wordlist, number_words, region_words)

        batch = []
        processed_for_pattern = 0
        batch_count = 0
        for domain in gen:
            batch.append(domain)
            processed_for_pattern += 1

            if max_per_pattern and processed_for_pattern >= max_per_pattern:
                if batch:
                    batch_count += 1
                    tmp_results = os.path.join(OUTPUT_DIR, f"massdns_{os.getpid()}_{batch_count}.txt")
                    ok = run_massdns_on_targets(resolvers_file, batch, tmp_results)
                    if ok:
                        alive = parse_massdns_results_for_alive(tmp_results)
                        append_alive(alive, seen_alive)
                    try:
                        os.remove(tmp_results)
                    except OSError:
                        pass
                print(f"[i] Reached max-per-pattern ({max_per_pattern}) for pattern: {pattern}")
                break

            if len(batch) >= batch_size:
                batch_count += 1
                tmp_results = os.path.join(OUTPUT_DIR, f"massdns_{os.getpid()}_{batch_count}.txt")
                ok = run_massdns_on_targets(resolvers_file, batch, tmp_results)
                if ok:
                    alive = parse_massdns_results_for_alive(tmp_results)
                    append_alive(alive, seen_alive)
                try:
                    os.remove(tmp_results)
                except OSError:
                    pass
                batch = []

        if batch:
            batch_count += 1
            tmp_results = os.path.join(OUTPUT_DIR, f"massdns_{os.getpid()}_{batch_count}.txt")
            ok = run_massdns_on_targets(resolvers_file, batch, tmp_results)
            if ok:
                alive = parse_massdns_results_for_alive(tmp_results)
                append_alive(alive, seen_alive)
            try:
                os.remove(tmp_results)
            except OSError:
                pass

        print(f"[+] Finished pattern: {pattern} (tested {processed_for_pattern} names)")

def main():
    parser = argparse.ArgumentParser(description="Streamed DNS fuzzing runner (pattern-by-pattern, batch checks)")
    parser.add_argument("patterns", help="File containing domain patterns (e.g., output of your fuzz generator)")
    parser.add_argument("wordlist", nargs="?", default=None, help="Main wordlist for generic FUZZ placeholders (if omitted, ./wordlists/2m-subdomains.txt is used when needed)")
    parser.add_argument("--number-file", default="number.txt", help="Wordlist for {number} placeholder (default: number.txt)")
    parser.add_argument("--region-file", default="region.txt", help="Wordlist for {region} placeholder (default: region.txt)")
    parser.add_argument("--batch-size", type=int, default=1000, help="Number of names to resolve per massdns run (default: 1000)")
    parser.add_argument("--max-per-pattern", type=int, default=0, help="Optional cap: max names to generate/test per pattern (0 = no cap)")
    parser.add_argument("--run-dns", action="store_true", help="Actually run massdns (for testing you can omit to only dry-run generation)")
    parser.add_argument("--skip-missing", action="store_true", help="If set, patterns that require the main wordlist will be skipped instead of aborting")
    args = parser.parse_args()

    if not os.path.exists(args.patterns):
        print(f"[-] Missing patterns file: {args.patterns}")
        sys.exit(1)

    # Decide main wordlist path:
    # 1) explicit CLI arg
    # 2) if omitted, we'll use DEFAULT_MAIN_WORDLIST when a pattern requires it
    main_wordlist = None
    if args.wordlist:
        if os.path.exists(args.wordlist) and os.path.isfile(args.wordlist):
            main_wordlist = args.wordlist
        else:
            print(f"[!] Provided wordlist path does not exist: {args.wordlist}")
            # still allow fallback to default if that exists
    if not main_wordlist and os.path.exists(DEFAULT_MAIN_WORDLIST):
        main_wordlist = DEFAULT_MAIN_WORDLIST

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    resolvers_file = os.path.join(OUTPUT_DIR, "resolvers.txt")
    if not os.path.exists(resolvers_file):
        download_resolvers(resolvers_file)

    # Dry-run behavior: monkeypatch run_massdns_on_targets to avoid actual DNS queries
    if not args.run_dns:
        print("[i] Dry-run mode (no massdns). To actually resolve, add --run-dns")
        original_run = globals()['run_massdns_on_targets']
        globals()['run_massdns_on_targets'] = lambda *a, **k: True
        process_patterns_stream(
            args.patterns, main_wordlist, resolvers_file,
            args.number_file, args.region_file, batch_size=args.batch_size,
            max_per_pattern=(args.max_per_pattern or None),
            skip_missing_main=args.skip_missing
        )
        globals()['run_massdns_on_targets'] = original_run
        print("[i] Dry-run complete.")
        return

    # Real run
    process_patterns_stream(
        args.patterns, main_wordlist, resolvers_file,
        args.number_file, args.region_file, batch_size=args.batch_size,
        max_per_pattern=(args.max_per_pattern or None),
        skip_missing_main=args.skip_missing
    )
    print(f"[+] All done. Alive domains written to: {ALIVE_FILE}")

if __name__ == "__main__":
    main()
