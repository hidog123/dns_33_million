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
ALIVE_FILE = os.path.join(OUTPUT_DIR, "output.txt")  # user asked for output.txt
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
    """
    Generate domain names for a single pattern. This yields names lazily.
    If the pattern requires main_wordlist_path and it's None, this generator yields nothing.
    """
    needs_main = pattern_needs_main(pattern)
    needs_number = "{number}" in pattern
    needs_region = "{region}" in pattern

    if needs_main and not main_wordlist_path:
        # Caller should handle this situation (abort/skip) — generator yields nothing.
        return

    # If no main placeholders, only expand number/region placeholders (if present).
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
            # nothing to do (pattern contains none of the handled placeholders)
            return
    else:
        # pattern needs the main wordlist: replace all main placeholders with each main word
        main_placeholders = []
        if "{fuzz_all}" in pattern:
            main_placeholders.append("{fuzz_all}")
        if "{fuzz}" in pattern:
            main_placeholders.append("{fuzz}")
        if "{fuzz_number}" in pattern:
            main_placeholders.append("{fuzz_number}")

        # Stream the large file to avoid memory blowout
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

def run_massdns_on_targets(
    massdns_bin: str,
    resolvers_file: str,
    targets_list: List[str],
    tmp_results_path: str,
    processes: int,
    socket_count: int,
    hashmap_size: int,
) -> bool:
    """
    Run massdns against the provided list of targets (written to a temp file).
    Returns True on success (massdns exit 0) or False otherwise.
    """
    if not targets_list:
        return True
    with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8", prefix="md_targets_", dir=OUTPUT_DIR) as tf:
        tmp_targets_path = tf.name
        for t in targets_list:
            tf.write(t + "\n")

    # Build massdns command
    # -r <resolvers> --processes <n> --socket-count <n> -s <hashmap-size> -t A -o S -w <outfile> <targetsfile>
    cmd = [
        massdns_bin,
        "-r", resolvers_file,
        "--processes", str(processes),
        "--socket-count", str(socket_count),
        "-s", str(hashmap_size),
        "-t", "A",
        "-o", "S",
        "-w", tmp_results_path,
        tmp_targets_path
    ]
    try:
        subprocess.run(cmd, check=True)
        try:
            os.remove(tmp_targets_path)
        except OSError:
            pass
        return True
    except subprocess.CalledProcessError:
        print("[!] massdns failed on this batch.")
        try:
            os.remove(tmp_targets_path)
        except OSError:
            pass
        return False
    except FileNotFoundError:
        print(f"[!] massdns binary not found at: {massdns_bin}")
        try:
            os.remove(tmp_targets_path)
        except OSError:
            pass
        return False

def parse_massdns_results_for_alive(results_path: str) -> List[str]:
    alive = []
    if not os.path.exists(results_path):
        return alive
    with open(results_path, "r", encoding="utf-8", errors="ignore") as rf:
        for line in rf:
            parts = line.split()
            # massdns simple output: <name> <type> <data> ...
            if len(parts) >= 3 and parts[1].upper() == "A":
                # strip trailing dot if present
                name = parts[0].rstrip(".")
                alive.append(name)
    # unique
    return list(dict.fromkeys(alive))

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
    massdns_bin: str = "massdns",
    processes: int = 1,
    socket_count: int = 1,
    hashmap_size: int = 10000,
    run_dns: bool = False,
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
            msg = f"[!] Pattern requires main wordlist but none provided/found: {pattern}"
            if skip_missing_main:
                print(msg + " (skipping due to --skip-missing)")
                continue
            else:
                print(msg)
                print(f"[!] Expected main wordlist at: {DEFAULT_MAIN_WORDLIST} (or pass explicit path). Aborting.")
                sys.exit(2)

        gen = pattern_domain_generator(pattern, main_wordlist, number_words, region_words)

        batch = []
        processed_for_pattern = 0
        batch_count = 0
        for domain in gen:
            batch.append(domain)
            processed_for_pattern += 1

            if max_per_pattern and processed_for_pattern >= max_per_pattern:
                # flush remaining batch then break
                if batch:
                    batch_count += 1
                    tmp_results = os.path.join(OUTPUT_DIR, f"massdns_{os.getpid()}_{batch_count}.txt")
                    if run_dns:
                        ok = run_massdns_on_targets(massdns_bin, resolvers_file, batch, tmp_results, processes, socket_count, hashmap_size)
                        if ok:
                            alive = parse_massdns_results_for_alive(tmp_results)
                            append_alive(alive, seen_alive)
                    else:
                        print(f"[i] (dry-run) would run massdns on {len(batch)} names -> {tmp_results}")
                    try:
                        os.remove(tmp_results)
                    except OSError:
                        pass
                print(f"[i] Reached max-per-pattern ({max_per_pattern}) for pattern: {pattern}")
                break

            if len(batch) >= batch_size:
                batch_count += 1
                tmp_results = os.path.join(OUTPUT_DIR, f"massdns_{os.getpid()}_{batch_count}.txt")
                if run_dns:
                    ok = run_massdns_on_targets(massdns_bin, resolvers_file, batch, tmp_results, processes, socket_count, hashmap_size)
                    if ok:
                        alive = parse_massdns_results_for_alive(tmp_results)
                        append_alive(alive, seen_alive)
                else:
                    print(f"[i] (dry-run) would run massdns on {len(batch)} names -> {tmp_results}")
                try:
                    os.remove(tmp_results)
                except OSError:
                    pass
                batch = []

        # final flush for this pattern
        if batch:
            batch_count += 1
            tmp_results = os.path.join(OUTPUT_DIR, f"massdns_{os.getpid()}_{batch_count}.txt")
            if run_dns:
                ok = run_massdns_on_targets(massdns_bin, resolvers_file, batch, tmp_results, processes, socket_count, hashmap_size)
                if ok:
                    alive = parse_massdns_results_for_alive(tmp_results)
                    append_alive(alive, seen_alive)
            else:
                print(f"[i] (dry-run) would run massdns on {len(batch)} names -> {tmp_results}")
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
    parser.add_argument("--massdns-bin", default="massdns", help="Path to massdns binary (default: massdns on PATH)")
    parser.add_argument("--processes", type=int, default=1, help="massdns --processes value (default: 1)")
    parser.add_argument("--socket-count", type=int, default=1, help="massdns --socket-count value (default: 1)")
    parser.add_argument("--hashmap-size", type=int, default=10000, help="massdns -s (hashmap-size) value (default: 10000)")
    args = parser.parse_args()

    if not os.path.exists(args.patterns):
        print(f"[-] Missing patterns file: {args.patterns}")
        sys.exit(1)

    # Decide main wordlist path:
    # Behavior:
    #  - If user supplied a wordlist but it does not exist -> abort unless --skip-missing provided
    #  - If user did not supply a wordlist -> use DEFAULT_MAIN_WORDLIST only if present
    main_wordlist = None
    if args.wordlist:
        if os.path.exists(args.wordlist) and os.path.isfile(args.wordlist):
            main_wordlist = args.wordlist
        else:
            print(f"[!] Provided wordlist path does not exist: {args.wordlist}")
            if not args.skip_missing:
                print("[!] Aborting due to missing provided wordlist (use --skip-missing to continue without it).")
                sys.exit(2)
            else:
                print("[i] --skip-missing set, continuing without main wordlist.")

    if not main_wordlist and os.path.exists(DEFAULT_MAIN_WORDLIST):
        main_wordlist = DEFAULT_MAIN_WORDLIST

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    resolvers_file = os.path.join(OUTPUT_DIR, "resolvers.txt")
    if not os.path.exists(resolvers_file):
        download_resolvers(resolvers_file)

    # Dry-run behavior: monkeypatch run_massdns_on_targets to avoid actual DNS queries
    if not args.run_dns:
        print("[i] Dry-run mode (no massdns). To actually resolve, add --run-dns")
        process_patterns_stream(
            args.patterns, main_wordlist, resolvers_file,
            args.number_file, args.region_file, batch_size=args.batch_size,
            max_per_pattern=(args.max_per_pattern or None),
            skip_missing_main=args.skip_missing,
            massdns_bin=args.massdns_bin,
            processes=args.processes,
            socket_count=args.socket_count,
            hashmap_size=args.hashmap_size,
            run_dns=False,
        )
        print("[i] Dry-run complete.")
        return

    # Real run
    process_patterns_stream(
        args.patterns, main_wordlist, resolvers_file,
        args.number_file, args.region_file, batch_size=args.batch_size,
        max_per_pattern=(args.max_per_pattern or None),
        skip_missing_main=args.skip_missing,
        massdns_bin=args.massdns_bin,
        processes=args.processes,
        socket_count=args.socket_count,
        hashmap_size=args.hashmap_size,
        run_dns=True,
    )
    print(f"[+] All done. Alive domains written to: {ALIVE_FILE}")

if __name__ == "__main__":
    main()
