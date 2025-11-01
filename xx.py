#!/usr/bin/env python3
import argparse
import os
import sys
import requests
import subprocess
from itertools import product

RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
OUTPUT_DIR = "dns_fuzz_results"

def download_resolvers(output_path: str):
    print("[+] Downloading latest resolvers list...")
    try:
        r = requests.get(RESOLVERS_URL, timeout=10)
        r.raise_for_status()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(r.text)
        print(f"[+] Resolvers list saved to {output_path}")
    except Exception as e:
        print(f"[!] Failed to download resolvers: {e}")
        sys.exit(1)

def generate_targets(patterns_file: str, wordlist_file: str, targets_file: str):
    print("[+] Generating target domains...")
    with open(patterns_file, "r", encoding="utf-8") as pf, open(wordlist_file, "r", encoding="utf-8") as wf:
        patterns = [p.strip() for p in pf if p.strip()]
        words = [w.strip() for w in wf if w.strip()]
    
    count = 0
    with open(targets_file, "w", encoding="utf-8") as tf:
        for pattern in patterns:
            if "{fuzz" not in pattern:
                print(f"[~] Skipping pattern without FUZZ placeholder: {pattern}")
                continue
            for word in words:
                domain = pattern.replace("{fuzz_all}", word).replace("{fuzz_number}", word).replace("{region}", word)
                tf.write(domain + "\n")
                count += 1
    
    print(f"[+] Generated {count} target domains in {targets_file}")

def run_massdns(resolvers_file: str, targets_file: str, results_file: str):
    print("[+] Running massdns...")
    cmd = ["massdns", "-r", resolvers_file, "-t", "A", "-o", "S", "-w", results_file, targets_file]
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] MassDNS completed successfully. Results saved to {results_file}")
    except subprocess.CalledProcessError:
        print("[!] MassDNS failed.")

def main():
    parser = argparse.ArgumentParser(description="Python version of DNS fuzzing orchestrator")
    parser.add_argument("patterns", help="File containing domain patterns (e.g., output of your fuzz generator)")
    parser.add_argument("wordlist", help="Wordlist for replacement (fuzz values)")
    parser.add_argument("--run-dns", action="store_true", help="Run massdns after generation")
    args = parser.parse_args()

    if not os.path.exists(args.patterns) or not os.path.exists(args.wordlist):
        print("[-] Missing input file(s). Usage: ./dns_fuzz_runner.py patterns.txt wordlist.txt")
        sys.exit(1)
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    resolvers_file = os.path.join(OUTPUT_DIR, "resolvers.txt")
    targets_file = os.path.join(OUTPUT_DIR, "targets.txt")
    results_file = os.path.join(OUTPUT_DIR, "massdns_results.txt")
    
    # Download resolvers
    download_resolvers(resolvers_file)
    
    # Generate targets
    generate_targets(args.patterns, args.wordlist, targets_file)
    
    # Optionally run massdns
    if args.run_dns:
        run_massdns(resolvers_file, targets_file, results_file)
    else:
        print("[i] Skipping massdns (use --run-dns to enable)")

if __name__ == "__main__":
    main()
