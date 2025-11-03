#!/usr/bin/env bash
# run_fuzz_massdns.sh
# Usage: ./run_fuzz_massdns.sh fuzz.text
# Reads fuzz.text line-by-line. For each pattern it expands placeholders:
#   {fuzz_number} -> /root/subdomain-enum/wordlists/numbers.txt
#   {fuzz_all}    -> /root/subdomain-enum/wordlists/2m-subdomains.txt
#   {region}      -> /root/subdomain-enum/wordlists/regions.txt
# Creates tmp.txt for each pattern, runs massdns, appends found domains to result_dns.txt,
# then deletes tmp files and moves to next pattern.
set -euo pipefail

FUZZ_FILE="${1:-}"
if [[ -z "$FUZZ_FILE" || ! -f "$FUZZ_FILE" ]]; then
  echo "Usage: $0 fuzz.text (fuzz.text must exist)"
  exit 2
fi

# Wordlist paths (as requested)
WL_NUM="/root/subdomain-enum/wordlists/numbers.txt"
WL_ALL="/root/subdomain-enum/wordlists/2m-subdomains.txt"
WL_REG="/root/subdomain-enum/wordlists/regions.txt"

# Check wordlists
for wl in "$WL_NUM" "$WL_ALL" "$WL_REG"; do
  if [[ ! -f "$wl" ]]; then
    echo "Warning: wordlist $wl not found. Patterns referencing it will produce no expansions."
  fi
done

# Resolvers URL and local path
RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
RESOLVERS_LOCAL="/tmp/resolvers.txt"

# Massdns options
MASSDNS_BIN="$(command -v massdns || true)"
if [[ -z "$MASSDNS_BIN" ]]; then
  echo "massdns not found in PATH. Please install massdns and ensure it's in PATH."
  exit 3
fi
MASSDNS_OPTS=(--processes 6 --socket-count 3)   # used in CLI form below

# Output result file
RESULT_FILE="result_dns.txt"
touch "$RESULT_FILE"

# safe temp files
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# download resolvers (overwrite local copy)
echo "[*] Downloading resolvers to $RESOLVERS_LOCAL ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$RESOLVERS_URL" -o "$RESOLVERS_LOCAL" || { echo "Failed to download resolvers"; exit 4; }
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$RESOLVERS_LOCAL" "$RESOLVERS_URL" || { echo "Failed to download resolvers"; exit 4; }
else
  echo "curl or wget required to download resolvers."
  exit 4
fi
echo "[*] Resolvers saved to $RESOLVERS_LOCAL (lines: $(wc -l < "$RESOLVERS_LOCAL"))"

# helper: read wordlist to array (preserving lines safely)
read_wordlist_to_array() {
  local file="$1"
  local -n _arr="$2"   # nameref for return
  _arr=()
  if [[ -f "$file" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      _arr+=("$line")
    done < "$file"
  fi
}

# main loop: read fuzz file line by line
line_no=0
while IFS= read -r pattern || [[ -n "$pattern" ]]; do
  ((line_no++))
  pattern="${pattern//[$'\r\n']}"  # strip CR/LF
  [[ -z "$pattern" ]] && continue
  echo "------------------------------------------------------------"
  echo "[*] Processing line $line_no: $pattern"

  # Start with single-element array containing the template
  current=( "$pattern" )

  # Expand {fuzz_number}
  if [[ "$pattern" == *"{fuzz_number}"* ]]; then
    read_wordlist_to_array "$WL_NUM" nums
    new=()
    if [[ ${#nums[@]} -eq 0 ]]; then
      echo "  - Warning: numbers wordlist empty or missing ($WL_NUM). Skipping {fuzz_number} expansion."
      # leave {fuzz_number} unchanged so that further expansions may still work
    else
      for p in "${current[@]}"; do
        for w in "${nums[@]}"; do
          new+=( "${p//\{fuzz_number\}/$w}" )
        done
      done
      current=( "${new[@]}" )
      echo "  - Expanded {fuzz_number} -> ${#current[@]} items"
    fi
  fi

  # Expand {fuzz_all}
  if [[ "${pattern}" == *"{fuzz_all}"* ]]; then
    read_wordlist_to_array "$WL_ALL" alls
    new=()
    if [[ ${#alls[@]} -eq 0 ]]; then
      echo "  - Warning: fuzz_all wordlist empty or missing ($WL_ALL). Skipping {fuzz_all} expansion."
    else
      for p in "${current[@]}"; do
        for w in "${alls[@]}"; do
          new+=( "${p//\{fuzz_all\}/$w}" )
        done
      done
      current=( "${new[@]}" )
      echo "  - Expanded {fuzz_all} -> ${#current[@]} items"
    fi
  fi

  # Expand {region}
  if [[ "${pattern}" == *"{region}"* ]]; then
    read_wordlist_to_array "$WL_REG" regs
    new=()
    if [[ ${#regs[@]} -eq 0 ]]; then
      echo "  - Warning: region wordlist empty or missing ($WL_REG). Skipping {region} expansion."
    else
      for p in "${current[@]}"; do
        for w in "${regs[@]}"; do
          new+=( "${p//\{region\}/$w}" )
        done
      done
      current=( "${new[@]}" )
      echo "  - Expanded {region} -> ${#current[@]} items"
    fi
  fi

  # If no placeholders matched, current still contains original pattern -> write as-is.
  # Write tmp.txt
  TMP_TXT="$TMP_DIR/tmp.txt"
  printf "%s\n" "${current[@]}" > "$TMP_TXT"

  echo "  - tmp file created ($TMP_TXT) with $(wc -l < "$TMP_TXT") entries"

  # Run massdns
  MASSDNS_OUT="$TMP_DIR/massdns.out"
  echo "  - Running massdns (processes 6, socket-count 3) ..."
  # massdns CLI expects options like: massdns -r resolvers -t A -o S --processes 6 --socket-count 3 -w out input
  "$MASSDNS_BIN" -r "$RESOLVERS_LOCAL" -t A -o S --processes 6 --socket-count 3 -w "$MASSDNS_OUT" "$TMP_TXT" || true
  echo "  - massdns finished (output: $MASSDNS_OUT, lines: $(wc -l < "$MASSDNS_OUT"))"

  # Parse results: extract first column (name.) and remove trailing dot, unique, append to result file
  if [[ -s "$MASSDNS_OUT" ]]; then
    # massdns -o S output format typically: <name>. <TYPE> <value>
    awk '{print $1}' "$MASSDNS_OUT" \
      | sed 's/\.$//' \
      | sort -u >> "$RESULT_FILE"
    # ensure uniqueness in global result
    sort -u -o "$RESULT_FILE" "$RESULT_FILE"
    echo "  - Added results to $RESULT_FILE (total lines: $(wc -l < "$RESULT_FILE"))"
  else
    echo "  - No results from massdns for this pattern."
  fi

  # cleanup per pattern
  rm -f "$TMP_TXT" "$MASSDNS_OUT"
  echo "  - Cleaned tmp files for line $line_no"

done < "$FUZZ_FILE"

echo "------------------------------------------------------------"
echo "[*] All lines processed. Final results in: $RESULT_FILE"
