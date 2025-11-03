#!/bin/bash

# Configuration
INPUT_FILE="fuzz.text"
RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
RESOLVERS_FILE="resolvers.txt"
OUTPUT_FILE="result_dns.txt"
TEMP_FILE="tmp.txt"

# Wordlists paths
NUMBERS_WORDLIST="/root/subdomain-enum/wordlists/numbers.txt"
SUBDOMAINS_WORDLIST="/root/subdomain-enum/wordlists/2m-subdomains.txt"
REGIONS_WORDLIST="/root/subdomain-enum/wordlists/regions.txt"

# Check if input file exists
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: Input file $INPUT_FILE not found!"
    exit 1
fi

# Check if wordlists exist
for wordlist in "$NUMBERS_WORDLIST" "$SUBDOMAINS_WORDLIST" "$REGIONS_WORDLIST"; do
    if [[ ! -f "$wordlist" ]]; then
        echo "Error: Wordlist $wordlist not found!"
        exit 1
    fi
done

# Download resolvers
echo "Downloading resolvers..."
if command -v wget &> /dev/null; then
    wget -q "$RESOLVERS_URL" -O "$RESOLVERS_FILE"
elif command -v curl &> /dev/null; then
    curl -s "$RESOLVERS_URL" -o "$RESOLVERS_FILE"
else
    echo "Error: Neither wget nor curl found. Please install one of them."
    exit 1
fi

# Check if resolvers file was downloaded successfully
if [[ ! -f "$RESOLVERS_FILE" ]] || [[ ! -s "$RESOLVERS_FILE" ]]; then
    echo "Error: Failed to download resolvers file!"
    exit 1
fi

# Check if massdns is installed
if ! command -v massdns &> /dev/null; then
    echo "Error: massdns is not installed. Please install it first."
    exit 1
fi

# Process each line in the input file
line_number=1
while IFS= read -r line; do
    echo "Processing line $line_number: $line"
    
    # Skip empty lines
    if [[ -z "$line" ]]; then
        echo "Skipping empty line"
        ((line_number++))
        continue
    fi
    
    # Clear temporary file
    > "$TEMP_FILE"
    
    # Check what patterns are present in the line
    if [[ "$line" == *"{fuzz_number}"* ]] && [[ "$line" == *"{fuzz_all}"* ]] && [[ "$line" == *"{region}"* ]]; then
        # All three patterns present
        echo "Processing line with all three patterns..."
        while IFS= read -r number; do
            while IFS= read -r subdomain; do
                while IFS= read -r region; do
                    modified_line="${line//\{fuzz_number\}/$number}"
                    modified_line="${modified_line//\{fuzz_all\}/$subdomain}"
                    modified_line="${modified_line//\{region\}/$region}"
                    echo "$modified_line" >> "$TEMP_FILE"
                done < "$REGIONS_WORDLIST"
            done < "$SUBDOMAINS_WORDLIST"
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_number}"* ]] && [[ "$line" == *"{fuzz_all}"* ]]; then
        # Only fuzz_number and fuzz_all patterns
        echo "Processing line with fuzz_number and fuzz_all patterns..."
        while IFS= read -r number; do
            while IFS= read -r subdomain; do
                modified_line="${line//\{fuzz_number\}/$number}"
                modified_line="${modified_line//\{fuzz_all\}/$subdomain}"
                echo "$modified_line" >> "$TEMP_FILE"
            done < "$SUBDOMAINS_WORDLIST"
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_number}"* ]] && [[ "$line" == *"{region}"* ]]; then
        # Only fuzz_number and region patterns
        echo "Processing line with fuzz_number and region patterns..."
        while IFS= read -r number; do
            while IFS= read -r region; do
                modified_line="${line//\{fuzz_number\}/$number}"
                modified_line="${modified_line//\{region\}/$region}"
                echo "$modified_line" >> "$TEMP_FILE"
            done < "$REGIONS_WORDLIST"
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_all}"* ]] && [[ "$line" == *"{region}"* ]]; then
        # Only fuzz_all and region patterns
        echo "Processing line with fuzz_all and region patterns..."
        while IFS= read -r subdomain; do
            while IFS= read -r region; do
                modified_line="${line//\{fuzz_all\}/$subdomain}"
                modified_line="${modified_line//\{region\}/$region}"
                echo "$modified_line" >> "$TEMP_FILE"
            done < "$REGIONS_WORDLIST"
        done < "$SUBDOMAINS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_number}"* ]]; then
        # Only fuzz_number pattern
        echo "Processing line with fuzz_number pattern..."
        while IFS= read -r number; do
            modified_line="${line//\{fuzz_number\}/$number}"
            echo "$modified_line" >> "$TEMP_FILE"
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_all}"* ]]; then
        # Only fuzz_all pattern
        echo "Processing line with fuzz_all pattern..."
        while IFS= read -r subdomain; do
            modified_line="${line//\{fuzz_all\}/$subdomain}"
            echo "$modified_line" >> "$TEMP_FILE"
        done < "$SUBDOMAINS_WORDLIST"
    
    elif [[ "$line" == *"{region}"* ]]; then
        # Only region pattern
        echo "Processing line with region pattern..."
        while IFS= read -r region; do
            modified_line="${line//\{region\}/$region}"
            echo "$modified_line" >> "$TEMP_FILE"
        done < "$REGIONS_WORDLIST"
    
    else
        # No patterns found, just use the line as is
        echo "No patterns found, using line as is..."
        echo "$line" >> "$TEMP_FILE"
    fi
    
    # Check if temporary file was created and has content
    if [[ ! -f "$TEMP_FILE" ]] || [[ ! -s "$TEMP_FILE" ]]; then
        echo "Error: Temporary file $TEMP_FILE is empty or wasn't created!"
        ((line_number++))
        continue
    fi
    
    echo "Generated $(wc -l < "$TEMP_FILE") subdomains for line $line_number"
    
    # Run massdns
    echo "Running massdns on temporary file..."
    massdns -r "$RESOLVERS_FILE" -t A -o S -w "${TEMP_FILE}.results" --processes 6 --socket-count 3 "$TEMP_FILE"
    
    # Check if massdns produced results
    if [[ -f "${TEMP_FILE}.results" ]] && [[ -s "${TEMP_FILE}.results" ]]; then
        # Add results to output file
        cat "${TEMP_FILE}.results" >> "$OUTPUT_FILE"
        echo "Added $(wc -l < "${TEMP_FILE}.results") results to $OUTPUT_FILE"
        # Remove results file
        rm "${TEMP_FILE}.results"
    else
        echo "No results found for line $line_number"
    fi
    
    # Remove temporary file
    rm "$TEMP_FILE"
    
    echo "Completed processing line $line_number"
    echo "----------------------------------------"
    
    ((line_number++))
    
done < "$INPUT_FILE"

echo "All lines processed successfully!"
echo "Final results saved in: $OUTPUT_FILE"
