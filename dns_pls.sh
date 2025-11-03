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

# Function to validate domain name
validate_domain() {
    local domain="$1"
    
    # Check if domain is too long (DNS limit is 255 chars)
    if [[ ${#domain} -gt 253 ]]; then
        return 1
    fi
    
    # Check for invalid characters or patterns
    if [[ "$domain" =~ [^a-zA-Z0-9.-] ]] || \
       [[ "$domain" == *".."* ]] || \
       [[ "$domain" == *"--"* ]] || \
       [[ "$domain" != *"."* ]]; then
        return 1
    fi
    
    # Check each label (part between dots) doesn't exceed 63 chars
    IFS='.' read -ra labels <<< "$domain"
    for label in "${labels[@]}"; do
        if [[ ${#label} -gt 63 ]]; then
            return 1
        fi
    done
    
    return 0
}

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

# Clean and validate resolvers file
echo "Cleaning resolvers file..."
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$RESOLVERS_FILE" > "${RESOLVERS_FILE}.clean"
mv "${RESOLVERS_FILE}.clean" "$RESOLVERS_FILE"

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
    
    valid_count=0
    total_count=0
    
    # Check what patterns are present in the line
    if [[ "$line" == *"{fuzz_number}"* ]] && [[ "$line" == *"{fuzz_all}"* ]] && [[ "$line" == *"{region}"* ]]; then
        # All three patterns present
        echo "Processing line with all three patterns..."
        while IFS= read -r number && [[ $valid_count -lt 100000 ]]; do
            while IFS= read -r subdomain && [[ $valid_count -lt 100000 ]]; do
                while IFS= read -r region && [[ $valid_count -lt 100000 ]]; do
                    modified_line="${line//\{fuzz_number\}/$number}"
                    modified_line="${modified_line//\{fuzz_all\}/$subdomain}"
                    modified_line="${modified_line//\{region\}/$region}"
                    
                    # Validate domain before writing
                    if validate_domain "$modified_line"; then
                        echo "$modified_line" >> "$TEMP_FILE"
                        ((valid_count++))
                    fi
                    ((total_count++))
                done < <(head -n 100 "$REGIONS_WORDLIST") # Limit regions to prevent explosion
            done < <(head -n 100 "$SUBDOMAINS_WORDLIST") # Limit subdomains
        done < <(head -n 10 "$NUMBERS_WORDLIST") # Limit numbers
    
    elif [[ "$line" == *"{fuzz_number}"* ]] && [[ "$line" == *"{fuzz_all}"* ]]; then
        # Only fuzz_number and fuzz_all patterns
        echo "Processing line with fuzz_number and fuzz_all patterns..."
        while IFS= read -r number && [[ $valid_count -lt 50000 ]]; do
            while IFS= read -r subdomain && [[ $valid_count -lt 50000 ]]; do
                modified_line="${line//\{fuzz_number\}/$number}"
                modified_line="${modified_line//\{fuzz_all\}/$subdomain}"
                
                # Validate domain before writing
                if validate_domain "$modified_line"; then
                    echo "$modified_line" >> "$TEMP_FILE"
                    ((valid_count++))
                fi
                ((total_count++))
            done < <(head -n 1000 "$SUBDOMAINS_WORDLIST") # Limit subdomains
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_number}"* ]] && [[ "$line" == *"{region}"* ]]; then
        # Only fuzz_number and region patterns
        echo "Processing line with fuzz_number and region patterns..."
        while IFS= read -r number && [[ $valid_count -lt 50000 ]]; do
            while IFS= read -r region && [[ $valid_count -lt 50000 ]]; do
                modified_line="${line//\{fuzz_number\}/$number}"
                modified_line="${modified_line//\{region\}/$region}"
                
                # Validate domain before writing
                if validate_domain "$modified_line"; then
                    echo "$modified_line" >> "$TEMP_FILE"
                    ((valid_count++))
                fi
                ((total_count++))
            done < "$REGIONS_WORDLIST"
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_all}"* ]] && [[ "$line" == *"{region}"* ]]; then
        # Only fuzz_all and region patterns
        echo "Processing line with fuzz_all and region patterns..."
        while IFS= read -r subdomain && [[ $valid_count -lt 50000 ]]; do
            while IFS= read -r region && [[ $valid_count -lt 50000 ]]; do
                modified_line="${line//\{fuzz_all\}/$subdomain}"
                modified_line="${modified_line//\{region\}/$region}"
                
                # Validate domain before writing
                if validate_domain "$modified_line"; then
                    echo "$modified_line" >> "$TEMP_FILE"
                    ((valid_count++))
                fi
                ((total_count++))
            done < "$REGIONS_WORDLIST"
        done < <(head -n 1000 "$SUBDOMAINS_WORDLIST") # Limit subdomains
    
    elif [[ "$line" == *"{fuzz_number}"* ]]; then
        # Only fuzz_number pattern
        echo "Processing line with fuzz_number pattern..."
        while IFS= read -r number && [[ $valid_count -lt 100000 ]]; do
            modified_line="${line//\{fuzz_number\}/$number}"
            
            # Validate domain before writing
            if validate_domain "$modified_line"; then
                echo "$modified_line" >> "$TEMP_FILE"
                ((valid_count++))
            fi
            ((total_count++))
        done < "$NUMBERS_WORDLIST"
    
    elif [[ "$line" == *"{fuzz_all}"* ]]; then
        # Only fuzz_all pattern
        echo "Processing line with fuzz_all pattern..."
        while IFS= read -r subdomain && [[ $valid_count -lt 100000 ]]; do
            modified_line="${line//\{fuzz_all\}/$subdomain}"
            
            # Validate domain before writing
            if validate_domain "$modified_line"; then
                echo "$modified_line" >> "$TEMP_FILE"
                ((valid_count++))
            fi
            ((total_count++))
        done < <(head -n 10000 "$SUBDOMAINS_WORDLIST") # Limit to prevent huge files
    
    elif [[ "$line" == *"{region}"* ]]; then
        # Only region pattern
        echo "Processing line with region pattern..."
        while IFS= read -r region && [[ $valid_count -lt 100000 ]]; do
            modified_line="${line//\{region\}/$region}"
            
            # Validate domain before writing
            if validate_domain "$modified_line"; then
                echo "$modified_line" >> "$TEMP_FILE"
                ((valid_count++))
            fi
            ((total_count++))
        done < "$REGIONS_WORDLIST"
    
    else
        # No patterns found, just use the line as is
        echo "No patterns found, using line as is..."
        if validate_domain "$line"; then
            echo "$line" >> "$TEMP_FILE"
            ((valid_count++))
        fi
        ((total_count++))
    fi
    
    echo "Generated $valid_count valid subdomains out of $total_count possible combinations"
    
    # Check if temporary file was created and has content
    if [[ ! -f "$TEMP_FILE" ]] || [[ ! -s "$TEMP_FILE" ]]; then
        echo "Error: Temporary file $TEMP_FILE is empty or wasn't created!"
        ((line_number++))
        continue
    fi
    
    echo "Running massdns on $valid_count subdomains..."
    
    # Run massdns with UDP first (faster) and fallback to TCP if needed
    # Use quieter output and better error handling
    massdns -r "$RESOLVERS_FILE" -t A -o S -w "${TEMP_FILE}.results" \
            --processes 6 --socket-count 3 \
            --root --retry REFUSED --retry SERVFAIL --retry TRUNCATED \
            --drop-group 5 --out-format snapshot \
            "$TEMP_FILE" 2>/dev/null
    
    # Alternative: If UDP has issues, try with lower parallelism
    # massdns -r "$RESOLVERS_FILE" -t A -o S -w "${TEMP_FILE}.results" \
    #         --processes 3 --socket-count 2 \
    #         "$TEMP_FILE" 2>/dev/null
    
    # Check if massdns produced results
    if [[ -f "${TEMP_FILE}.results" ]] && [[ -s "${TEMP_FILE}.results" ]]; then
        # Add results to output file
        cat "${TEMP_FILE}.results" >> "$OUTPUT_FILE"
        result_count=$(wc -l < "${TEMP_FILE}.results")
        echo "Added $result_count results to $OUTPUT_FILE"
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
