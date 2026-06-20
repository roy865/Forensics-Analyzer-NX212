#!/bin/bash

############################################################
# Project: WINDOWS FORENSICS | PROJECT: ANALYZER
# Student Name: Roy Mastrov
# Student ID: s23
# Unit Name: TMagen773639
# Program Code: NX212
# Lecturer Name: Zach Azoalis
# Description: Automated HDD and Memory Forensic Analyzer
############################################################

# --- Colors (Fixed Formatting) ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

# --- Settings & Trap ---
hide_cursor() { tput civis; }
show_cursor() { tput cnorm; }
trap "show_cursor; exit" INT TERM EXIT

# --- UI Functions ---
show_progress() {
    local task=$1
    local duration=$2
    for i in {1..10}; do
        local percent=$((i*10))
        local bar=$(printf "%${i}s" | tr ' ' '#')
        printf "\r${BLUE}[*] %-25s${NC} [${GREEN}%-10s${NC}] %d%%\e[K" "$task" "$bar" "$percent"
        sleep 0.2
    done
    echo ""
}

# --- 1.1 Check Root ---
check_root() { 
    if [[ $EUID -ne 0 ]]; then 
        echo -e "${RED}[!] Error: This script must be run as root (sudo).${NC}"
        exit 1
    fi 
}

# --- 1.3 Install Forensics Tools (Optimized) ---
install_tools() {
    echo -e "${BLUE}[*] Checking Forensics Environment...${NC}"
    local tools=("bulk-extractor" "binwalk" "foremost" "zip" "strings" "volatility")
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            echo -e " ${GREEN}[V]${NC} $tool is ready."
        else
            echo -e " ${RED}[X]${NC} $tool is missing."
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}[+] Missing tools detected. Updating and installing: ${missing_tools[*]}...${NC}"
        apt-get update > /dev/null 2>&1
        for tool in "${missing_tools[@]}"; do
            apt-get install -y $tool > /dev/null 2>&1
            echo -e " ${GREEN}✔${NC} $tool installed successfully."
        done
        echo -e "${GREEN}[V] All tools are now installed.${NC}"
    else
        echo -e "${GREEN}[V] Environment is perfect. No installation needed.${NC}"
    fi
}

# --- Main Execution Flow ---
hide_cursor
clear
echo -e "${BLUE}==========================================${NC}"
echo -e "      WINDOWS FORENSICS ANALYZER NX212    "
echo -e "      Investigator: Roy Mastrov           "
echo -e "${BLUE}==========================================${NC}"

check_root
install_tools

# --- 1.2 User Input & File Check ---
echo -e "\n${YELLOW}Enter the path to the evidence file (HDD or Memory):${NC}"
show_cursor
read -p "> " TARGET_INPUT
hide_cursor
TARGET_FILE=$(eval echo "$TARGET_INPUT")

if [[ ! -f "$TARGET_FILE" ]]; then
    echo -e "${RED}[!] Error: File '$TARGET_FILE' does not exist.${NC}"
    show_cursor && exit 1
fi

START_TIME=$(date +%s)
OUT_DIR="Analysis_Report_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"
REPORT_FILE="$OUT_DIR/summary_report.txt"

echo -e "\n${BLUE}[Starting Forensic Investigation on: $TARGET_FILE]${NC}"

# --- 1.4 & 1.5 Carving & Extraction ---
show_progress "Integrity (Hashing)" 1
sha256sum "$TARGET_FILE" > "$OUT_DIR/file_hashes.txt"

show_progress "Foremost Carving" 2
foremost -i "$TARGET_FILE" -o "$OUT_DIR/foremost_output" 2>/dev/null

show_progress "Binwalk Analysis" 2
binwalk "$TARGET_FILE" > "$OUT_DIR/binwalk_report.txt" 2>&1

show_progress "Bulk Extractor Artifacts" 3
bulk_extractor -o "$OUT_DIR/bulk_output" "$TARGET_FILE" > /dev/null 2>&1

# --- 1.6 Network Traffic Detection ---
PCAP_COUNT=$(find "$OUT_DIR" -name "*.pcap" | wc -l)
if [ "$PCAP_COUNT" -gt 0 ]; then
    echo -e "${GREEN}[+] Network traffic (PCAP) found! Files: $PCAP_COUNT${NC}"
fi

# --- 1.7 Human Readable Search (Strings) ---
show_progress "Scanning for Credentials" 2
strings "$TARGET_FILE" | grep -Ei "pass|user|admin|login" > "$OUT_DIR/potential_creds.txt"

# --- 2. Memory Analysis (Volatility) ---
echo -e "${YELLOW}[*] Attempting Volatility Memory Analysis...${NC}"
PROFILE=$(volatility -f "$TARGET_FILE" imageinfo 2>/dev/null | grep "Suggested Profile(s)" | awk -F': ' '{print $2}' | cut -d',' -f1 | tr -d ' ')

if [ -n "$PROFILE" ] && [[ "$PROFILE" != *"No"* ]]; then
    echo -e "${GREEN}[+] Memory Profile Identified: $PROFILE${NC}"
    volatility -f "$TARGET_FILE" --profile=$PROFILE pslist > "$OUT_DIR/memory_processes.txt" 2>/dev/null
    volatility -f "$TARGET_FILE" --profile=$PROFILE netscan > "$OUT_DIR/memory_network.txt" 2>/dev/null
    volatility -f "$TARGET_FILE" --profile=$PROFILE hivelist > "$OUT_DIR/memory_registry.txt" 2>/dev/null
    show_progress "Volatility Analysis" 3
else
    echo -e "${RED}[-] Not a recognizable memory dump, skipping Volatility steps.${NC}"
fi

# --- 3.1 & 3.2 Results & Statistics ---
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
FOUND_FILES=$(find "$OUT_DIR" -type f | wc -l)

{
    echo "WINDOWS FORENSICS REPORT - NX212"
    echo "================================="
    echo "Investigator: Roy Mastrov"
    echo "Student ID: s23"
    echo "File Analyzed: $TARGET_FILE"
    echo "Analysis Duration: $TOTAL_TIME seconds"
    echo "Total Artifacts Extracted: $FOUND_FILES"
    echo "================================="
} > "$REPORT_FILE"

# --- 3.3 Zip Everything ---
show_progress "Archiving Evidence" 1
zip -r "${OUT_DIR}.zip" "$OUT_DIR" > /dev/null

echo -e "\n${GREEN}✔ Investigation Complete!${NC}"
echo -e "${BLUE}[!] Statistics:${NC} $FOUND_FILES files found in $TOTAL_TIME seconds."
echo -e "${BLUE}[!] Results Packed:${NC} ${OUT_DIR}.zip"
show_cursor
