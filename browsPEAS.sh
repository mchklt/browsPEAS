#!/bin/bash

set -euo pipefail

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

banner() {
  echo -e "${GREEN}[+] browsPEAS - Browser Scraper By @mchklt${RESET}"
}

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]
Options:
  -l, --list        List available browser directories
  -b, --browsers    Comma-separated browser names to scan (default: detected)
  -h, --help        Show this help menu

Available Browsers:
  firefox, chrome, chromium, brave, brave-browser, opera

Example:
  $0 -b firefox,chrome
EOF
  exit 0
}

declare -A BROWSER_PATHS=(
  [firefox]="$HOME/.mozilla/firefox"
  [chrome]="$HOME/.config/google-chrome"
  [chromium]="$HOME/.config/chromium"
  [brave]="$HOME/.config/brave"
  [brave-browser]="$HOME/.config/brave-browser"
  [opera]="$HOME/.config/opera"
)

detect_browsers() {
  DETECTED=()
  for key in "${!BROWSER_PATHS[@]}"; do
    if [ -d "${BROWSER_PATHS[$key]}" ]; then
      DETECTED+=("$key")
    fi
  done
}

list_browsers() {
  detect_browsers
  echo -e "${YELLOW}Available browser profiles on this machine:${RESET}"
  for browser in "${DETECTED[@]}"; do
    echo "  - $browser -> ${BROWSER_PATHS[$browser]}"
  done
  exit 0
}

parse_args() {
  # Show help if no arguments provided
  if [[ $# -eq 0 ]]; then
    usage
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--list)
        list_browsers
        ;;
      -b|--browsers)
        IFS=',' read -ra SELECTED <<< "$2"
        for b in "${SELECTED[@]}"; do
          if [[ ! -d "${BROWSER_PATHS[$b]:-}" ]]; then
            echo -e "${RED}[!] Warning: Browser \"$b\" directory not found. Skipping.${RESET}"
          fi
        done
        shift
        ;;
      -h|--help)
        usage
        ;;
      *)
        echo -e "${RED}[!] Unknown option: $1${RESET}"
        usage
        ;;
    esac
    shift
  done
}

init_paths() {
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  OUT_DIR="browser_scrape_${TIMESTAMP}"
  mkdir -p "$OUT_DIR"

  HISTORY_FILE="$OUT_DIR/history.txt"
  BOOKMARKS_FILE="$OUT_DIR/bookmarks.txt"
  HOSTS_FILE="$OUT_DIR/hosts.txt"
  PARAMS_FILE="$OUT_DIR/params.txt"
  PRETTY_SECRETS="$OUT_DIR/secrets_styled.txt"

  touch "$HISTORY_FILE" "$BOOKMARKS_FILE" "$HOSTS_FILE" "$PARAMS_FILE" "$PRETTY_SECRETS"
  echo -e "${GREEN}[+] Output directory created: $OUT_DIR${RESET}"
}

declare -A seen_blocks=()
output=""
scrape_and_extract() {
  TEMP_RAW=$(mktemp)
  echo -e "${GREEN}[+] Scanning selected browsers...${RESET}"

  for name in "${SELECTED[@]}"; do
    DIR="${BROWSER_PATHS[$name]}"
    if [[ -d "$DIR" ]]; then
      echo -e "${YELLOW}  -> Scanning $name (${DIR})${RESET}"
      find "$DIR" -type f -exec strings {} \; 2>/dev/null >> "$TEMP_RAW"
    fi
  done

  # Extract and filter URLs
  grep -Eo 'https?://[^"<> ]+' "$TEMP_RAW" | sort -u > "$TEMP_RAW.urls"
  echo -e "${GREEN}[+] Extracted URLs:${RESET}"
  cat "$TEMP_RAW.urls"

  # Extract and filter endpoints with query parameters
  grep -Eo 'https?://[^ ]+\?[^\s"'\''<>]+' "$TEMP_RAW.urls" | sort -u > "$PARAMS_FILE"
  echo -e "${GREEN}[+] Extracted endpoints with query parameters:${RESET}"
  cat "$PARAMS_FILE"

  # Extract sensitive information from URLs
  grep -iE 'https?://[^ ]*(password|token|secret|apikey|key|jwt)=[^ &"'\''<>]+' "$TEMP_RAW.urls" \
    | sort -u > "$TEMP_RAW.secrets" || touch "$TEMP_RAW.secrets"

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *\?* ]] && continue

    url="${line%%\?*}"
    query="${line#*\?}"
    block="endpoint: $url"$'\n'

    IFS='&' read -ra parts <<< "$query"
    for part in "${parts[@]}"; do
      [[ "$part" != *=* ]] && continue
      key="${part%%=*}"
      val="${part#*=}"
      val="${val%%http*}"

      if [[ "$key" =~ ^(username|user|user_id|userid|password|pass|pwd|passwd|email|mail|token|access_token|refresh_token|jwt)$ ]]; then
        block+="$key => $val"$'\n'
      fi
    done

    if [[ -n "$block" ]] && [[ -z "${seen_blocks[$block]:-}" ]]; then
      seen_blocks[$block]=1
      output+="$block"$'\n'
    fi
  done < "$TEMP_RAW.secrets"

  echo "$output" > "$PRETTY_SECRETS"

  rm -f "$TEMP_RAW" "$TEMP_RAW.urls" "$TEMP_RAW.secrets"
}

get_firefox_places_files() {
  local firefox_dir="${BROWSER_PATHS[firefox]}"
  if [[ -d "$firefox_dir" ]]; then
    find "$firefox_dir" -type f -name "places.sqlite" 2>/dev/null
  fi
}

extract_bookmarks() {
  echo -e "${GREEN}[+] Extracting bookmarks...${RESET}"

  > "$BOOKMARKS_FILE"

  for name in "${SELECTED[@]}"; do
    DIR="${BROWSER_PATHS[$name]}"

    if [[ "$name" == "firefox" ]]; then
      get_firefox_places_files | while read -r db; do
        if [[ -f "$db" ]]; then
          echo -e "${YELLOW}  -> Firefox bookmarks from $db${RESET}"

          TEMP_DB=$(mktemp --suffix=.sqlite)
          cp "$db" "$TEMP_DB"

          echo -e "${GREEN}     [*] Running SQLite query...${RESET}"
          sqlite3 -separator "|" "$TEMP_DB" \
            "SELECT COALESCE(moz_bookmarks.title, '(No Title)'), moz_places.url
             FROM moz_bookmarks
             JOIN moz_places ON moz_bookmarks.fk = moz_places.id
             WHERE moz_bookmarks.type = 1 AND moz_places.url IS NOT NULL;" 2>/dev/null |
          while IFS="|" read -r title url; do
            [[ -n "$url" ]] && echo "$title => $url" >> "$BOOKMARKS_FILE"
          done

          rm -f "$TEMP_DB"
        else
          echo -e "${RED}[!] places.sqlite not found at $db${RESET}"
        fi
      done
    else
      find "$DIR" -type f -iname "Bookmarks" 2>/dev/null | while read -r json; do
        if [[ -f "$json" ]]; then
          echo -e "${YELLOW}  -> Chromium-based bookmarks from $json${RESET}"

          jq -r '.. | select(.url? and .name?) | "\(.name) => \(.url)"' "$json" 2>/dev/null >> "$BOOKMARKS_FILE"
        fi
      done
    fi
  done

  # Nettoyage et tri final
  sort -u "$BOOKMARKS_FILE" -o "$BOOKMARKS_FILE"
  echo -e "${GREEN}[+] Bookmark extraction complete! Saved in: $BOOKMARKS_FILE${RESET}"
}



extract_history() {
  echo -e "${GREEN}[+] Extracting browsing history...${RESET}"
  for name in "${SELECTED[@]}"; do
    DIR="${BROWSER_PATHS[$name]}"
    if [[ -d "$DIR" ]]; then
      if command -v sqlite3 >/dev/null 2>&1; then
        find "$DIR" -name "History" -o -name "places.sqlite" 2>/dev/null | while read -r DB; do
          echo -e "${YELLOW}  -> Parsing DB: $DB${RESET}"
          sqlite3 "$DB" "SELECT url FROM urls;" 2>/dev/null
          sqlite3 "$DB" "SELECT url FROM moz_places;" 2>/dev/null
        done
      else
        echo -e "${RED}[!] sqlite3 not found. Fallback...${RESET}"
        find "$DIR" -type f \( -name "*.sqlite" -o -name "*.json" \) -exec strings {} \; \
          | grep -Eo 'https?://[^"<> ]+'
      fi
    fi
  done | sort -u >> "$HISTORY_FILE"
}

summary() {
  echo ""
  echo -e "${GREEN}[+] Scraping complete. Final files in: $OUT_DIR${RESET}"
  ls -lh "$OUT_DIR"
}

banner
detect_browsers
SELECTED=()  # Initialize empty by default
parse_args "$@"  # Will show help if no args provided

# Only continue if browsers were selected
if [[ ${#SELECTED[@]} -eq 0 ]]; then
  SELECTED=("${DETECTED[@]}")
fi

init_paths
scrape_and_extract
extract_bookmarks
extract_history
summary

cat $OUT_DIR${RESET}/bookmarks.txt
