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
  PARAMS_FILE="$OUT_DIR/parameters.txt"
  PRETTY_SECRETS="$OUT_DIR/sensitive_params.txt"

  touch "$HISTORY_FILE" "$BOOKMARKS_FILE" "$PARAMS_FILE" "$PRETTY_SECRETS"
  echo -e "${GREEN}[+] Output directory created: $OUT_DIR${RESET}"
}

declare -A seen_blocks=()
declare -A seen_urls=()
declare -A seen_params=()

scrape_and_extract() {
  echo -e "${GREEN}[+] Scanning selected browsers...${RESET}"

  for name in "${SELECTED[@]}"; do
    DIR="${BROWSER_PATHS[$name]}"
    if [[ ! -d "$DIR" ]]; then
      continue
    fi
    
    echo -e "${YELLOW}  -> Scanning $name (${DIR})${RESET}"
    while IFS= read -r line; do
      # Skip if we've seen this URL before
      [[ -n "${seen_urls[$line]:-}" ]] && continue
      seen_urls[$line]=1
      
      # Process URLs with parameters
      if [[ "$line" == *\?* ]]; then
        echo "$line" >> "$PARAMS_FILE"
        
        if [[ "$line" =~ .*(username|password|token).* ]]; then
          url="${line%%\?*}"
          query="${line#*\?}"
          block="endpoint: $url"$'\n'
          
          IFS='&' read -ra parts <<< "$query"
          for part in "${parts[@]}"; do
            [[ "$part" != *=* ]] && continue
            key="${part%%=*}"
            val="${part#*=}"
            
            # Using existing grep pattern for sensitive params
            if [[ "$key" =~ ^(username|user|user_id|userid|password|pass|pwd|passwd|email|mail|token|access_token|refresh_token|jwt|api_key|session_id|sessionid|sessid|PHPSESSID|JSESSIONID|auth|auth_token|auth_key|authcode|otp|mfa_token|verification_code|remember_me|stay_logged_in|name|first_name|last_name|full_name|address|street|city|zip|postal_code|phone|mobile|telephone|ssn|social_security|national_id|dob|birth_date|age|credit_card|cc_number|cvv|expiry_date|bank_account|iban|swift_code|admin|is_admin|role|privilege|superuser|debug|test_mode|env|environment|secret|secret_key|private_key|encryption_key|config|settings|db_config|csrf_token|csrf|xsrf_token|redirect|return_url|next|callback|query|search|q|filter|id|uid|record_id|document_id|table|db|database|collection|limit|offset|page|count|api|endpoint|method|action|sql|query_string|command|file|filename|file_path|upload|dir|directory|path|location|download|export|import|attachment|document|image|invoice|order_id|transaction_id|amount|price|total|quantity|discount|coupon|promo_code|account_id|customer_id|client_id|url|uri|link|src|dest|referer|referrer|origin|user_agent|ua|device_id|ip|client_ip|remote_addr|PHP_SESSION|REQUEST_METHOD|VIEWSTATE|EVENTVALIDATION|ASP\.NET_SessionId|_method|authenticity_token|csrftoken|_token|XSRF-TOKEN|debug|test|dev|stage|show_errors|display_errors|error_reporting|dump|var_dump|console\.log|verbose|trace|stack_trace|hash|md5|sha1|hmac|license|serial|activation_key|captcha|recaptcha_token).* ]]; then
              block+="$key => $val"$'\n'
            fi
          done
          
          # Store unique blocks
          if [[ -n "$block" && -z "${seen_blocks[$block]:-}" ]]; then
            seen_blocks[$block]=1
            echo "$block" >> "$PRETTY_SECRETS"
          fi
        fi
      fi
    done < <(find "$DIR" -type f -exec strings {} \; 2>/dev/null | grep -Eo 'https?://[^"<> ]+')
  done

  echo -e "${GREEN}[+] Found $(wc -l < "$PARAMS_FILE") unique parameters${RESET}"
  echo -e "${GREEN}[+] Found $(wc -l < "$PRETTY_SECRETS") sensitive parameters${RESET}"
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

  sort -u "$BOOKMARKS_FILE" -o "$BOOKMARKS_FILE"
  echo -e "${GREEN}[+] Bookmark extraction complete! Saved in: $BOOKMARKS_FILE${RESET}"
}

extract_history() {
  echo -e "${GREEN}[+] Extracting browsing history...${RESET}"
  
  > "$HISTORY_FILE"
  
  for name in "${SELECTED[@]}"; do
    DIR="${BROWSER_PATHS[$name]}"
    if [[ ! -d "$DIR" ]]; then
      continue
    fi
    
    echo -e "${YELLOW}  -> Processing $name history...${RESET}"
    
    if [[ "$name" == "firefox" ]]; then
      find "$DIR" -type f -name "places.sqlite" 2>/dev/null | while read -r db; do
        if [[ -f "$db" ]]; then
          TEMP_DB=$(mktemp --suffix=.sqlite)
          cp "$db" "$TEMP_DB"
          
          sqlite3 "$TEMP_DB" "SELECT url FROM moz_places WHERE url LIKE 'http%';" 2>/dev/null >> "$HISTORY_FILE"
          rm -f "$TEMP_DB"
        fi
      done
    else
      # Chrome-based browsers
      find "$DIR" -type f -name "History" 2>/dev/null | while read -r db; do
        if [[ -f "$db" ]]; then
          TEMP_DB=$(mktemp --suffix=.sqlite)
          cp "$db" "$TEMP_DB"
          
          sqlite3 "$TEMP_DB" "SELECT url FROM urls WHERE url LIKE 'http%';" 2>/dev/null >> "$HISTORY_FILE"
          rm -f "$TEMP_DB"
        fi
      done
    fi
  done

  # Clean up and deduplicate
  if [[ -f "$HISTORY_FILE" ]]; then
    sort -u "$HISTORY_FILE" -o "$HISTORY_FILE"
    echo -e "${GREEN}[+] History extraction complete! Saved in: $HISTORY_FILE${RESET}"
  else
    echo -e "${RED}[!] No history entries found${RESET}"
  fi
}

summary() {
  echo ""
  echo -e "${GREEN}[+] Scraping complete. Final files in: $OUT_DIR${RESET}"
  ls -lh "$OUT_DIR"
}

banner
detect_browsers
SELECTED=() 
parse_args "$@" 
if [[ ${#SELECTED[@]} -eq 0 ]]; then
  SELECTED=("${DETECTED[@]}")
fi

init_paths
scrape_and_extract
extract_bookmarks
extract_history
summary
