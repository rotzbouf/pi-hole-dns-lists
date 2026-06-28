#!/usr/bin/env bash
# Pi-Hole blocklist updater
# Checks source URL health, prunes dead entries, regenerates aggregated domain files,
# and supports adding new URLs individually or from a curated recommended list.
#
# Usage: ./update.sh [--check] [--update] [--generate] [--add <url>] [--recommend] [--dry-run]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMEOUT=10
DRY_RUN=false
DO_CHECK=false
DO_UPDATE=false
DO_GENERATE=false
DO_ADD=false
ADD_URL=""
ADD_TO="piholeBL.list"
DO_RECOMMEND=false

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

log()  { echo -e "\n${BLUE}▶${NC} ${BOLD}$*${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}!${NC} $*"; }

# ── Curated list of modern, actively maintained sources ────────────────────────
# --recommend checks these in parallel and auto-adds all live, not-yet-included ones.
RECOMMENDED_NAMES=(
    # Threat / Malware / Phishing
    "URLhaus — active malware URLs (abuse.ch)"
    "HaGeZi Threat Intelligence Feeds — malware, phishing, C&C"
    "HaGeZi Fake — Fake-Shops, -News, -Support-Seiten"
    "Phishing Database — active phishing domains"
    "Spam404 — Scam & Spam-Seiten"
    "BlockList Project — Malware"
    "BlockList Project — Phishing"
    "OSINT Digital Side — aktuelle Threat-Intel-Domains"
    # Ads / Tracking
    "HaGeZi Multi — Werbung, Tracking, Spam (umfassend)"
    "HaGeZi Pro — ausgewogen, wenig false-positives"
    "OISD Big — breite Abdeckung, wenig false-positives"
    "1Hosts Pro — umfassend"
    "1Hosts Lite — ausgewogen"
    "Peter Lowe — Werbung & Tracking-Server"
    # Specific
    "HaGeZi Gambling — Glücksspiel-Domains"
    "HaGeZi DoH/VPN/TOR/Proxy — Bypass-Schutz"
    "Windows Spy Blocker — Microsoft-Telemetrie"
    "NoCoin — Cryptomining-Domains"
    "StevenBlack Fakenews+Gambling — Kategorien-Erweiterung"
    "RPiList Malware — kuratierte Malware-Liste (DE)"
)
RECOMMENDED_URLS=(
    "https://urlhaus.abuse.ch/downloads/hostfile/"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/fake.txt"
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt"
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"
    "https://big.oisd.nl/"
    "https://o0.pages.dev/Pro/hosts.txt"
    "https://o0.pages.dev/Lite/hosts.txt"
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/gambling.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh-vpn-proxy-bypass.txt"
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts"
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware"
)

usage() {
    cat <<'EOF'
Usage: update.sh [OPTIONS]

  --check           Check all source URLs for availability (default)
  --update          Remove dead URLs from .list files
  --generate        Regenerate .txt files from working sources
  --add <url>       Add a new URL (checks for duplicates and availability)
  --to <list>       Target list for --add: "pihole" (default) or "more"
  --recommend       Auto-add all live curated sources not yet in the lists
  --dry-run         Show changes without modifying files
  -h, --help        Show this help

Examples:
  ./update.sh                                    # check URL health
  ./update.sh --update --dry-run                 # preview dead URL removal
  ./update.sh --update --generate                # prune dead + rebuild .txt
  ./update.sh --add https://example.com/bl.txt   # add a specific URL
  ./update.sh --add https://example.com/bl.txt --to more
  ./update.sh --recommend                        # auto-add all live curated sources
  ./update.sh --recommend --to more              # add to more_piholeBL.list instead
  ./update.sh --recommend --dry-run              # preview what would be added
EOF
    exit 0
}

# ── Argument parsing ───────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && DO_CHECK=true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)     DO_CHECK=true; shift ;;
        --update)    DO_UPDATE=true; DO_CHECK=true; shift ;;
        --generate)  DO_GENERATE=true; DO_CHECK=true; shift ;;
        --add)       DO_ADD=true; ADD_URL="${2:?'--add requires a URL'}"; shift 2 ;;
        --to)
            case "${2:-}" in
                pihole) ADD_TO="piholeBL.list" ;;
                more)   ADD_TO="more_piholeBL.list" ;;
                *) echo "Unknown list '${2:-}' — use 'pihole' or 'more'" >&2; exit 1 ;;
            esac
            shift 2 ;;
        --recommend) DO_RECOMMEND=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)   usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

# ── Core helpers ───────────────────────────────────────────────────────────────

check_url() {
    # curl always writes "%{http_code}" (incl. "000" on timeout), no fallback needed
    curl -s -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" --location --max-redirs 5 "$1" 2>/dev/null; true
}

# Parses both hosts-format (0.0.0.0/127.0.0.1 prefix) and plain domain lists.
# Strips comments, validates domain format, lowercases everything.
extract_domains() {
    local skip='^(localhost|broadcasthost|local|ip6-localhost|ip6-loopback|loopback)$'
    grep -v '^[[:space:]]*[#!]' | grep -v '^[[:space:]]*$' | tr -d '\r' | \
    awk -v skip="$skip" '
        /^(0\.0\.0\.0|127\.0\.0\.1|::1)[[:space:]]/ {
            if ($2 !~ skip) print $2; next
        }
        /^[a-zA-Z0-9]/ { print $1 }
    ' | \
    grep -Ev '^[0-9.]+$' | \
    grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$' | \
    tr '[:upper:]' '[:lower:]'
}

# Returns the list file ("piholeBL.list" / "more_piholeBL.list" / "") that already contains $1
find_in_lists() {
    local url="$1"
    for list in piholeBL.list more_piholeBL.list; do
        if grep -qxF "$url" "$SCRIPT_DIR/$list" 2>/dev/null; then
            echo "$list"
            return 0
        fi
    done
    return 0  # not found is still a success — caller checks empty string
}

# ── --add: add a single URL ────────────────────────────────────────────────────

cmd_add() {
    local url="$1"
    local target="$2"
    local target_path="$SCRIPT_DIR/$target"

    log "Adding URL to $target"

    # Duplicate check
    local existing_in
    existing_in=$(find_in_lists "$url")
    if [[ -n "$existing_in" ]]; then
        warn "Already present in $existing_in — nothing to do."
        return 0
    fi

    # Availability check
    printf "  Checking  %s\n" "$url"
    local code
    code=$(check_url "$url")

    if [[ "$code" == "200" ]]; then
        ok "Reachable ($code)"
    else
        warn "URL returned ${code:-timeout}"
        printf "  Add anyway? [y/N] "
        read -r answer || true
        [[ "$answer" != "y" && "$answer" != "Y" ]] && { warn "Aborted."; return 0; }
    fi

    if $DRY_RUN; then
        warn "dry-run — would append to $target:"
        echo "    $url"
    else
        echo "$url" >> "$target_path"
        ok "Appended to $target"
    fi
}

# ── --recommend: check curated list in parallel, auto-add all live new entries ──

cmd_recommend() {
    local target="$ADD_TO"

    log "Syncing recommended sources → $target"
    echo
    printf "  Checking availability"

    # Collect all currently configured URLs for duplicate detection
    local existing_urls
    existing_urls=$(grep -hv '^[[:space:]]*[#]' \
        "$SCRIPT_DIR/piholeBL.list" "$SCRIPT_DIR/more_piholeBL.list" 2>/dev/null | \
        grep -v '^[[:space:]]*$' || true)

    # Parallel URL checks: each writes its HTTP code to a tmpfile.
    # </dev/null prevents background jobs from consuming piped stdin.
    local tmpdir
    tmpdir=$(mktemp -d)
    for i in "${!RECOMMENDED_URLS[@]}"; do
        { check_url "${RECOMMENDED_URLS[$i]}" > "$tmpdir/$i"; printf '.'; } </dev/null &
    done
    wait
    echo  # newline after the dots

    # Display status and collect URLs that need to be added
    echo
    local to_add=()
    for i in "${!RECOMMENDED_NAMES[@]}"; do
        local url="${RECOMMENDED_URLS[$i]}"
        local name="${RECOMMENDED_NAMES[$i]}"
        local code
        code=$(cat "$tmpdir/$i" 2>/dev/null || echo "000")

        if echo "$existing_urls" | grep -qxF "$url"; then
            printf "  ${DIM}%-62s  ✓ vorhanden${NC}\n" "$name"
        elif [[ "$code" == "200" ]]; then
            printf "  ${GREEN}+${NC} ${BOLD}%-62s${NC}  ${GREEN}→ wird hinzugefügt${NC}\n" "$name"
            to_add+=("$url")
        else
            printf "  ${DIM}%-62s  ✗ tot ($code)${NC}\n" "$name"
        fi
    done
    rm -rf "$tmpdir"

    echo
    if [[ ${#to_add[@]} -eq 0 ]]; then
        ok "Alle empfohlenen aktiven Listen sind bereits vorhanden."
        return
    fi

    printf "  %d neue URL(s) werden zu %s hinzugefügt\n" "${#to_add[@]}" "$target"
    echo

    for url in "${to_add[@]}"; do
        if $DRY_RUN; then
            warn "dry-run: $url"
        else
            echo "$url" >> "$SCRIPT_DIR/$target"
            ok "$url"
        fi
    done
}

# ── --check / --update / --generate: process a .list file ─────────────────────

process_list() {
    local list_file="$1"
    local txt_file="${list_file%.list}.txt"
    local list_path="$SCRIPT_DIR/$list_file"
    local txt_path="$SCRIPT_DIR/$txt_file"

    [[ ! -f "$list_path" ]] && { warn "$list_file not found, skipping"; return; }

    log "Checking $list_file"

    local live_urls=()
    local dead_urls=()

    while IFS= read -r url || [[ -n "${url:-}" ]]; do
        [[ -z "$url" || "$url" == \#* ]] && continue

        printf "  %-68s" "$url"
        local code
        code=$(check_url "$url")

        if [[ "$code" == "200" ]]; then
            printf "${GREEN}%s${NC}\n" "$code"
            live_urls+=("$url")
        else
            printf "${RED}%s${NC}\n" "${code:-timeout}"
            dead_urls+=("$url")
        fi
    done < "$list_path"

    echo
    printf "  Live: ${GREEN}%d${NC}   Dead: ${RED}%d${NC}\n" "${#live_urls[@]}" "${#dead_urls[@]}"

    # --update: strip dead URLs while preserving comments and blank lines
    if $DO_UPDATE && [[ ${#dead_urls[@]} -gt 0 ]]; then
        log "Pruning ${#dead_urls[@]} dead URL(s) from $list_file"

        local tmp
        tmp=$(mktemp)
        grep -vxFf <(printf '%s\n' "${dead_urls[@]}") "$list_path" > "$tmp" || true

        if $DRY_RUN; then
            warn "dry-run — would remove:"
            diff "$list_path" "$tmp" 2>/dev/null | grep '^<' | sed 's/^< /    /' || true
            rm "$tmp"
        else
            mv "$tmp" "$list_path"
            ok "Updated $list_file"
        fi
    fi

    # --generate: fetch live sources, extract domains, dedup, write .txt
    if $DO_GENERATE; then
        [[ ${#live_urls[@]} -eq 0 ]] && { warn "No live URLs — skipping $txt_file generation"; return; }

        log "Generating $txt_file from ${#live_urls[@]} source(s)"

        local tmp_all
        tmp_all=$(mktemp)
        local total=0

        for url in "${live_urls[@]}"; do
            printf "  Fetching %-62s" "$url"
            local content
            if content=$(curl -sf --max-time 30 --location --max-redirs 5 "$url" 2>/dev/null); then
                local n
                n=$(printf '%s\n' "$content" | extract_domains | tee -a "$tmp_all" | wc -l)
                printf "${GREEN}%6d domains${NC}\n" "$n"
                (( total += n )) || true
            else
                printf "${YELLOW}%-6s${NC}\n" "failed"
            fi
        done

        local unique
        unique=$(sort -u "$tmp_all" | wc -l)
        echo
        printf "  Fetched: %d   Unique after dedup: ${GREEN}%d${NC}\n" "$total" "$unique"

        if $DRY_RUN; then
            warn "dry-run — would write $txt_file ($unique unique domains)"
            rm "$tmp_all"
        else
            sort -u "$tmp_all" > "$txt_path"
            rm "$tmp_all"
            ok "Written $txt_path ($unique unique domains)"
        fi
    fi
}

# ── Main ───────────────────────────────────────────────────────────────────────

SEP='────────────────────────────────────────────────────────────────────────────'

echo
echo -e "${BOLD}Pi-Hole Blocklist Updater${NC}   $(date '+%Y-%m-%d %H:%M')"
$DRY_RUN && echo -e "${YELLOW}[DRY RUN — no files will be modified]${NC}"
echo "$SEP"

if $DO_ADD; then
    cmd_add "$ADD_URL" "$ADD_TO"
elif $DO_RECOMMEND; then
    cmd_recommend
else
    for list in piholeBL.list more_piholeBL.list; do
        process_list "$list"
        echo
        echo "$SEP"
    done
fi

echo
echo -e "${GREEN}Done.${NC}"
