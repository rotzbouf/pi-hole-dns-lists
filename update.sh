#!/usr/bin/env bash
# Pi-Hole blocklist updater
# Sources are organized into categories, each with a <category>.list (URLs) and
# a generated <category>.txt (deduplicated domains).
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
ADD_TO="ads"
DO_RECOMMEND=false

CATEGORIES=("threat" "ads" "tracking" "telemetry" "gambling")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

log()  { echo -e "\n${BLUE}▶${NC} ${BOLD}$*${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}!${NC} $*"; }

# ── Curated sources ─────────────────────────────────────────────────────────────
# Three parallel arrays (same index = same source).
# RECOMMENDED_CATS determines which <category>.list each URL belongs to.
RECOMMENDED_NAMES=(
    # Threat / Malware / Phishing
    "URLhaus — active malware URLs (abuse.ch)"
    "HaGeZi Threat Intelligence Feeds — malware, phishing, C&C"
    "ThreatFox — Malware-IOCs & C2-Server (abuse.ch)"
    "Phishing Database — active phishing domains"
    "Spam404 — Scam & Spam-Seiten"
    "DandelionSprout Anti-Malware — Malware & Exploit-Domains"
    "DigitalSide Threat-Intel — aktuelle IOC-Domains (CERT Italia)"
    "BlockList Project — Scam & Fake-Seiten"
    "BlockList Project — Malware"
    "BlockList Project — Phishing"
    "BlockList Project — Ransomware"
    "BlockList Project — Fraud (Betrug & Missbrauch)"
    "RPiList Malware — kuratierte Malware-Liste (DE)"
    "RPiList Phishing — kuratierte Phishing-Domains (DE)"
    "HaGeZi Fake — Fake-Shops, Fake-News & Betrugsseiten"
    "CERT Poland — aktuelle Phishing & Malware-Domains"
    # Ads
    "HaGeZi Multi — Werbung, Tracking, Spam (umfassend)"
    "HaGeZi Pro — ausgewogen, wenig false-positives"
    "HaGeZi Pop-up Ads — Popup-Werbung & Ablenkung"
    "OISD Big — breite Abdeckung, wenig false-positives"
    "GoodbyeAds — mobile Werbung & Tracking"
    "1Hosts Lite — ausgewogen"
    "1Hosts Pro — aggressivere Werbeblockierung"
    "Peter Lowe — Werbung & Tracking-Server"
    "Dan Pollock (SomeoneWhoCares) — klassische Hosts-Liste"
    "EasyList (Firebog-Mirror) — klassische Werbeblocker-Liste"
    "BlockList Project — Ads (Werbung)"
    # Tracking
    "BlockList Project — Tracking"
    # Telemetrie
    "Windows Spy Blocker — Microsoft-Telemetrie"
    "HaGeZi Native Apple — Apple-Telemetrie"
    "HaGeZi Native Samsung — Samsung-Telemetrie & Ads"
    "HaGeZi Native TikTok — TikTok-Tracking & Telemetrie"
    "HaGeZi Native Xiaomi — Xiaomi-Telemetrie & Ads"
    "HaGeZi Native Amazon — Amazon-Telemetrie"
    # Gambling / Fakenews / Crypto
    "BlockList Project — Glücksspiel"
    "NoCoin — Cryptomining-Domains"
    "StevenBlack Fakenews+Gambling — Kategorien-Erweiterung"
)
RECOMMENDED_URLS=(
    # Threat
    "https://urlhaus.abuse.ch/downloads/hostfile/"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt"
    "https://threatfox.abuse.ch/downloads/hostfile/"
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt"
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt"
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt"
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware"
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/phishing"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/fake.txt"
    "https://hole.cert.pl/domains/domains.txt"
    # Ads
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/popupads.txt"
    "https://big.oisd.nl/"
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt"
    "https://o0.pages.dev/Lite/hosts.txt"
    "https://o0.pages.dev/Pro/hosts.txt"
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
    "https://someonewhocares.org/hosts/zero/hosts"
    "https://v.firebog.net/hosts/Easylist.txt"
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt"
    # Tracking
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt"
    # Telemetry
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.apple.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.samsung.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.tiktok.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.xiaomi.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.amazon.txt"
    # Gambling
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt"
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts"
)
RECOMMENDED_CATS=(
    # Threat (16)
    "threat"    # URLhaus
    "threat"    # HaGeZi TIF
    "threat"    # ThreatFox
    "threat"    # Phishing Database
    "threat"    # Spam404
    "threat"    # DandelionSprout
    "threat"    # DigitalSide
    "threat"    # BlockList Scam
    "threat"    # BlockList Malware
    "threat"    # BlockList Phishing
    "threat"    # BlockList Ransomware
    "threat"    # BlockList Fraud
    "threat"    # RPiList Malware
    "threat"    # RPiList Phishing
    "threat"    # HaGeZi Fake
    "threat"    # CERT Poland
    # Ads (11)
    "ads"       # HaGeZi Multi
    "ads"       # HaGeZi Pro
    "ads"       # HaGeZi Pop-up
    "ads"       # OISD Big
    "ads"       # GoodbyeAds
    "ads"       # 1Hosts Lite
    "ads"       # 1Hosts Pro
    "ads"       # Peter Lowe
    "ads"       # Dan Pollock
    "ads"       # EasyList
    "ads"       # BlockList Ads
    # Tracking (1)
    "tracking"  # BlockList Tracking
    # Telemetry (6)
    "telemetry" # Windows Spy Blocker
    "telemetry" # HaGeZi Native Apple
    "telemetry" # HaGeZi Native Samsung
    "telemetry" # HaGeZi Native TikTok
    "telemetry" # HaGeZi Native Xiaomi
    "telemetry" # HaGeZi Native Amazon
    # Gambling (3)
    "gambling"  # BlockList Gambling
    "gambling"  # NoCoin
    "gambling"  # StevenBlack Fakenews+Gambling
)

usage() {
    cat <<'EOF'
Usage: update.sh [OPTIONS]

  --check           Check all source URLs for availability (default)
  --update          Remove dead URLs from .list files
  --generate        Regenerate .txt files from working sources
  --add <url>       Add a new URL (checks for duplicates and availability)
  --to <category>   Target category for --add (default: ads)
  --recommend       Auto-add all live curated sources not yet in any list
  --dry-run         Show changes without modifying files
  -h, --help        Show this help

Categories (each has a <category>.list source file → <category>.txt output):
  threat      Malware, phishing, C2, ransomware, scam, fraud
  ads         Advertising domains
  tracking    Trackers and privacy
  telemetry   Native device and OS telemetry
  gambling    Gambling, fakenews, cryptomining

Examples:
  ./update.sh                                    # check URL health
  ./update.sh --update --dry-run                 # preview dead URL removal
  ./update.sh --update --generate                # prune dead + rebuild .txt files
  ./update.sh --add https://example.com/bl.txt   # add to ads (default)
  ./update.sh --add https://example.com/bl.txt --to threat
  ./update.sh --recommend                        # auto-add all live curated sources
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
                threat|ads|tracking|telemetry|gambling) ADD_TO="${2}" ;;
                *) echo "Unknown category '${2:-}' — use: threat, ads, tracking, telemetry, gambling" >&2; exit 1 ;;
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
    tr '[:upper:]' '[:lower:]' || true
}

# Returns the .list file that already contains $1, or empty string if not found.
find_in_lists() {
    local url="$1"
    for cat in "${CATEGORIES[@]}"; do
        if grep -qxF "$url" "$SCRIPT_DIR/${cat}.list" 2>/dev/null; then
            echo "${cat}.list"
            return 0
        fi
    done
}

# ── --add: add a single URL to a category ─────────────────────────────────────

cmd_add() {
    local url="$1"
    local cat="$2"
    local target="${cat}.list"
    local target_path="$SCRIPT_DIR/$target"

    log "Adding URL to $target"

    local existing_in
    existing_in=$(find_in_lists "$url")
    if [[ -n "$existing_in" ]]; then
        warn "Already present in $existing_in — nothing to do."
        return 0
    fi

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

# ── --recommend: check curated sources in parallel, add live ones by category ──

cmd_recommend() {
    log "Syncing recommended sources"
    echo
    printf "  Checking availability"

    local existing_urls
    existing_urls=$(
        for cat in "${CATEGORIES[@]}"; do
            grep -hv '^[[:space:]]*[#]' "$SCRIPT_DIR/${cat}.list" 2>/dev/null || true
        done | grep -v '^[[:space:]]*$' || true
    )

    local tmpdir
    tmpdir=$(mktemp -d)
    for i in "${!RECOMMENDED_URLS[@]}"; do
        { check_url "${RECOMMENDED_URLS[$i]}" > "$tmpdir/$i"; printf '.'; } </dev/null &
    done
    wait
    echo

    echo
    declare -A to_add_per_cat
    for cat in "${CATEGORIES[@]}"; do to_add_per_cat[$cat]=""; done

    for i in "${!RECOMMENDED_NAMES[@]}"; do
        local url="${RECOMMENDED_URLS[$i]}"
        local name="${RECOMMENDED_NAMES[$i]}"
        local cat="${RECOMMENDED_CATS[$i]}"
        local code
        code=$(cat "$tmpdir/$i" 2>/dev/null || echo "000")

        if echo "$existing_urls" | grep -qxF "$url"; then
            printf "  ${DIM}[%-9s] %-56s  ✓ vorhanden${NC}\n" "$cat" "$name"
        elif [[ "$code" == "200" ]]; then
            printf "  ${GREEN}+${NC} ${BOLD}[%-9s]${NC} ${BOLD}%-56s${NC}  ${GREEN}→ wird hinzugefügt${NC}\n" "$cat" "$name"
            to_add_per_cat[$cat]+="$url"$'\n'
        else
            printf "  ${DIM}[%-9s] %-56s  ✗ tot ($code)${NC}\n" "$cat" "$name"
        fi
    done
    rm -rf "$tmpdir"

    echo
    local total_new=0
    for cat in "${CATEGORIES[@]}"; do
        [[ -z "${to_add_per_cat[$cat]}" ]] && continue
        local count
        count=$(printf '%s' "${to_add_per_cat[$cat]}" | grep -c .)
        (( total_new += count )) || true
    done

    if [[ $total_new -eq 0 ]]; then
        ok "Alle empfohlenen aktiven Listen sind bereits vorhanden."
        return
    fi

    printf "  %d neue URL(s) werden hinzugefügt\n" "$total_new"
    echo

    for cat in "${CATEGORIES[@]}"; do
        [[ -z "${to_add_per_cat[$cat]}" ]] && continue
        local target="$SCRIPT_DIR/${cat}.list"
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if $DRY_RUN; then
                warn "dry-run → ${cat}.list: $url"
            else
                echo "$url" >> "$target"
                ok "${cat}.list ← $url"
            fi
        done <<< "${to_add_per_cat[$cat]}"
    done
}

# ── --check / --update / --generate: process one category ─────────────────────

process_list() {
    local cat="$1"
    local list_file="${cat}.list"
    local txt_file="${cat}.txt"
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
    for cat in "${CATEGORIES[@]}"; do
        process_list "$cat"
        echo
        echo "$SEP"
    done
fi

echo
echo -e "${GREEN}Done.${NC}"
