# pi-hole-dns-lists

DNS blocklists for use with [Pi-Hole](https://pi-hole.net/).

Sources are organized into categories. Each category has a `.list` file (source URLs)
and a generated `.txt` file (compiled, deduplicated domains) ready to use in Pi-Hole.

## Setup

1. Login to your Pi-Hole
2. Go to **Settings → Blocklists**
3. Add the raw URL(s) of the categories you want
4. Run **Update Gravity**

You may remove all default Pi-Hole blocklists — they are already included here.

---

## Lists

### threat.txt — Malware, phishing, C2, ransomware, scam, fraud
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/threat.txt
```

### ads.txt — Advertising domains
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/ads.txt
```

### tracking.txt — Trackers and privacy
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/tracking.txt
```

### telemetry.txt — Native device and OS telemetry
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/telemetry.txt
```

### gambling.txt — Gambling, fakenews, cryptomining
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/gambling.txt
```

---

## Keeping the lists up to date

The repository includes `update.sh` — a script to check source URL health,
remove defunct entries, add curated sources, and rebuild the compiled `.txt` files.

```bash
# Check which source URLs are still alive
./update.sh

# Remove dead URLs + rebuild .txt files
./update.sh --update --generate

# Preview changes without modifying any files
./update.sh --update --dry-run

# Add a specific URL to a category
./update.sh --add https://example.com/blocklist.txt --to threat
./update.sh --add https://example.com/blocklist.txt --to ads

# Auto-add all live curated sources not yet in any list
./update.sh --recommend

# Preview what --recommend would add
./update.sh --recommend --dry-run
```

Available categories for `--to`: `threat`, `ads`, `tracking`, `telemetry`, `gambling`

---

## Whitelists & further resources

- [Commonly whitelisted domains](https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212)
- [firebog.net](https://firebog.net/) — curated, regularly tested blocklist collection
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) — comprehensive, actively maintained lists
