# pi-hole-dns-lists

DNS blocklists for use with [Pi-Hole](https://pi-hole.net/).

## Setup

1. Login to your Pi-Hole
2. Go to **Settings → Blocklists**
3. Add the raw URL of one of the lists below
4. Run **Update Gravity**

You may remove all default blocklists — they are already included here.

---

## Lists

### piholeBL.txt — main list
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/piholeBL.txt
```
A curated collection of ad, tracking, malware, and phishing domains.
No issues observed in daily use.

### more_piholeBL.txt — extended list
```
https://raw.githubusercontent.com/rotzbouf/pi-hole-dns-lists/master/more_piholeBL.txt
```
Additional sources for broader coverage. Add on top of the main list.

---

## Keeping the lists up to date

The repository includes `update.sh` — a script to check source URL health,
remove defunct entries, add modern sources, and rebuild the compiled `.txt` files.

```bash
# Check which source URLs are still alive
./update.sh

# Remove dead URLs from .list files + rebuild .txt files
./update.sh --update --generate

# Add a specific URL
./update.sh --add https://example.com/blocklist.txt

# Add to the extended list instead
./update.sh --add https://example.com/blocklist.txt --to more

# Auto-add all live curated sources not yet in the lists (20 sources checked in parallel)
./update.sh --recommend

# Add to the extended list instead of the main list
./update.sh --recommend --to more

# Preview changes without modifying any files
./update.sh --recommend --dry-run
./update.sh --update --dry-run
```

---

## Whitelists & further resources

- [Commonly whitelisted domains](https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212)
- [firebog.net](https://firebog.net/) — curated, regularly tested blocklist collection
- [github.com/chadmayfield/my-pihole-blocklists](https://github.com/chadmayfield/my-pihole-blocklists)
