#!/usr/bin/env python3
# Converts Gitea PBKDF2-HMAC-SHA256 hashes into a format hashcat can use (mode 10900)
# Improved to accept plain salt:hash, hash|salt, or full sqlite "select * from user;" rows.

import argparse
import base64
import re
import sys

HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]{8,}$')  # token made of hex chars (min length 8 to avoid tiny numbers)

def find_hex_pair_in_line(line):
    """
    Scan a line (eg. a full sqlite 'select * from user;' row)
    and return the first adjacent pair of hex tokens found.
    Returns tuple (part1, part2) or (None, None) if not found.
    """
    # Split on common separators used by sqlite / pipes / spaces / tabs
    tokens = re.split(r'[|\t ,;]+', line.strip())
    hex_tokens = [t for t in tokens if HEX_TOKEN_RE.match(t)]
    if not hex_tokens:
        return None, None

    # Look for adjacent hex tokens in the original token list (not just the filtered list)
    # This helps catch cases like "...|salt|hash|..."
    for i in range(len(tokens) - 1):
        t1 = tokens[i]
        t2 = tokens[i + 1]
        if HEX_TOKEN_RE.match(t1) and HEX_TOKEN_RE.match(t2):
            return t1, t2

    # fallback: if at least two hex tokens anywhere, take the last two (often salt,hash are near the end)
    if len(hex_tokens) >= 2:
        return hex_tokens[-2], hex_tokens[-1]

    # nothing useful found
    return None, None

def convert_hash(hash_string):
    """Converts a SALT+HASH string to a hashcat compatible format.
       Accepts 'salt:hash', 'hash|salt', or a full sqlite row that contains two adjacent hex fields.
    """
    # If the line looks like a sqlite full row (contains many separators), try to extract hex pair
    if '|' in hash_string and ':' not in hash_string:
        # could be either 'hash|salt' or full sqlite row; attempt to split first
        # try the quick path: exactly one '|' and two hex parts
        parts = hash_string.split('|')
        if len(parts) == 2 and all(HEX_TOKEN_RE.match(p) for p in parts):
            # direct hash|salt pair
            part1, part2 = parts
        else:
            # try scanning more generally
            p1, p2 = find_hex_pair_in_line(hash_string)
            if not p1:
                print(f"[-] Could not find salt+hash pair in line: {hash_string}", file=sys.stderr)
                return None
            part1, part2 = p1, p2
    else:
        # Normalize delimiter to ':'
        normalized = hash_string.replace('|', ':')
        if ':' in normalized:
            try:
                part1, part2 = normalized.split(':', 1)
            except ValueError:
                print(f"[-] Invalid input format: {hash_string}", file=sys.stderr)
                return None
        else:
            # no delimiter at all (single token) -> maybe user piped a full sqlite row with different separators
            p1, p2 = find_hex_pair_in_line(hash_string)
            if p1 and p2:
                part1, part2 = p1, p2
            else:
                print(f"[-] Invalid input format (expected salt:hash or a row with both salt and hash).\n"
                      f"Example: 'salt:hash' or pipe 'select salt,passwd from user;' into this script.", file=sys.stderr)
                return None

    # Now we have part1 and part2; ensure they are hex
    try:
        bytes1 = bytes.fromhex(part1)
        bytes2 = bytes.fromhex(part2)
    except ValueError:
        print(f"[-] Invalid hex input: {part1} or {part2}", file=sys.stderr)
        return None

    # If lengths are equal, keep original order (part1 = salt). Otherwise smaller is salt.
    if len(bytes1) > len(bytes2):
        salt_bytes = bytes2
        hash_bytes = bytes1
    else:
        salt_bytes = bytes1
        hash_bytes = bytes2

    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')

    return f"sha256:50000:{salt_b64}:{hash_b64}"

def main():
    parser = argparse.ArgumentParser(
        description="Convert Gitea SALT+HASH strings to a hashcat-compatible format.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  gitea2hashcat.py <salt>:<hash>
  gitea2hashcat.py <hash>|<salt>
  cat sqlite_rows.txt | gitea2hashcat.py
  sqlite3 gitea.db 'select salt,passwd from user;' | gitea2hashcat.py

If you run `select * from user;` and pipe it, the script will try to auto-find two adjacent hex fields (salt+passwd)."""
    )
    parser.add_argument('hashes', nargs='*', help='SALT+HASH strings to convert (or pipe sqlite rows)')
    args = parser.parse_args()

    print("[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)\n")

    if args.hashes:
        for hash_string in args.hashes:
            converted = convert_hash(hash_string.strip())
            if converted:
                print(converted)
    else:
        for line in sys.stdin:
            line = line.rstrip('\n')
            if not line.strip():
                continue
            converted = convert_hash(line)
            if converted:
                print(converted)

if __name__ == "__main__":
    main()
