# gitea2hashcat

Convert Gitea PBKDF2-HMAC-SHA256 (salt + hash) entries into Hashcat format (mode 10900).

## Features
- Accepts `salt:hash` or `hash|salt`.
- Accepts piping the output of `sqlite3 gitea.db 'select salt,passwd from user;'`.
- Attempts to auto-detect salt+hash when given a full `select * from user;` row.

## Usage
Make executable:
chmod +x gitea2hashcat.py
Convert single pair:


python3 gitea2hashcat.py <salt>:<hash>
Pipe from sqlite:


sqlite3 gitea.db "select salt,passwd from user;" | python3 gitea2hashcat.py > hashes.txt
Crack with hashcat:


hashcat -m 10900 hashes.txt /path/to/wordlist.txt
