
# Colossus ⚔️

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/abhaybansal16/colossus/blob/main/LICENSE) [![Python Version](https://img.shields.io/badge/python-3.6+-brightgreen.svg)](https://www.python.org/downloads/)

A Universal Crypto Analyzer Tool for security researchers, CTF players, and developers.

Colossus is a fast, all-in-one command-line utility that helps you quickly encode, decode, hash, and analyze strings. It supports common encodings, classical ciphers, and modern hashes, and can automatically analyze a string to identify its type.


## Features

- **Multiple Modes:** Encrypt, Decrypt, and Auto-Analyze.
- **Common Encodings:** Base64, Hex, URL.
- **Classical Ciphers:** Caesar (brute-force), ROT47, Vigenère, Substitution.
- **Modern Hashes:** MD5, SHA1, SHA256.
- **Pipeline Support:** Natively works with other command-line tools like `echo` and `cat`.
- **Statistical Analysis:** Calculates Shannon entropy to guess data type.

## Installation

Clone the repository and run the installer. The script will install dependencies and move `colossus` to `/usr/local/bin`, making it available system-wide.

```
bash
# Clone the repository
git clone https://github.com/abhaybansal16/colossus.git

# Navigate into the directory
cd colossus

# Run the installer with sudo
sudo bash install.sh
````

Open a new terminal session after installation for the `colossus` command to be available.

## Usage

### Help Menu

```text
usage: (for mac) colossus [-h] (-e | -d) [--ENCRYPTION_TYPE] [-k KEY] [text]
usage: (for linux/wsl) colossus [-h] (-e | -d) [ENCRYPTION_TYPE] [-k KEY] [text]
Colossus - A Universal Crypto Analyzer Tool.

positional arguments:
  text                  The string to be processed (optional if piped from stdin).

options:
  -h, --help            show this help message and exit
  -e, --encrypt         Encrypt/encode/hash the input string.
  -d, --decrypt         Decrypt/decode or analyze the input string.
                        (With a method flag: decodes. Without: analyzes.)
  -k, --key KEY         Key for ciphers like Vigenere or Substitution.

methods:
  Choose ONE of the following methods:

 --base64/b64         Use Base64 encoding/decoding.
--base64url/b64url    Use Base64 URL Safe encoding/decoding.
--hex                 Use Hex encoding/decoding.
--url                 Use URL encoding/decoding.
--rot47               Use ROT47 cipher.
--vigenere            Use Vigenere cipher (requires --key).
--substitution        Use Substitution cipher (requires --key).
--caesar              Use Caesar cipher brute-force (decode only).
--md5                 Use MD5 hash (encode only).
--sha1                Use SHA1 hash (encode only).
--sha224              Use SHA224 hash (encode only).
--sha256              Use SHA256 hash (encode only).
--sha384              Use SHA384 hash (encode only).
--sha512              Use SHA512 hash (encode only).
--sha3-224            Use SHA3-224 hash (encode only).
--sha3-256            Use SHA3-256 hash (encode only).
--sha3-384            Use SHA3-384 hash (encode only).
--sha3-512            Use SHA3-512 hash (encode only).


Example pipeline usage:
  echo "hello world" | colossus -e --base64
```

### Basic Examples

**Encoding & Hashing**

```bash
$ echo "hello world" | colossus -e --base64

 /$$$$$$    /$$$$$$  /$$        /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$
/ $$__ $$  /$$__  $$| $$       /$$__  $$ /$$__  $$ /$$__  $$| $$  | $$ /$$__  $$
| $$  \__/| $$  \ $$| $$      | $$  \ $$| $$  \__/| $$  \__/| $$  | $$| $$  \__/
| $$      | $$  | $$| $$      | $$  | $$|  $$$$$$ |  $$$$$$ | $$  | $$|  $$$$$$
| $$      | $$  | $$| $$      | $$  | $$ \____  $$ \____  $$| $$  | $$ \____  $$
| $$    $$| $$  | $$| $$      | $$  | $$ /$$  \ $$ /$$  \ $$| $$  | $$ /$$  \ $$
|  $$$$$$/|  $$$$$$/| $$$$$$$$|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/
 \______/  \______/ |________/ \______/  \______/  \______/  \______/  \______/

                A Universal Crypto Analyzer for Researchers

[+] Mode:  Encrypt/Hash
[+] Type:  BASE64
[+] Input: hello world
[+] Output: aGVsbG8gd29ybGQ=
```

**Decoding & Analysis**

```bash
$   colossus -d "w6==@"

 /$$$$$$    /$$$$$$  /$$        /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$
/ $$__ $$  /$$__  $$| $$       /$$__  $$ /$$__  $$ /$$__  $$| $$  | $$ /$$__  $$
| $$  \__/| $$  \ $$| $$      | $$  \ $$| $$  \__/| $$  \__/| $$  | $$| $$  \__/
| $$      | $$  | $$| $$      | $$  | $$|  $$$$$$ |  $$$$$$ | $$  | $$|  $$$$$$
| $$      | $$  | $$| $$      | $$  | $$ \____  $$ \____  $$| $$  | $$ \____  $$
| $$    $$| $$  | $$| $$      | $$  | $$ /$$  \ $$ /$$  \ $$| $$  | $$ /$$  \ $$
|  $$$$$$/|  $$$$$$/| $$$$$$$$|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/
 \______/  \______/ |________/ \______/  \______/  \______/  \______/  \______/


                A Universal Crypto Analyzer for Researchers

[*] Starting automatic analysis on: w6==@

--- STATISTICAL ANALYSIS ---
    Shannon Entropy: 1.9219
    Hint: Low entropy suggests plain text or simple encoding (e.g., Hex).

--- ENCODING & HASH ANALYSIS ---
[-] No common encoding or hash type identified.

--- CLASSICAL CIPHER ANALYSIS ---
 Detected as: ROT47
          Result: Hello

```
