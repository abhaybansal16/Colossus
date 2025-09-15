````markdown
# Colossus ⚔️

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.6+-brightgreen.svg)

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

```bash
# Clone the repository
git clone [https://github.com/abhaybansal16/colossus.git](https://github.com/abhaybansal16/colossus.git)

# Navigate into the directory
cd colossus

# Run the installer with sudo
sudo bash install.sh
````

Open a new terminal session after installation for the `colossus` command to be available.

## Usage

### Help Menu

\<details\>
\<summary\>Click to view the full help menu\</summary\>

```text
usage: colossus [-h] (-e | -d) [--base64] [--hex] [--url] [--rot47] [--vigenere] [--substitution] [--caesar] [--md5] [--sha1] [--sha256] [-k KEY] [text]

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

  --base64              Use Base64 encoding/decoding.
  --hex                 Use Hex encoding/decoding.
  --url                 Use URL encoding/decoding.
  --rot47               Use ROT47 cipher.
  --vigenere            Use Vigenere cipher (requires --key).
  --substitution        Use Substitution cipher (requires --key).
  --caesar              Use Caesar cipher brute-force (decrypt mode only).
  --md5                 Use MD5 hash (encrypt mode only).
  --sha1                Use SHA1 hash (encrypt mode only).
  --sha256              Use SHA256 hash (encrypt mode only).

Example pipeline usage:
  echo "hello world" | colossus -e --base64
```

\</details\>

### Basic Examples

**Encoding & Hashing**

```bash
$ echo "hello world" | colossus -e --base64

 /$$$$$$   /$$$$$$  /$$        /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$/$$__ $$ /$$__  $$| $$      /$$__ $$ /$$__  $$/$$__ $$| $$ |$$ /$$__  $$|$$  \__/| $$ \$$| $$     |$$  \ $$| $$ \__/|$$  \__/| $$ |$$| $$  \__/
| $$     |$$  | $$| $$     |$$  | $$|  $$$$$$| $$$$$$|$$  | $$|  $$$$$$|$$      | $$ |$$| $$     |$$  | $$\____ $$ \____  $$| $$ |$$ \____  $$|$$    $$| $$ |$$| $$     |$$  | $$/$$  \$$ /$$ \$$| $$ |$$ /$$ \$$
|  $$$$$$/| $$$$$$/| $$$$$$$$| $$$$$$/| $$$$$$/| $$$$$$/| $$$$GG| $$$$$$/
 \______/ \______/ |________/ \______/ \______/ \______/ \______/ \______/

                A Universal Crypto Analyzer for Researchers

[+] Mode:  Encrypt/Hash
[+] Type:  BASE64
[+] Input: hello world
[+] Output: aGVsbG8gd29ybGQ=
```

**Decoding & Analysis**

```bash
$ colossus -d "aGVsbG8gd29ybGQ="

 /$$$$$$   /$$$$$$  /$$        /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$/$$__ $$ /$$__  $$| $$      /$$__ $$ /$$__  $$/$$__ $$| $$ |$$ /$$__  $$|$$  \__/| $$ \$$| $$     |$$  \ $$| $$ \__/|$$  \__/| $$ |$$| $$  \__/
| $$     |$$  | $$| $$     |$$  | $$|  $$$$$$| $$$$$$|$$  | $$|  $$$$$$|$$      | $$ |$$| $$     |$$  | $$\____ $$ \____  $$| $$ |$$ \____  $$|$$    $$| $$ |$$| $$     |$$  | $$/$$  \$$ /$$ \$$| $$ |$$ /$$ \$$
|  $$$$$$/| $$$$$$/| $$$$$$$$| $$$$$$/| $$$$$$/| $$$$$$/| $$$$GG| $$$$$$/
 \______/ \______/ |________/ \______/ \______/ \______/ \______/ \______/

                A Universal Crypto Analyzer for Researchers

[*] Starting automatic analysis on: aGVsbG8gd29ybGQ=

--- STATISTICAL ANALYSIS ---
    Shannon Entropy: 3.7381
    Hint: Medium entropy is common for encodings like Base64.

--- ENCODING & HASH ANALYSIS ---
[+] Found potential matches:
     Detected as: Base64
           Result: hello world


--- CLASSICAL CIPHER ANALYSIS ---
```

```
```