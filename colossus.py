#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Colossus - A Universal Crypto Analyser Tool for Security Researchers
"""

import argparse
import base64
import hashlib
import re
import sys
import math
from collections import Counter
from urllib.parse import unquote, quote
from colorama import init, Fore, Style

# Initialise Colorama for cross-platform colored output
init(autoreset=True)

def print_banner():
    """Prints the Colossus ASCII art banner."""
    banner = r"""
 /$$$$$$    /$$$$$$  /$$        /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$
/ $$__ $$  /$$__  $$| $$       /$$__  $$ /$$__  $$ /$$__  $$| $$  | $$ /$$__  $$
| $$  \__/| $$  \ $$| $$      | $$  \ $$| $$  \__/| $$  \__/| $$  | $$| $$  \__/
| $$      | $$  | $$| $$      | $$  | $$|  $$$$$$ |  $$$$$$ | $$  | $$|  $$$$$$
| $$      | $$  | $$| $$      | $$  | $$ \____  $$ \____  $$| $$  | $$ \____  $$
| $$    $$| $$  | $$| $$      | $$  | $$ /$$  \ $$ /$$  \ $$| $$  | $$ /$$  \ $$
|  $$$$$$/|  $$$$$$/| $$$$$$$$|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/
 \______/  \______/ |________/ \______/  \______/  \______/  \______/  \______/
    """
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(Fore.YELLOW + Style.BRIGHT + "\n                A Universal Crypto Analyzer for Researchers\n")

# --- ENCODING AND HASHING FUNCTIONS ---

def encode_base64(text, key=None):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def encode_base64_url(text, key=None):
    return base64.urlsafe_b64encode(text.encode('utf-8')).decode('utf-8')

def encode_hex(text, key=None):
    return text.encode('utf-8').hex()

def encode_url(text, key=None):
    return quote(text)

def hash_md5(text, key=None):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def hash_sha1(text, key=None):
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def hash_sha224(text, key=None):
    return hashlib.sha224(text.encode('utf-8')).hexdigest()

def hash_sha256(text, key=None):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def hash_sha384(text, key=None):
    return hashlib.sha384(text.encode('utf-8')).hexdigest()

def hash_sha512(text, key=None):
    return hashlib.sha512(text.encode('utf-8')).hexdigest()

def hash_sha3_224(text, key=None):
    return hashlib.sha3_224(text.encode('utf-8')).hexdigest()

def hash_sha3_256(text, key=None):
    return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def hash_sha3_384(text, key=None):
    return hashlib.sha3_384(text.encode('utf-8')).hexdigest()

def hash_sha3_512(text, key=None):
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()

def encode_rot47(text, key=None):
    result = ""
    for char in text:
        char_ord = ord(char)
        if 33 <= char_ord <= 126:
            result += chr(33 + ((char_ord - 33 + 47) % 94))
        else:
            result += char
    return result

def encode_vigenere(text, key):
    result = ""
    key_index = 0
    for char in text:
        if 'a' <= char <= 'z':
            shift = ord(key[key_index % len(key)].lower()) - ord('a')
            result += chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            key_index += 1
        elif 'A' <= char <= 'Z':
            shift = ord(key[key_index % len(key)].lower()) - ord('a')
            result += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            key_index += 1
        else:
            result += char
    return result

def encode_substitution(text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    if len(key) != 26 or not all(c in key.lower() for c in alphabet):
        return "[ERROR] Substitution key must be a 26-character permutation of the alphabet."

    table = str.maketrans(alphabet + alphabet.upper(), key.lower() + key.upper())
    return text.translate(table)


# --- STATISTICAL AND CIPHER ANALYSIS ---

def calculate_entropy(data_bytes):
    """Calculates the Shannon entropy of a byte string."""
    if not data_bytes:
        return 0.0

    counts = Counter(data_bytes)
    total_length = len(data_bytes)
    entropy = 0.0

    for count in counts.values():
        p_x = count / total_length
        entropy -= p_x * math.log2(p_x)

    return entropy

def decode_caesar_bruteforce(ciphertext):
    """
    Brute-forces all possible Caesar cypher shifts (1-25) on the input text.
    Returns a list of tuples (shift, plaintext).
    """
    results = []
    for shift in range(1, 26):
        plaintext = ""
        for char in ciphertext:
            if 'a' <= char <= 'z':
                shifted = ord(char) - shift
                if shifted < ord('a'):
                    shifted += 26
                plaintext += chr(shifted)
            elif 'A' <= char <= 'Z':
                shifted = ord(char) - shift
                if shifted < ord('A'):
                    shifted += 26
                plaintext += chr(shifted)
            else:
                plaintext += char
        results.append((shift, plaintext))
    return results


# --- AUTO-IDENTIFICATION AND DECODING ---

def auto_identify_and_decode(input_str):
    """
    Identifies the encoding/hash of the input string and attempts to decode it.
    """
    print(f"{Fore.YELLOW}[*] Starting automatic analysis on: {Style.RESET_ALL}{input_str}")

    # --- 1. Statistical Analysis ---
    entropy = calculate_entropy(input_str.encode('utf-8', errors='ignore'))
    entropy_color = Fore.GREEN if entropy < 4 else Fore.YELLOW if entropy < 6 else Fore.RED
    print(f"\n{Fore.WHITE}{Style.BRIGHT}--- STATISTICAL ANALYSIS ---{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Shannon Entropy: {entropy_color}{Style.BRIGHT}{entropy:.4f}{Style.RESET_ALL}")
    if entropy > 6.0:
        print(f"    {Fore.YELLOW}Hint: High entropy suggests encrypted or compressed data.")
    elif entropy < 4.0:
        print(f"    {Fore.GREEN}Hint: Low entropy suggests plain text or simple encoding (e.g., Hex).")
    else:
        print(f"    {Fore.YELLOW}Hint: Medium entropy is common for encodings like Base64.")


    # --- 2. Identification Rules Engine ---
    print(f"\n{Fore.WHITE}{Style.BRIGHT}--- ENCODING & HASH ANALYSIS ---{Style.RESET_ALL}")
    identifications = []

    # Rule: Hexadecimal
    if re.fullmatch(r"^[a-fA-F0-9]+$", input_str) and len(input_str) % 2 == 0:
        try:
            decoded_hex = bytes.fromhex(input_str).decode('utf-8')
            # Check for printable characters to increase confidence
            if all(c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ' for c in decoded_hex):
                 identifications.append(('Hex', decoded_hex))
        except (ValueError, UnicodeDecodeError):
            pass # Not valid hex or not valid utf-8

    # Rule: Base64
    if re.fullmatch(r"^[a-zA-Z0-9+/]*={0,2}$", input_str) and len(input_str) % 4 == 0:
        try:
            decoded_b64 = base64.b64decode(input_str).decode('utf-8')
            identifications.append(('Base64', decoded_b64))
        except Exception:
            pass

    # Rule: Base64 URL Safe
    if re.fullmatch(r"^[a-zA-Z0-9_-]*={0,2}$", input_str) and len(input_str) % 4 == 0:
        try:
            decoded_b64_url = base64.urlsafe_b64decode(input_str).decode('utf-8')
            identifications.append(('Base64 URL Safe', decoded_b64_url))
        except Exception:
            pass

    # Rule: URL Encoded
    if '%' in input_str:
        try:
            decoded_url = unquote(input_str)
            # Only consider it a match if decoding actually changed the string
            if decoded_url != input_str:
                identifications.append(('URL Encoded', decoded_url))
        except Exception:
            pass

    # Rule: Hashes (by length)
    hash_lengths = {
        32: 'MD5',
        40: 'SHA-1',
        56: 'SHA-224 / SHA3-224',
        64: 'SHA-256 / SHA3-256',
        96: 'SHA-384 / SHA3-384',
        128: 'SHA-512 / SHA3-512'
    }

    if re.fullmatch(r"^[a-fA-F0-9]+$", input_str):
        length = len(input_str)
        if length in hash_lengths:
            identifications.append((f'Possible Hash ({hash_lengths[length]})', "Cannot be reversed. Try cracking it against a wordlist."))


    # --- Display Encoding/Hash Results ---
    if not identifications:
        print(f"{Fore.RED}[-] No common encoding or hash type identified.")
    else:
        print(f"{Fore.GREEN}[+] Found potential matches:")
        for type_name, result in identifications:
            print(f"    {Fore.GREEN} Detected as: {Style.BRIGHT}{type_name}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}      Result: {Style.BRIGHT}{result}{Style.RESET_ALL}\n")

    # --- 3. Classical Cypher Analysis ---
    print(f"\n{Fore.WHITE}{Style.BRIGHT}--- CLASSICAL CIPHER ANALYSIS ---{Style.RESET_ALL}")

    # Rule: ROT47
    if all(33 <= ord(c) <= 126 for c in input_str):
        decoded_rot47 = encode_rot47(input_str) # ROT47 is its own inverse
        if decoded_rot47 != input_str:
            print(f"{Fore.GREEN} Detected as: {Style.BRIGHT}ROT47{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}      Result: {Style.BRIGHT}{decoded_rot47}{Style.RESET_ALL}\n")

    # Rule: Caesar / ROT13
    if re.fullmatch(r"^[a-zA-Z\s,.]+$", input_str):
        print(f"{Fore.YELLOW}[*] Input is alphabetic, attempting Caesar cipher brute-force...{Style.RESET_ALL}")

        caesar_results = decode_caesar_bruteforce(input_str)
        for shift, plaintext in caesar_results:
            # Highlight ROT13 specifically, as it's a common case
            highlight = f"({Fore.MAGENTA}ROT13{Style.RESET_ALL})" if shift == 13 else ""
            print(f"    {Fore.GREEN}Shift {shift:02d}: {Fore.CYAN}{Style.BRIGHT}{plaintext} {highlight}")

        # Hint for more complex cyphers
        if entropy > 4.0:
            print(f"\n{Fore.YELLOW}[*] Hint: The high entropy for alphabetic text could indicate a polyalphabetic cipher like Vigenère.{Style.RESET_ALL}")


def main():
    """Main function to parse arguments and run the tool."""
    print_banner()
    # --- MODE SELECTION ---
    encode_help_text = (
        "Encode or hash the input string.\n"
        "Available options:\n"
        "  Encodings:\n"
        "    base64 (b64)\n"
        "    base64url (b64url)\n"
        "    hex\n"
        "    url\n"
        "  Ciphers:\n"
        "    rot47\n"
        "    vigenere (requires --key)\n"
        "    substitution (requires --key)\n"
        "  Hashes (SHA-2):\n"
        "    md5\n"
        "    sha1\n"
        "    sha224\n"
        "    sha256\n"
        "    sha384\n"
        "    sha512\n"
        "  Hashes (SHA-3):\n"
        "    sha3-224\n"
        "    sha3-256\n"
        "    sha3-384\n"
        "    sha3-512"
    )

    valid_encodings = [
        'base64', 'b64', 'base64url', 'b64url', 'hex', 'url',
        'rot47', 'vigenere', 'substitution',
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'
    ]

    parser = argparse.ArgumentParser(
        description="Colossus - A Universal Crypto Analyser Tool.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-e', '--encode',
        dest='encode_type',
        help=encode_help_text
        # no choices here to allow clean help formatting
    )
    group.add_argument(
        '-d', '--decode',
        action='store_true',
        help='Automatically identify and decode/analyse the input string.'
    )
    parser.add_argument('text', nargs='?', help='The string to be processed.')
    parser.add_argument('-k', '--key', help='Key for ciphers like Vigenere or Substitution.')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.encode_type and args.encode_type not in valid_encodings:
        print(f"{Fore.RED}[-] Error: Invalid encoding or hash type '{args.encode_type}'.\nValid types:\n  " +
              "\n  ".join(valid_encodings))
        sys.exit(1)

    # --- INPUT ---
    input_text = args.text
    if not input_text:
        if not sys.stdin.isatty():
            input_text = sys.stdin.read().rstrip('\n')
        else:
            print(f"{Fore.RED}[-] Error: No input provided. Please specify text argument or pipe input.")
            sys.exit(1)
    # --- LOGIC ---
    if args.decode:
        auto_identify_and_decode(input_text)
    elif args.encode_type:
        if args.encode_type in ['vigenere', 'substitution'] and not args.key:
            print(f"{Fore.RED}[-] Error: The '{args.encode_type}' cypher requires a key. Use the -k or --key argument.")
            sys.exit(1)
        actions = {
            'base64': encode_base64, 'b64': encode_base64,
            'base64url': encode_base64_url, 'b64url': encode_base64_url,
            'hex': encode_hex,
            'url': encode_url,
            'rot47': encode_rot47,
            'vigenere': encode_vigenere,
            'substitution': encode_substitution,
            'md5': hash_md5,
            'sha1': hash_sha1,
            'sha224': hash_sha224,
            'sha256': hash_sha256,
            'sha384': hash_sha384,
            'sha512': hash_sha512,
            'sha3-224': hash_sha3_224,
            'sha3-256': hash_sha3_256,
            'sha3-384': hash_sha3_384,
            'sha3-512': hash_sha3_512
        }

        result = actions[args.encode_type](input_text, args.key)
        print(f"{Fore.GREEN}[+] Input: {Style.RESET_ALL}{input_text}")
        if args.key:
            print(f"{Fore.GREEN}[+] Key:   {Style.RESET_ALL}{args.key}")
        print(f"{Fore.GREEN}[+] Type:  {Style.RESET_ALL}{args.encode_type.upper()}")
        print(f"{Fore.GREEN}[+] {Style.BRIGHT}Output: {Style.RESET_ALL}{Fore.CYAN}{Style.BRIGHT}{result}")

if __name__ == "__main__":
    main()
