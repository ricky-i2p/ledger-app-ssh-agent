#!/usr/bin/env python3
"""Ledger Blue SSH public-key retrieval."""

import argparse
import base64
import struct

from ledgerblue.comm import getDongle


KEY_HEADER = "ecdsa-sha2-nistp256"
CURVE_NAME = "nistp256"
KEY_HEADER_ED25519 = "ssh-ed25519"


def parse_bip32_path(path):
    if not path:
        return b""

    result = bytearray()
    for element in path.split("/"):
        hardened = element.endswith("'")
        if hardened:
            element = element[:-1]

        index = int(element)
        if not 0 <= index < 0x80000000:
            raise ValueError(f"Invalid BIP32 path element: {element}")

        if hardened:
            index |= 0x80000000

        result.extend(struct.pack(">I", index))

    return bytes(result)


parser = argparse.ArgumentParser()
parser.add_argument("--path", help="BIP32 path to retrieve")
parser.add_argument("--ed25519", help="Use Ed25519 curve", action="store_true")
args = parser.parse_args()

path = args.path or "44'/535348'/0'/0/0"
dongle_path = parse_bip32_path(path)

if args.ed25519:
    p2 = "02"
    key_header = KEY_HEADER_ED25519
else:
    p2 = "01"
    key_header = KEY_HEADER

# APDU header, followed by path length/count and the encoded path.
apdu = (
    bytes.fromhex("800200" + p2)
    + bytes((len(dongle_path) + 1, len(dongle_path) // 4))
    + dongle_path
)

dongle = getDongle(True)
result = dongle.exchange(apdu)
key = result[1:]

key_header_bytes = key_header.encode("ascii")
blob = struct.pack(">I", len(key_header_bytes)) + key_header_bytes

if args.ed25519:
    if len(key) < 64:
        raise ValueError(f"Expected at least 64 key bytes, got {len(key)}")

    key_x = key[:32]
    key_y = bytearray(key[32:64][::-1])

    if key_x[31] & 1:
        key_y[31] |= 0x80

    key = bytes(key_y)
else:
    curve_name_bytes = CURVE_NAME.encode("ascii")
    blob += struct.pack(">I", len(curve_name_bytes)) + curve_name_bytes

blob += struct.pack(">I", len(key)) + key
print(key_header + " " + base64.b64encode(blob).decode("ascii"))

