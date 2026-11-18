#!/usr/bin/env python3
import argparse
import base64
import logging
import os
import socket
import struct
import tempfile
import threading

from ledgerblue.comm import getDongle

SIG_HEADER = b"ecdsa-sha2-nistp256"
SOCK_PREFIX = "blue-ssh-agent"
TIMEOUT = 0.5

SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5


def u32(value):
    return struct.pack(">I", value)


def read_exact(connection, count):
    """Read exactly count bytes, or return None if the peer disconnects."""
    chunks = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_bip32_path(path):
    if not path:
        return b""

    result = bytearray()
    for element in path.split("/"):
        hardened = element.endswith("'")
        number = element[:-1] if hardened else element
        index = int(number, 10)
        if not 0 <= index < 0x80000000:
            raise ValueError("BIP32 path index out of range")
        if hardened:
            index |= 0x80000000
        result.extend(u32(index))
    return bytes(result)


def handle_request_identities(key_blob, comment):
    return (
        bytes([SSH2_AGENT_IDENTITIES_ANSWER])
        + u32(1)
        + u32(len(key_blob)) + key_blob
        + u32(len(comment)) + comment
    )


def handle_sign_request(payload, key_blob, path):
    # Payload: key blob, data-to-sign, flags.
    if len(payload) < 4:
        return bytes([SSH_AGENT_FAILURE])

    blob_size = struct.unpack(">I", payload[:4])[0]
    cursor = 4
    if len(payload) < cursor + blob_size + 4:
        return bytes([SSH_AGENT_FAILURE])

    requested_blob = payload[cursor:cursor + blob_size]
    cursor += blob_size
    if requested_blob != key_blob:
        logging.debug("Client requested a different key blob")
        return bytes([SSH_AGENT_FAILURE])

    challenge_size = struct.unpack(">I", payload[cursor:cursor + 4])[0]
    cursor += 4
    if len(payload) < cursor + challenge_size:
        return bytes([SSH_AGENT_FAILURE])

    challenge = payload[cursor:cursor + challenge_size]
    dongle = getDongle(logging.getLogger().isEnabledFor(logging.DEBUG))
    try:
        encoded_path = parse_bip32_path(path)
        offset = 0
        signature = None

        while offset < len(challenge):
            data = b""
            if offset == 0:
                if len(encoded_path) // 4 > 255:
                    raise ValueError("BIP32 path is too long")
                data = bytes([len(encoded_path) // 4]) + encoded_path

            chunk_size = min(len(challenge) - offset, 255 - len(data))
            if chunk_size <= 0:
                raise ValueError("No room for challenge data in APDU")

            data += challenge[offset:offset + chunk_size]
            p1 = 0x00 if offset == 0 else 0x01
            offset += chunk_size
            if offset == len(challenge):
                p1 |= 0x80

            # ECDSA mode, matching the pasted legacy agent.
            apdu = bytes.fromhex("8004") + bytes([p1, 0x01, len(data)]) + data
            signature = dongle.exchange(apdu)
    finally:
        dongle.close()

    # Preserve the legacy app's signature-response parsing.
    if not signature or len(signature) < 6:
        return bytes([SSH_AGENT_FAILURE])

    r_length = signature[3]
    r_start = 4
    s_length_index = r_start + r_length + 1
    if s_length_index >= len(signature):
        return bytes([SSH_AGENT_FAILURE])

    s_length = signature[s_length_index]
    s_start = s_length_index + 1
    r = signature[r_start:r_start + r_length]
    s = signature[s_start:s_start + s_length]
    if len(r) != r_length or len(s) != s_length:
        return bytes([SSH_AGENT_FAILURE])

    signature_value = u32(len(r)) + r + u32(len(s)) + s
    encoded_signature = (
        u32(len(SIG_HEADER)) + SIG_HEADER
        + u32(len(signature_value)) + signature_value
    )
    return bytes([SSH2_AGENT_SIGN_RESPONSE]) + u32(len(encoded_signature)) + encoded_signature


def client_handler(connection, key_blob, comment, path):
    try:
        while True:
            header = read_exact(connection, 4)
            if header is None:
                return

            message_size = struct.unpack(">I", header)[0]
            if message_size < 1 or message_size > 1_048_576:
                return

            message = read_exact(connection, message_size)
            if message is None:
                return

            logging.debug("Received SSH-agent message type %d", message[0])
            if message[0] == SSH2_AGENTC_REQUEST_IDENTITIES:
                response = handle_request_identities(key_blob, comment)
            elif message[0] == SSH2_AGENTC_SIGN_REQUEST:
                response = handle_sign_request(message[1:], key_blob, path)
            else:
                response = bytes([SSH_AGENT_FAILURE])

            connection.sendall(u32(len(response)) + response)
    except Exception:
        logging.debug("Error handling SSH-agent client", exc_info=True)
        try:
            response = bytes([SSH_AGENT_FAILURE])
            connection.sendall(u32(len(response)) + response)
        except OSError:
            pass
    finally:
        connection.close()


parser = argparse.ArgumentParser()
parser.add_argument("--path", default="44'/535348'/0'/0/0",
                    help="BIP32 derivation path")
parser.add_argument("--key", required=True,
                    help="Base64-encoded SSH public-key blob")
parser.add_argument("--debug", action="store_true",
                    help="Enable debug logging")
args = parser.parse_args()

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)

try:
    key_blob = base64.b64decode(args.key, validate=True)
    parse_bip32_path(args.path)  # Validate the path before starting.
except (ValueError, TypeError) as error:
    parser.error(f"invalid --key or --path: {error}")

# Put the socket in a private temporary directory. The directory is normally
# created with owner-only permissions by tempfile.
socket_dir = tempfile.mkdtemp(prefix=SOCK_PREFIX + "-")
socket_path = os.path.join(socket_dir, "agent.sock")

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    server.bind(socket_path)
    os.chmod(socket_path, 0o600)
    server.listen(5)

    print("Export these variables in your shell:")
    print(f"export SSH_AUTH_SOCK={socket_path}")
    print(f"export SSH_AGENT_PID={os.getpid()}")
    print("Agent running ...")

    while True:
        connection, _ = server.accept()
        connection.settimeout(TIMEOUT)
        threading.Thread(
            target=client_handler,
            args=(connection, key_blob, b"Ledger SSH key", args.path),
            daemon=True,
        ).start()
except KeyboardInterrupt:
    pass
finally:
    server.close()
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    try:
        os.rmdir(socket_dir)
    except OSError:
        pass
