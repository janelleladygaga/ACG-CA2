import socket
import struct

from Crypto.Cipher import AES

# Load the same key/nonce that generateKey.py produced, so this matches
# whatever server.py is using.
with open("key.bin", "rb") as f:
    key = f.read()

with open("nonce.bin", "rb") as f:
    nonce = f.read()

# AES-EAX is an AEAD (Authenticated Encryption with Associated Data) mode:
# it gives both confidentiality (encryption) AND a way to prove integrity
# (via the tag produced below), from a single primitive.
cipher = AES.new(key,AES.MODE_EAX, nonce)


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost",9999))  # TCP handshake to the server

filename = "file.txt"

with open(filename,"rb") as f:
    data = f.read()  # read the whole file into memory as raw bytes

# encrypt_and_digest() does two things at once:
#  - encrypted: the ciphertext (same length as the original data, for EAX)
#  - tag: a 16-byte value that lets the receiver PROVE nothing was altered.
#    If even one bit of `encrypted` changes later, this tag won't match anymore.
encrypted, tag = cipher.encrypt_and_digest(data)

# --- Send everything over the socket, in an order both sides agree on ---
# TCP is just a raw byte stream (no built-in message boundaries), so every
# piece we send needs either a fixed, known size, or a length prefix telling
# the receiver how many bytes to read.

# 1. Filename: variable length, so send a 4-byte length header first.
filename_bytes = filename.encode()
client.sendall(struct.pack(">I", len(filename_bytes)))
client.sendall(filename_bytes)

# 2. Tag: EAX tags are always exactly 16 bytes, so no length prefix needed —
#    the receiver already knows to read exactly 16 bytes here.
client.sendall(tag)

# 3. Ciphertext: variable length (depends on file size), so length-prefix it too.
client.sendall(struct.pack(">I", len(encrypted)))
client.sendall(encrypted)

client.close()
