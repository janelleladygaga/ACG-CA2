import socket
import struct
import tqdm
from Crypto.Cipher import AES

# Load the SAME key/nonce the client is using — generated once by
# generateKey.py, both sides just read the file.
with open("key.bin", "rb") as f:
    key = f.read()

with open("nonce.bin", "rb") as f:
    nonce = f.read()

cipher = AES.new(key,AES.MODE_EAX, nonce)


def recv_exact(sock, n):
    """Block until exactly n bytes have been received, no more, no less.
    Needed because sock.recv(n) only REQUESTS up to n bytes — the OS can
    hand back fewer, so this loops and accumulates until we have it all."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before expected bytes arrived")
        buf.extend(chunk)
    return bytes(buf)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",9999))
server.listen()  # start accepting incoming connections

client, addr = server.accept()  # blocks until a client connects; `client` is
                                 # a NEW socket just for this one connection


# --- Read everything back in the exact order client.py sent it ---

# 1. Filename: first read the 4-byte length header, then that many bytes.
filename_len = struct.unpack(">I", recv_exact(client, 4))[0]
file_name = recv_exact(client, filename_len).decode()
print(file_name)

# 2. Tag: always exactly 16 bytes for EAX, no header needed.
tag = recv_exact(client, 16)

# 3. Ciphertext length header — also tells us exactly how many bytes to
#    expect in the recv loop below, so no separate end-marker is needed.
file_size = struct.unpack(">I", recv_exact(client, 4))[0]
print(file_size)


progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1000, total=file_size)

# Read the ciphertext in a loop (recv() may hand back data in smaller pieces
# than file_size), until we've collected exactly file_size bytes.
encrypted_data = bytearray()
while len(encrypted_data) < file_size:
    chunk = client.recv(1024)
    if not chunk:
        raise ConnectionError("socket closed before full file arrived")
    encrypted_data.extend(chunk)
    progress.update(len(chunk))

# decrypt_and_verify() recomputes what the tag SHOULD be from the received
# ciphertext and compares it to the tag we were sent. If they don't match —
# meaning the data was altered anywhere in transit — it raises ValueError
# instead of handing back plaintext. This IS the integrity check.
try:
    plaintext = cipher.decrypt_and_verify(bytes(encrypted_data), tag)
except ValueError:
    print("[SERVER] INTEGRITY CHECK FAILED — data was tampered with or corrupted in transit. Discarding.")
    client.close()
    server.close()
    raise SystemExit(1)

# Only reached if verification succeeded — so it's safe to open (and
# truncate) the destination file here, not before.
with open(file_name, "wb") as file:
    file.write(plaintext)

client.close()
server.close()
