import socket
import struct

from Crypto.Cipher import AES

with open("key.bin", "rb") as f:
    key = f.read()

with open("nonce.bin", "rb") as f:
    nonce = f.read()

cipher = AES.new(key, AES.MODE_EAX, nonce)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))

filename = "file.txt"

with open(filename, "rb") as f:
    data = f.read()

encrypted, tag = cipher.encrypt_and_digest(data)

print("[TAMPER TEST] Original ciphertext (first byte):", encrypted[0])

# deliberately flip one bit in the ciphertext, simulating an attacker
# modifying the data in transit (e.g. a MITM on the network)
tampered = bytearray(encrypted)
tampered[0] ^= 0xFF
encrypted = bytes(tampered)

print("[TAMPER TEST] Tampered ciphertext (first byte): ", encrypted[0])
print("[TAMPER TEST] Sending corrupted payload with the ORIGINAL (untampered) tag...")

filename_bytes = filename.encode()
client.sendall(struct.pack(">I", len(filename_bytes)))
client.sendall(filename_bytes)

client.sendall(tag)

client.sendall(struct.pack(">I", len(encrypted)))
client.sendall(encrypted)

client.close()
print("[TAMPER TEST] Sent. Check the server's output — it should reject this with an INTEGRITY CHECK FAILED message.")
