from Crypto.Random import get_random_bytes  # cryptographically secure random generator

KEY_FILE = "key.bin"
NONCE_FILE = "nonce.bin"

# Generate a random 16-byte (128-bit) AES key and a random 16-byte nonce.
# get_random_bytes() is safe for crypto use — Python's built-in `random`
# module is predictable and must never be used to generate keys.
key = get_random_bytes(16)
nonce = get_random_bytes(16)

# Save both to disk so client.py and server.py can load the SAME values.
# Random alone isn't enough — both sides need to agree on the exact same
# key/nonce, and calling get_random_bytes() separately in each script would
# give two different, incompatible values. "Generate once, both sides read
# the same file" is the simplest way to keep them in sync.
with open(KEY_FILE, "wb") as f:
    f.write(key)

with open(NONCE_FILE, "wb") as f:
    f.write(nonce)

print(f"[KEYGEN] New key saved to {KEY_FILE}")
print(f"[KEYGEN] New nonce saved to {NONCE_FILE}")
print("[KEYGEN] Run this again any time you want to rotate to a fresh key+nonce.")