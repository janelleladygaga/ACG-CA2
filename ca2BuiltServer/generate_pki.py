import datetime
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


def save_private_key(key, path):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def build_name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_self_signed_ca():
    private_key = ed25519.Ed25519PrivateKey.generate()
    name = build_name("CA2 Practice Root CA")

    # subject == issuer is what makes this "self-signed" — the CA is
    # vouching for itself, since there's no one above it to vouch for it.
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        # BasicConstraints(ca=True) is a flag baked into the cert saying
        # "I am allowed to sign other certificates" — required for a root CA.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # algorithm=None is required for Ed25519/Ed448 keys specifically —
        # unlike RSA, they have one fixed internal hash, nothing to configure.
        .sign(private_key, algorithm=None)
    )
    return private_key, cert


def make_identity_cert(common_name, ca_private_key, ca_cert):
    private_key = ed25519.Ed25519PrivateKey.generate()

    cert = (
        x509.CertificateBuilder()
        .subject_name(build_name(common_name))
        # issuer is the CA's name, not this identity's own name — this
        # cert is NOT self-signed.
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        # ca=False — this identity cannot sign other certificates, unlike the root.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # signed with the CA's private key, not the identity's own key —
        # a certificate is something done TO your public key by someone
        # else, never something you do to yourself.
        .sign(ca_private_key, algorithm=None)
    )
    return private_key, cert


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)

    print("[PKI] Generating root CA...")
    ca_private_key, ca_cert = make_self_signed_ca()
    save_private_key(ca_private_key, os.path.join(KEYS_DIR, "ca_private.pem"))
    save_cert(ca_cert, os.path.join(KEYS_DIR, "ca_cert.pem"))

    print("[PKI] Generating server identity, signed by CA...")
    server_private_key, server_cert = make_identity_cert("server", ca_private_key, ca_cert)
    save_private_key(server_private_key, os.path.join(KEYS_DIR, "server_private.pem"))
    save_cert(server_cert, os.path.join(KEYS_DIR, "server_cert.pem"))

    print("[PKI] Generating client identity, signed by CA...")
    client_private_key, client_cert = make_identity_cert("client", ca_private_key, ca_cert)
    save_private_key(client_private_key, os.path.join(KEYS_DIR, "client_private.pem"))
    save_cert(client_cert, os.path.join(KEYS_DIR, "client_cert.pem"))

    print(f"\n[PKI] Done. Files written to {KEYS_DIR}")
    print("[PKI] Keep *_private.pem files confidential — never send them over the network.")


if __name__ == "__main__":
    main()
