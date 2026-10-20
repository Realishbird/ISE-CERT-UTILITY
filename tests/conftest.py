import datetime
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(tempfile.mkdtemp(prefix="ise-cert-utility-test-"))
os.environ["ISE_CERT_UTILITY_ETC"] = str(ROOT / "etc")
os.environ["ISE_CERT_UTILITY_VAR"] = str(ROOT / "var")
os.environ["ISE_CERT_UTILITY_SYSTEM_CA"] = str(ROOT / "roots.pem")

import pytest  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from ise_cert_utility import config, paths  # noqa: E402


@pytest.fixture(autouse=True)
def clean_state():
    for directory in (paths.ETC, paths.VAR):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, mode=0o700)
    yield


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _build(subject, issuer, key, signer, *, ca, days=90, san=None, start=None):
    now = start or datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    else:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
                                    critical=False)
    return builder.sign(signer, hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def issued():
    """A root -> intermediate -> leaf chain written in Certbot's live/ layout."""
    domain = "ise.example.net"
    root_key, int_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _build("Test Root", "Test Root", root_key, root_key, ca=True, days=3650)
    inter = _build("Test Intermediate", "Test Root", int_key, root_key, ca=True, days=1000)
    leaf = _build(domain, "Test Intermediate", leaf_key, int_key, ca=False, san=domain)
    live = paths.live_dir(domain)
    live.mkdir(parents=True)
    (live / "cert.pem").write_bytes(pem(leaf))
    (live / "chain.pem").write_bytes(pem(inter))
    (live / "fullchain.pem").write_bytes(pem(leaf) + pem(inter))
    (live / "privkey.pem").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths.SYSTEM_CA_BUNDLE.write_bytes(pem(root))
    return {"domain": domain, "root": root, "intermediate": inter, "leaf": leaf}


@pytest.fixture
def configured(issued):
    config.save({"domain": issued["domain"], "acme_email": "pki@example.net", "node": "ise-01",
                 "username": "api"})
    config.save_secrets({"ise_password": "ise-secret-password", "cloudflare_token": "cf_token_value_123456789"})
    return {**config.load(), **issued}
