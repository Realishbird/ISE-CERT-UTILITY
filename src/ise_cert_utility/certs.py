"""Local certificate inspection and verification."""
import hashlib
import re
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from . import paths

PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def fingerprint(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def clean_fingerprint(value):
    return re.sub(r"[^0-9a-f]", "", (value or "").lower())


def load_pems(data):
    return [x509.load_pem_x509_certificate(block) for block in PEM_CERT.findall(data)]


def to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def describe(cert):
    expires = cert.not_valid_after_utc
    try:
        names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = names.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"ECDSA {key.curve.name}"
    else:
        key_desc = type(key).__name__
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": _cn(cert.issuer),
        "sans": sans,
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "expires": expires.isoformat(),
        "days": (expires - datetime.now(UTC)).days,
        "lifetime_days": max((expires - cert.not_valid_before_utc).days, 1),
        "fingerprint": fingerprint(cert),
        "key": key_desc,
    }


def _cn(name):
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


_cache = {}


def info(domain):
    """Describe the current certificate for domain; cached by file mtime."""
    if not domain:
        return {"present": False}
    path = paths.live_dir(domain) / "cert.pem"
    try:
        stamp = path.stat().st_mtime_ns
    except (FileNotFoundError, PermissionError):
        return {"present": False}
    cached = _cache.get(path)
    if cached and cached[0] == stamp:
        result = dict(cached[1])
    else:
        try:
            result = {"present": True, **describe(x509.load_pem_x509_certificate(path.read_bytes()))}
        except (ValueError, OSError):
            return {"present": True, "error": "The certificate file could not be parsed."}
        _cache[path] = (stamp, result)
    # Recompute so a long-running process does not show a stale countdown.
    result["days"] = (datetime.fromisoformat(result["expires"]) - datetime.now(UTC)).days
    return result


def system_roots():
    return load_pems(paths.SYSTEM_CA_BUNDLE.read_bytes())


def verify_lineage(domain, min_days=7, names=()):
    """Validate the issued certificate end to end and return (leaf, intermediates, root).

    Checks hostname, that every configured name is present, validity period, serverAuth usage, the chain to a public
    root in the system trust store, and that the private key matches.
    """
    live = paths.live_dir(domain)
    leaf = x509.load_pem_x509_certificate((live / "cert.pem").read_bytes())
    intermediates = load_pems((live / "chain.pem").read_bytes())
    if not intermediates:
        raise RuntimeError("chain.pem does not contain any intermediate certificates.")
    absent = sorted(set(names) - set(describe(leaf)["sans"]))
    if absent:
        raise RuntimeError(f"The certificate does not include {', '.join(absent)}. "
                           "Run Renew and deploy to request one with the configured names.")
    remaining = leaf.not_valid_after_utc - datetime.now(UTC)
    if remaining < timedelta(days=min_days):
        raise RuntimeError(f"The certificate expires in {remaining.days} days; renew it before deploying.")
    verifier = PolicyBuilder().store(Store(system_roots())).build_server_verifier(x509.DNSName(domain))
    try:
        chain = verifier.verify(leaf, intermediates)
    except VerificationError as exc:
        raise RuntimeError(f"Certificate chain did not validate against public roots: {exc}") from None
    key = serialization.load_pem_private_key((live / "privkey.pem").read_bytes(), password=None)
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spki) != leaf.public_key().public_bytes(*spki):
        raise RuntimeError("The certificate and private key do not match.")
    return leaf, chain[1:-1], chain[-1]


def is_ca(cert):
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False
