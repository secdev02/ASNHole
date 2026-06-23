#!/usr/bin/env python3
# =============================================================================
# cert_test_battery.py  —  Certificate Validation Test Battery for Windows
# =============================================================================
#
# Generates a suite of signed .exe and .dll assemblies, each backed by a
# certificate chain containing a specific cryptographic anomaly.  Every binary
# is fed to PowerShell's Authenticode engine; unexpected results are preserved
# to a UUID-stamped fault archive.
#
# PREREQUISITES
# -------------
#   pip install cryptography
#   Windows 10/11 or Server 2019+  (PowerShell 5.1+)
#   .NET Framework 4.x  (for csc.exe)
#   Run elevated (Administrator) to avoid UAC dialogs on root-cert import.
#
# DIRECTORY LAYOUT PRODUCED
# -------------------------
#   C:\Test\CertValidation\
#     certs\          one sub-folder per anomaly with .pfx / .cer artefacts
#     assemblies\     .exe and .dll per anomaly
#     faults\         UUID-named folders for unexpected / crash results
#     logs\           main.log + per-case powershell transcripts
#     source\         generated C# source
#     report.json     machine-readable summary
# =============================================================================

import os
import sys
import json
import uuid
import shutil
import logging
import datetime
import subprocess
import textwrap
import traceback
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ── dependency guard ──────────────────────────────────────────────────────────
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )
except ImportError:
    sys.exit(
        "[FATAL] 'cryptography' is required.  Run:  pip install cryptography"
    )

# =============================================================================
# §1  CONFIGURATION
# =============================================================================

BASE_DIR     = Path(r"C:\Test\CertValidation")
CERT_DIR     = BASE_DIR / "certs"
ASSEMBLY_DIR = BASE_DIR / "assemblies"
FAULT_DIR    = BASE_DIR / "faults"
LOG_DIR      = BASE_DIR / "logs"
SOURCE_DIR   = BASE_DIR / "source"
REPORT_PATH  = BASE_DIR / "report.json"

# Optional: original MS kernel cert paths (cloning attempted if present)
MS_CERT_DIR  = Path(r"C:\Test")
MS_ROOT_CER  = MS_CERT_DIR / "MSKernel32Root.cer"
MS_PCA_CER   = MS_CERT_DIR / "MSKernel32PCA.cer"
MS_LEAF_CER  = MS_CERT_DIR / "MSKernel32Leaf.cer"

PFX_PASSWORD = "TestBattery2024!"          # used for all PKCS#12 artefacts
STORE_MY     = r"Cert:\CurrentUser\My"
STORE_ROOT   = r"Cert:\CurrentUser\Root"
STORE_CA     = r"Cert:\CurrentUser\CA"

_TZ          = datetime.timezone.utc
_NOW         = datetime.datetime.now(_TZ)

# Convenience time anchors
T_PAST           = _NOW - datetime.timedelta(days=3650)   # 10 y ago
T_YESTERDAY      = _NOW - datetime.timedelta(days=1)
T_LEAF_FROM      = _NOW - datetime.timedelta(days=2)      # "issued" 2 days ago
T_FUTURE_START   = _NOW + datetime.timedelta(days=1)
T_FUTURE_END     = _NOW + datetime.timedelta(days=3650)
T_STANDARD_END   = _NOW + datetime.timedelta(days=3650)

# =============================================================================
# §2  ANOMALY REGISTRY
# =============================================================================

ANOMALIES: Dict[str, Dict[str, Any]] = {
    # ── Baseline ─────────────────────────────────────────────────────────────
    "VALID_CHAIN": {
        "desc": "Baseline — valid 3-level chain, all constraints correct",
        "expected_valid": True,
        "category": "baseline",
    },
    # ── Temporal anomalies ────────────────────────────────────────────────────
    "ROOT_EXPIRED": {
        "desc": "Root CA notAfter is in the past (certificate expired)",
        "expected_valid": False,
        "category": "temporal",
    },
    "ROOT_NOT_YET_VALID": {
        "desc": "Root CA notBefore is in the future (not yet valid)",
        "expected_valid": False,
        "category": "temporal",
    },
    "ICA_EXPIRED": {
        "desc": "Intermediate CA certificate has expired",
        "expected_valid": False,
        "category": "temporal",
    },
    "LEAF_EXPIRED": {
        "desc": "Leaf/end-entity certificate has expired",
        "expected_valid": False,
        "category": "temporal",
    },
    "LEAF_NOT_YET_VALID": {
        "desc": "Leaf certificate notBefore is in the future",
        "expected_valid": False,
        "category": "temporal",
    },
    # ── Signature / chain-integrity anomalies ─────────────────────────────────
    "LEAF_ROGUE_SIGNATURE": {
        "desc": "Leaf cert signed by rogue key instead of the true ICA",
        "expected_valid": False,
        "category": "signature",
    },
    "ICA_ROGUE_SIGNATURE": {
        "desc": "Intermediate cert signed by rogue key instead of the true root",
        "expected_valid": False,
        "category": "signature",
    },
    "LEAF_SELF_SIGNED": {
        "desc": "Leaf is self-signed; not chained to any CA",
        "expected_valid": False,
        "category": "signature",
    },
    "LEAF_BIT_FLIPPED": {
        "desc": "RSA signature bytes in the leaf cert DER have been bit-flipped",
        "expected_valid": False,
        "category": "signature",
    },
    # ── Key Usage / EKU anomalies ─────────────────────────────────────────────
    "LEAF_WRONG_EKU": {
        "desc": "Leaf EKU is emailProtection only — missing codeSigning",
        "expected_valid": False,
        "category": "eku",
    },
    "LEAF_NO_EKU": {
        "desc": "Leaf certificate has no Extended Key Usage extension at all",
        "expected_valid": False,
        "category": "eku",
    },
    "LEAF_KEY_USAGE_NO_SIGN": {
        "desc": "Leaf Key Usage set to keyEncipherment only — no digitalSignature bit",
        "expected_valid": False,
        "category": "key_usage",
    },
    # ── Basic Constraints anomalies ────────────────────────────────────────────
    "LEAF_IS_CA": {
        "desc": "Leaf certificate has BasicConstraints CA:TRUE (end-entity as CA)",
        "expected_valid": False,
        "category": "constraints",
    },
    "ICA_NO_CA_FLAG": {
        "desc": "Intermediate CA cert is missing BasicConstraints (not declared as CA)",
        "expected_valid": False,
        "category": "constraints",
    },
    "ICA_PATH_LEN_EXCEEDED": {
        "desc": "ICA has pathLenConstraint=0 but signs a sub-CA that then signs leaf",
        "expected_valid": False,
        "category": "constraints",
    },
    # ── Hash algorithm anomalies ───────────────────────────────────────────────
    "LEAF_MD5_SIGNATURE": {
        "desc": "Leaf certificate signed with md5WithRSAEncryption (banned)",
        "expected_valid": False,
        "category": "algorithm",
    },
    "LEAF_SHA1_SIGNATURE": {
        "desc": "Leaf certificate signed with sha1WithRSAEncryption (deprecated)",
        "expected_valid": False,
        "category": "algorithm",
    },
    # ── Key-size anomalies ────────────────────────────────────────────────────
    "LEAF_WEAK_KEY_1024": {
        "desc": "Leaf RSA key is 1024 bits — below Windows minimum",
        "expected_valid": False,
        "category": "key_size",
    },
    # ── Extension anomalies ───────────────────────────────────────────────────
    "LEAF_UNKNOWN_CRITICAL": {
        "desc": "Leaf contains an unrecognised critical extension (RFC 5280 §4.2)",
        "expected_valid": False,
        "category": "extension",
    },
    # ── Trust-store anomalies ─────────────────────────────────────────────────
    "ROOT_NOT_TRUSTED": {
        "desc": "Valid chain, but root cert deliberately NOT imported as trusted",
        "expected_valid": False,
        "category": "trust",
    },
}

# =============================================================================
# §3  DATACLASSES
# =============================================================================

@dataclass
class ChainSpec:
    """All parameters needed to build one certificate chain."""
    root_key_bits:          int                          = 2048
    root_valid_from:        datetime.datetime            = field(default_factory=lambda: _NOW)
    root_valid_to:          datetime.datetime            = field(default_factory=lambda: T_STANDARD_END)
    root_sign_hash:         str                          = "sha256"

    ica_key_bits:           int                          = 2048
    ica_valid_from:         datetime.datetime            = field(default_factory=lambda: _NOW)
    ica_valid_to:           datetime.datetime            = field(default_factory=lambda: T_STANDARD_END)
    ica_path_len:           Optional[int]                = 0
    ica_is_ca:              bool                         = True
    ica_sign_hash:          str                          = "sha256"
    ica_rogue_sign:         bool                         = False

    # Only used by ICA_PATH_LEN_EXCEEDED
    use_sub_ica:            bool                         = False

    leaf_key_bits:          int                          = 2048
    leaf_valid_from:        datetime.datetime            = field(default_factory=lambda: T_LEAF_FROM)
    leaf_valid_to:          datetime.datetime            = field(default_factory=lambda: T_STANDARD_END)
    leaf_eku:               Optional[List[str]]          = None   # None → code_signing
    leaf_ku_digital_sign:   bool                         = True
    leaf_is_ca:             bool                         = False
    leaf_sign_hash:         str                          = "sha256"
    leaf_rogue_sign:        bool                         = False
    leaf_self_signed:       bool                         = False
    leaf_unknown_critical:  bool                         = False
    leaf_bit_flip:          bool                         = False

    install_root:           bool                         = True


@dataclass
class TestRecord:
    """Tracks one anomaly test end-to-end."""
    test_id:        str
    anomaly_id:     str
    description:    str
    expected_valid: bool
    category:       str
    spec_dict:      Dict[str, Any]  = field(default_factory=dict)
    cert_dir:       str             = ""
    exe_path:       str             = ""
    dll_path:       str             = ""
    sign_exe:       Dict            = field(default_factory=dict)
    sign_dll:       Dict            = field(default_factory=dict)
    validate_exe:   Dict            = field(default_factory=dict)
    validate_dll:   Dict            = field(default_factory=dict)
    load_exe:       Dict            = field(default_factory=dict)
    load_dll:       Dict            = field(default_factory=dict)
    run_exe:        Dict            = field(default_factory=dict)
    is_fault:       bool            = False
    fault_reason:   str             = ""
    fault_dir:      str             = ""
    error:          str             = ""
    timestamp:      str             = field(default_factory=lambda: _NOW.isoformat())

# =============================================================================
# §4  LOGGING
# =============================================================================

log: logging.Logger = logging.getLogger("cert_battery")

def _setup_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(LOG_DIR / "main.log", encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    log.setLevel(logging.DEBUG)
    log.addHandler(fh)
    log.addHandler(ch)

def _init_dirs() -> None:
    for d in (CERT_DIR, ASSEMBLY_DIR, FAULT_DIR, LOG_DIR, SOURCE_DIR):
        d.mkdir(parents=True, exist_ok=True)

# =============================================================================
# §5  CRYPTOGRAPHY HELPERS
# =============================================================================

def _gen_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )


def _subject_name(cn: str, org: str = "CertTestBattery") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _hash_for(name: str):
    table = {
        "sha256": hashes.SHA256(),
        "sha1":   hashes.SHA1(),
        "md5":    hashes.MD5(),
    }
    if name not in table:
        raise ValueError("Unknown hash: " + name)
    return table[name]


def _build_root_cert(
    key,
    spec: ChainSpec,
    cn: str = "CertTest Root CA",
) -> x509.Certificate:
    subject = _subject_name(cn)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(spec.root_valid_from)
        .not_valid_after(spec.root_valid_to)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=2),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    return b.sign(key, _hash_for(spec.root_sign_hash), default_backend())


def _build_ica_cert(
    key,
    issuer_key,
    issuer_cert: x509.Certificate,
    spec: ChainSpec,
    cn: str = "CertTest Intermediate CA",
    path_len: Optional[int] = 0,
    is_ca: bool = True,
    sign_hash: str = "sha256",
    rogue_sign: bool = False,
) -> x509.Certificate:
    signing_key = _gen_key(2048) if rogue_sign else issuer_key
    b = (
        x509.CertificateBuilder()
        .subject_name(_subject_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(spec.ica_valid_from)
        .not_valid_after(spec.ica_valid_to)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    if is_ca:
        b = b.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len),
            critical=True,
        )
    else:
        # ICA_NO_CA_FLAG: deliberately omit BasicConstraints
        pass
    return b.sign(signing_key, _hash_for(sign_hash), default_backend())


def _build_leaf_cert(
    key,
    issuer_key,
    issuer_cert: x509.Certificate,
    spec: ChainSpec,
    cn: str = "CertTest Code Signing Leaf",
) -> x509.Certificate:
    signing_key = _gen_key(2048) if spec.leaf_rogue_sign else issuer_key

    # Key Usage
    digital_sig = spec.leaf_ku_digital_sign
    b = (
        x509.CertificateBuilder()
        .subject_name(_subject_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(spec.leaf_valid_from)
        .not_valid_after(spec.leaf_valid_to)
        .add_extension(
            x509.BasicConstraints(
                ca=spec.leaf_is_ca,
                path_length=0 if spec.leaf_is_ca else None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_sig,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=not digital_sig,   # set something if dig-sign off
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    # EKU
    if spec.leaf_eku is None:
        # Default: code signing
        b = b.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    elif len(spec.leaf_eku) == 0:
        pass  # No EKU extension at all
    elif "email" in spec.leaf_eku:
        b = b.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )

    # Unknown critical extension
    if spec.leaf_unknown_critical:
        UNKNOWN_OID = ObjectIdentifier("2.99.999.1.2.3.4.5")
        b = b.add_extension(
            x509.UnrecognizedExtension(UNKNOWN_OID, b"\x05\x00"),
            critical=True,
        )

    return b.sign(signing_key, _hash_for(spec.leaf_sign_hash), default_backend())


def _build_self_signed_leaf(
    key, spec: ChainSpec, cn: str = "CertTest Self-Signed Leaf"
) -> x509.Certificate:
    subject = _subject_name(cn)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(spec.leaf_valid_from)
        .not_valid_after(spec.leaf_valid_to)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    )
    return b.sign(key, hashes.SHA256(), default_backend())


def _flip_cert_signature(cert_der: bytes) -> bytes:
    """
    Flip bytes inside the RSA signature field of a DER-encoded certificate.
    For RSA-2048 the signature value is 256 bytes and sits at the very end
    of the outer SEQUENCE.  We corrupt 10 bytes at a safe interior offset,
    leaving all ASN.1 structural bytes intact so the cert can still be parsed.
    """
    tampered = bytearray(cert_der)
    # The last ~256 bytes are the RSA sig value.  Flip bytes at [-220:-200].
    start = max(0, len(tampered) - 220)
    end   = max(0, len(tampered) - 200)
    for i in range(start, end):
        tampered[i] ^= 0xAA
    return bytes(tampered)


def _export_pfx(
    key,
    cert: x509.Certificate,
    chain: List[x509.Certificate],
    path: Path,
) -> None:
    pfx_data = serialize_key_and_certificates(
        name=b"cert_battery",
        key=key,
        cert=cert,
        cas=chain if chain else None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            PFX_PASSWORD.encode()
        ),
    )
    path.write_bytes(pfx_data)


def _export_cer(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))


# =============================================================================
# §6  CHAIN BUILDER (ANOMALY FACTORY)
# =============================================================================

def _spec_for(anomaly_id: str) -> ChainSpec:
    """Map anomaly ID → ChainSpec with the appropriate parameters."""
    s = ChainSpec()

    if anomaly_id == "VALID_CHAIN":
        pass

    elif anomaly_id == "ROOT_EXPIRED":
        s.root_valid_from = T_PAST
        s.root_valid_to   = T_YESTERDAY

    elif anomaly_id == "ROOT_NOT_YET_VALID":
        s.root_valid_from = T_FUTURE_START
        s.root_valid_to   = T_FUTURE_END

    elif anomaly_id == "ICA_EXPIRED":
        s.ica_valid_from  = T_PAST
        s.ica_valid_to    = T_YESTERDAY

    elif anomaly_id == "LEAF_EXPIRED":
        s.leaf_valid_from = T_PAST
        s.leaf_valid_to   = T_YESTERDAY

    elif anomaly_id == "LEAF_NOT_YET_VALID":
        s.leaf_valid_from = T_FUTURE_START
        s.leaf_valid_to   = T_FUTURE_END

    elif anomaly_id == "LEAF_ROGUE_SIGNATURE":
        s.leaf_rogue_sign = True

    elif anomaly_id == "ICA_ROGUE_SIGNATURE":
        s.ica_rogue_sign  = True

    elif anomaly_id == "LEAF_SELF_SIGNED":
        s.leaf_self_signed = True

    elif anomaly_id == "LEAF_BIT_FLIPPED":
        s.leaf_bit_flip   = True

    elif anomaly_id == "LEAF_WRONG_EKU":
        s.leaf_eku        = ["email"]

    elif anomaly_id == "LEAF_NO_EKU":
        s.leaf_eku        = []

    elif anomaly_id == "LEAF_KEY_USAGE_NO_SIGN":
        s.leaf_ku_digital_sign = False

    elif anomaly_id == "LEAF_IS_CA":
        s.leaf_is_ca      = True

    elif anomaly_id == "ICA_NO_CA_FLAG":
        s.ica_is_ca       = False

    elif anomaly_id == "ICA_PATH_LEN_EXCEEDED":
        s.ica_path_len    = 0
        s.use_sub_ica     = True

    elif anomaly_id == "LEAF_MD5_SIGNATURE":
        s.leaf_sign_hash  = "md5"

    elif anomaly_id == "LEAF_SHA1_SIGNATURE":
        s.leaf_sign_hash  = "sha1"

    elif anomaly_id == "LEAF_WEAK_KEY_1024":
        s.leaf_key_bits   = 1024

    elif anomaly_id == "LEAF_UNKNOWN_CRITICAL":
        s.leaf_unknown_critical = True

    elif anomaly_id == "ROOT_NOT_TRUSTED":
        s.install_root    = False

    else:
        raise ValueError("Unknown anomaly_id: " + anomaly_id)

    return s


def build_chain(anomaly_id: str, out_dir: Path) -> Dict[str, Any]:
    """
    Build a full certificate chain (root → ICA → leaf) according to the
    given anomaly spec.  Writes .pfx and .cer files to *out_dir* and returns
    a dict with all paths and metadata.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = _spec_for(anomaly_id)
    artefacts: Dict[str, Any] = {
        "anomaly_id":    anomaly_id,
        "spec":          _spec_to_dict(spec),
        "install_root":  spec.install_root,
    }

    # ── Root ──────────────────────────────────────────────────────────────────
    root_key  = _gen_key(spec.root_key_bits)
    root_cert = _build_root_cert(root_key, spec)
    root_cer  = out_dir / "root.cer"
    _export_cer(root_cert, root_cer)
    artefacts["root_cer"] = str(root_cer)

    # ── Self-signed leaf (no ICA / root chain) ────────────────────────────────
    if spec.leaf_self_signed:
        leaf_key  = _gen_key(spec.leaf_key_bits)
        leaf_cert = _build_self_signed_leaf(leaf_key, spec)
        leaf_pfx  = out_dir / "leaf.pfx"
        _export_pfx(leaf_key, leaf_cert, [], leaf_pfx)
        artefacts.update({
            "leaf_pfx":   str(leaf_pfx),
            "ica_cer":    None,
            "sub_ica_cer": None,
            "chain_certs": [],
        })
        return artefacts

    # ── ICA (or ICA + sub-ICA for ICA_PATH_LEN_EXCEEDED) ─────────────────────
    ica_key  = _gen_key(spec.ica_key_bits)
    ica_cert = _build_ica_cert(
        ica_key, root_key, root_cert, spec,
        path_len=spec.ica_path_len,
        is_ca=spec.ica_is_ca,
        sign_hash=spec.ica_sign_hash,
        rogue_sign=spec.ica_rogue_sign,
    )
    ica_cer  = out_dir / "ica.cer"
    _export_cer(ica_cert, ica_cer)
    artefacts["ica_cer"] = str(ica_cer)

    signing_ica_key  = ica_key
    signing_ica_cert = ica_cert
    chain_certs      = [ica_cert, root_cert]

    if spec.use_sub_ica:
        # Sub-ICA: signed by ICA which has pathLen=0 → constraint violation
        sub_ica_key  = _gen_key(2048)
        sub_ica_cert = _build_ica_cert(
            sub_ica_key, ica_key, ica_cert,
            spec,
            cn="CertTest Sub-CA (pathLen violation)",
            path_len=0,
            is_ca=True,
            sign_hash="sha256",
            rogue_sign=False,
        )
        sub_ica_cer  = out_dir / "sub_ica.cer"
        _export_cer(sub_ica_cert, sub_ica_cer)
        artefacts["sub_ica_cer"]  = str(sub_ica_cer)
        signing_ica_key           = sub_ica_key
        signing_ica_cert          = sub_ica_cert
        chain_certs               = [sub_ica_cert, ica_cert, root_cert]
    else:
        artefacts["sub_ica_cer"]  = None

    artefacts["chain_certs"] = [str(p) for p in (
        [out_dir / "sub_ica.cer"] if spec.use_sub_ica else []
    ) + [ica_cer, root_cer]]

    # ── Leaf ──────────────────────────────────────────────────────────────────
    leaf_key  = _gen_key(spec.leaf_key_bits)
    leaf_cert = _build_leaf_cert(
        leaf_key, signing_ica_key, signing_ica_cert, spec
    )

    # Optionally corrupt the leaf cert's RSA signature bytes
    if spec.leaf_bit_flip:
        tampered_der  = _flip_cert_signature(
            leaf_cert.public_bytes(serialization.Encoding.DER)
        )
        try:
            leaf_cert = x509.load_der_x509_certificate(tampered_der, default_backend())
        except Exception as exc:
            log.warning("Bit-flip produced unparseable cert (%s); using rogue-sign instead.", exc)
            # Fall back: build a rogue-signed cert (same practical effect)
            spec.leaf_rogue_sign = True
            leaf_cert = _build_leaf_cert(
                leaf_key, _gen_key(2048), signing_ica_cert, spec
            )

    leaf_pfx  = out_dir / "leaf.pfx"
    _export_pfx(leaf_key, leaf_cert, chain_certs, leaf_pfx)
    artefacts["leaf_pfx"] = str(leaf_pfx)

    return artefacts


def _spec_to_dict(spec: ChainSpec) -> Dict[str, Any]:
    """Convert a ChainSpec to a JSON-serialisable dict."""
    raw = asdict(spec)
    out: Dict[str, Any] = {}
    for k, v in raw.items():
        if isinstance(v, datetime.datetime):
            out[k] = v.isoformat()
        elif isinstance(v, list):
            out[k] = v
        else:
            out[k] = v
    return out

# =============================================================================
# §7  C# SOURCE GENERATION AND COMPILATION
# =============================================================================

_EXE_SOURCE = textwrap.dedent("""\
using System;
using System.Reflection;

public class Program
{
    public static void Main(string[] args)
    {
        Assembly asm = Assembly.GetExecutingAssembly();
        Console.WriteLine("=== CertTestBattery Executable ===");
        Console.WriteLine("Name  : " + asm.GetName().Name);
        Console.WriteLine("MVID  : " + asm.ManifestModule.ModuleVersionId.ToString());
        Console.WriteLine("UTC   : " + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        if (args.Length > 0)
        {
            Console.WriteLine("Args  : " + string.Join(", ", args));
        }
        Environment.Exit(0);
    }
}
""")

_DLL_SOURCE = textwrap.dedent("""\
using System;
using System.Reflection;

public class TestLibrary
{
    public static string GetAssemblyInfo()
    {
        Assembly asm = Assembly.GetExecutingAssembly();
        return string.Format(
            "Library={0}  MVID={1}  UTC={2}",
            asm.GetName().Name,
            asm.ManifestModule.ModuleVersionId.ToString(),
            DateTime.UtcNow.ToString("O")
        );
    }

    public string InstanceInfo()
    {
        return "Instance created at " + DateTime.UtcNow.ToString("O");
    }
}
""")


def _find_csc() -> Optional[Path]:
    """Locate csc.exe from .NET Framework or the Roslyn SDK."""
    candidates = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
        r"C:\Program Files\dotnet\sdk",   # will glob below
    ]
    for c in candidates[:2]:
        p = Path(c)
        if p.exists():
            return p
    # Try dotnet-hosted Roslyn
    dotnet_sdk = Path(r"C:\Program Files\dotnet\sdk")
    if dotnet_sdk.exists():
        for roslyn_csc in sorted(dotnet_sdk.glob("*/Roslyn/bincore/csc.dll"),
                                 reverse=True):
            return roslyn_csc  # caller must use 'dotnet <csc.dll>'
    return None


def _compile(src_path: Path, out_path: Path, target: str, csc: Path) -> Tuple[bool, str]:
    """
    Compile *src_path* to *out_path*.
    target: 'exe' or 'library'
    Returns (success, stderr_text).
    """
    if csc.suffix == ".dll":
        cmd = [
            "dotnet", str(csc),
            "/nologo",
            "/target:" + target,
            "/out:" + str(out_path),
            str(src_path),
        ]
    else:
        cmd = [
            str(csc),
            "/nologo",
            "/target:" + target,
            "/out:" + str(out_path),
            str(src_path),
        ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0, result.stderr + result.stdout
    except Exception as exc:
        return False, str(exc)


def compile_assemblies(label: str, csc: Path) -> Dict[str, Any]:
    """
    Compile the EXE and DLL source files for one test case.
    Returns dict with 'exe_path', 'dll_path', 'ok', 'errors'.
    """
    slot = ASSEMBLY_DIR / label
    slot.mkdir(parents=True, exist_ok=True)

    exe_src = SOURCE_DIR / (label + "_exe.cs")
    dll_src = SOURCE_DIR / (label + "_dll.cs")
    exe_out = slot / (label + ".exe")
    dll_out = slot / (label + ".dll")

    exe_src.write_text(_EXE_SOURCE, encoding="utf-8")
    dll_src.write_text(_DLL_SOURCE, encoding="utf-8")

    exe_ok, exe_err = _compile(exe_src, exe_out, "exe",     csc)
    dll_ok, dll_err = _compile(dll_src, dll_out, "library", csc)

    return {
        "exe_path": str(exe_out) if exe_ok else "",
        "dll_path": str(dll_out) if dll_ok else "",
        "exe_ok":   exe_ok,
        "dll_ok":   dll_ok,
        "exe_err":  exe_err if not exe_ok else "",
        "dll_err":  dll_err if not dll_ok else "",
    }

# =============================================================================
# §8  POWERSHELL INTEGRATION
# =============================================================================

def _ps(script: str, label: str = "") -> Dict[str, Any]:
    """
    Execute *script* in a PowerShell sub-process.
    Writes the raw transcript to logs/<label>.ps1.log if label is given.
    Returns dict with 'stdout', 'stderr', 'rc', 'ok'.
    """
    ps_exe   = "powershell.exe"
    full_cmd = [
        ps_exe,
        "-NonInteractive", "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=120
        )
        out = {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "rc":     result.returncode,
            "ok":     result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        out = {"stdout": "", "stderr": "TIMEOUT", "rc": -1, "ok": False}
    except Exception as exc:
        out = {"stdout": "", "stderr": str(exc), "rc": -2, "ok": False}

    if label:
        try:
            log_path = LOG_DIR / (label + ".ps1.log")
            log_path.write_text(
                "# SCRIPT\n" + script + "\n\n# STDOUT\n" + out["stdout"]
                + "\n\n# STDERR\n" + out["stderr"],
                encoding="utf-8",
            )
        except Exception:
            pass
    return out


def _import_cer_to_store(cer_path: str, store: str, label: str) -> str:
    """Import a DER certificate into *store*.  Returns thumbprint or ''."""
    script = (
        "$cert = Import-Certificate"
        " -FilePath '" + cer_path + "'"
        " -CertStoreLocation '" + store + "'"
        " -ErrorAction Stop; $cert.Thumbprint"
    )
    res = _ps(script, label + "_import_cer")
    if res["ok"] and res["stdout"]:
        return res["stdout"].strip()
    log.warning("Import-Certificate failed for %s: %s", cer_path, res["stderr"])
    return ""


def _import_pfx_to_store(pfx_path: str, store: str, label: str) -> str:
    """Import a PFX (with private key) into *store*.  Returns thumbprint or ''."""
    script = (
        "$pw = ConvertTo-SecureString '" + PFX_PASSWORD + "' -AsPlainText -Force; "
        "$cert = Import-PfxCertificate"
        " -FilePath '" + pfx_path + "'"
        " -CertStoreLocation '" + store + "'"
        " -Password $pw -ErrorAction Stop; $cert.Thumbprint"
    )
    res = _ps(script, label + "_import_pfx")
    if res["ok"] and res["stdout"]:
        return res["stdout"].strip()
    log.warning("Import-PfxCertificate failed: %s", res["stderr"])
    return ""


def _remove_cert(thumbprint: str, store: str) -> None:
    if not thumbprint:
        return
    script = (
        "Remove-Item -Path '" + store + "\\" + thumbprint + "' -ErrorAction SilentlyContinue"
    )
    _ps(script)


def _sign_binary(binary_path: str, thumbprint: str, label: str) -> Dict[str, Any]:
    """Sign a PE file using Set-AuthenticodeSignature.  Returns status dict."""
    script = (
        "$cert = Get-Item -Path '" + STORE_MY + "\\" + thumbprint + "'; "
        "$sig  = Set-AuthenticodeSignature"
        " -FilePath '" + binary_path + "'"
        " -Certificate $cert"
        " -ErrorAction SilentlyContinue; "
        "ConvertTo-Json -Compress @{ "
        "  Status=$sig.Status.ToString(); "
        "  StatusMessage=$sig.StatusMessage; "
        "  HashAlgorithm=$sig.SignatureType.ToString() "
        "}"
    )
    res = _ps(script, label + "_sign")
    try:
        data = json.loads(res["stdout"])
    except Exception:
        data = {"Status": "ParseError", "StatusMessage": res["stdout"] + res["stderr"]}
    data["rc"]  = res["rc"]
    data["raw"] = res["stdout"]
    return data


def _validate_binary(binary_path: str, label: str) -> Dict[str, Any]:
    """Run Get-AuthenticodeSignature and return a structured result dict."""
    script = (
        "$sig = Get-AuthenticodeSignature -FilePath '" + binary_path + "'; "
        "ConvertTo-Json -Compress @{ "
        "  Status=$sig.Status.ToString(); "
        "  StatusMessage=$sig.StatusMessage; "
        "  IsValid=($sig.Status -eq 'Valid'); "
        "  SignerCN=$sig.SignerCertificate.Subject; "
        "  Thumbprint=$sig.SignerCertificate.Thumbprint "
        "}"
    )
    res = _ps(script, label + "_validate")
    try:
        data = json.loads(res["stdout"])
    except Exception:
        data = {"Status": "ParseError", "StatusMessage": res["stdout"] + res["stderr"]}
    data["rc"] = res["rc"]
    return data


def _load_assembly(binary_path: str, label: str) -> Dict[str, Any]:
    """
    Try to load a .NET assembly into a PowerShell child process and invoke
    a known method.  Returns result dict.
    """
    is_dll = binary_path.lower().endswith(".dll")
    if is_dll:
        invoke = (
            "$a = [System.Reflection.Assembly]::LoadFrom('" + binary_path + "'); "
            "$t = $a.GetType('TestLibrary'); "
            "$r = $t.GetMethod('GetAssemblyInfo').Invoke($null, @()); $r"
        )
    else:
        invoke = (
            "$a = [System.Reflection.Assembly]::LoadFrom('" + binary_path + "'); "
            "$t = $a.GetType('Program'); $t.FullName"
        )
    script = (
        "try { " + invoke + " } "
        "catch { Write-Output ('LOAD_ERROR: ' + $_.Exception.Message) }"
    )
    res = _ps(script, label + "_load")
    loaded    = "LOAD_ERROR:" not in res["stdout"] and res["ok"]
    error_msg = ""
    if "LOAD_ERROR:" in res["stdout"]:
        error_msg = res["stdout"]
    elif res["stderr"]:
        error_msg = res["stderr"]
    return {"loaded": loaded, "output": res["stdout"], "error": error_msg, "rc": res["rc"]}


def _run_exe(binary_path: str, label: str) -> Dict[str, Any]:
    """Execute the .exe and capture stdout / exit code."""
    try:
        result = subprocess.run(
            [binary_path],
            capture_output=True, text=True, timeout=10
        )
        return {
            "rc":     result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "ran":    True,
        }
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "TIMEOUT", "ran": False}
    except Exception as exc:
        return {"rc": -2, "stdout": "", "stderr": str(exc), "ran": False}

# =============================================================================
# §9  FAULT TRACKER
# =============================================================================

def _is_fault(rec: TestRecord) -> Tuple[bool, str]:
    """
    Determine whether the test produced an unexpected result.

    A fault is any of:
      • valid_result does not match expected_valid
      • An unhandled exception during signing or validation
      • The PowerShell host process crashes (rc < 0)
    """
    for name, d in [("validate_exe", rec.validate_exe), ("validate_dll", rec.validate_dll)]:
        is_valid = d.get("IsValid", False)
        if is_valid != rec.expected_valid:
            return True, (
                "Authenticode IsValid=" + str(is_valid)
                + " but expected " + str(rec.expected_valid)
                + " for " + name
            )
        if d.get("rc", 0) < 0:
            return True, "PowerShell crashed during " + name + " (rc=" + str(d.get("rc")) + ")"

    for name, d in [("sign_exe", rec.sign_exe), ("sign_dll", rec.sign_dll)]:
        if d.get("rc", 0) < -1:
            return True, "Unexpected crash during " + name

    return False, ""


def _preserve_fault(rec: TestRecord, artefacts: Dict[str, Any]) -> Path:
    """Copy binaries and cert files to a UUID-stamped fault directory."""
    fault_slot = FAULT_DIR / rec.test_id
    fault_slot.mkdir(parents=True, exist_ok=True)

    # Copy binaries
    for key in ("exe_path", "dll_path"):
        src = artefacts.get(key, "")
        if src and Path(src).exists():
            shutil.copy2(src, fault_slot)

    # Copy cert artefacts
    cert_src = Path(artefacts.get("cert_dir", ""))
    if cert_src.exists():
        shutil.copytree(str(cert_src), str(fault_slot / "certs"), dirs_exist_ok=True)

    # Write metadata
    meta = {
        "test_id":       rec.test_id,
        "anomaly_id":    rec.anomaly_id,
        "description":   rec.description,
        "expected_valid": rec.expected_valid,
        "fault_reason":  rec.fault_reason,
        "spec":          artefacts.get("spec", {}),
        "sign_exe":      rec.sign_exe,
        "sign_dll":      rec.sign_dll,
        "validate_exe":  rec.validate_exe,
        "validate_dll":  rec.validate_dll,
        "load_exe":      rec.load_exe,
        "load_dll":      rec.load_dll,
        "run_exe":       rec.run_exe,
        "timestamp":     rec.timestamp,
    }
    (fault_slot / "fault_info.json").write_text(
        json.dumps(meta, indent=2, default=str), encoding="utf-8"
    )
    log.warning("FAULT preserved → %s", fault_slot)
    return fault_slot

# =============================================================================
# §10  MS CERT CLONING (OPTIONAL)
# =============================================================================

def _clone_ms_certs(root_path: Path, pca_path: Path, leaf_path: Path) -> Optional[Dict]:
    """
    Read real MS certs, extract their subject names and validity ranges,
    and generate synthetic chains with matching structure but fresh keys.
    Returns artefact dict or None on failure.
    """
    try:
        root_cert_orig = x509.load_der_x509_certificate(
            root_path.read_bytes(), default_backend()
        )
        pca_cert_orig  = x509.load_der_x509_certificate(
            pca_path.read_bytes(), default_backend()
        )
        leaf_cert_orig = x509.load_der_x509_certificate(
            leaf_path.read_bytes(), default_backend()
        )
    except Exception as exc:
        log.error("Failed to load MS certs: %s", exc)
        return None

    log.info("Cloning MS certs: root=%s  pca=%s  leaf=%s",
             root_cert_orig.subject.rfc4514_string(),
             pca_cert_orig.subject.rfc4514_string(),
             leaf_cert_orig.subject.rfc4514_string())

    # Build a synthetic chain using the original subject names
    spec       = ChainSpec()
    out_dir    = CERT_DIR / "CLONED_MS"
    out_dir.mkdir(parents=True, exist_ok=True)

    root_key   = _gen_key(2048)
    root_cert  = (
        x509.CertificateBuilder()
        .subject_name(root_cert_orig.subject)
        .issuer_name(root_cert_orig.subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(T_STANDARD_END)
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )
    root_cer   = out_dir / "root.cer"
    _export_cer(root_cert, root_cer)

    ica_key    = _gen_key(2048)
    ica_cert   = _build_ica_cert(
        ica_key, root_key, root_cert, spec,
        cn=pca_cert_orig.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if pca_cert_orig.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "Cloned PCA",
        path_len=0, is_ca=True, sign_hash="sha256",
    )
    ica_cer    = out_dir / "ica.cer"
    _export_cer(ica_cert, ica_cer)

    leaf_key   = _gen_key(2048)
    spec_leaf  = ChainSpec()
    leaf_cert  = _build_leaf_cert(
        leaf_key, ica_key, ica_cert, spec_leaf,
        cn=leaf_cert_orig.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if leaf_cert_orig.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "Cloned Leaf",
    )
    leaf_pfx   = out_dir / "leaf.pfx"
    _export_pfx(leaf_key, leaf_cert, [ica_cert, root_cert], leaf_pfx)

    return {
        "anomaly_id":   "CLONED_MS",
        "cert_dir":     str(out_dir),
        "root_cer":     str(root_cer),
        "ica_cer":      str(ica_cer),
        "sub_ica_cer":  None,
        "leaf_pfx":     str(leaf_pfx),
        "install_root": True,
        "chain_certs":  [str(ica_cer), str(root_cer)],
        "spec":         _spec_to_dict(ChainSpec()),
    }

# =============================================================================
# §11  TEST RUNNER
# =============================================================================

def _run_one(
    anomaly_id: str,
    description: str,
    expected_valid: bool,
    category: str,
    csc: Path,
    results: List[TestRecord],
    artefacts_override: Optional[Dict] = None,
) -> None:
    test_id = str(uuid.uuid4())
    label   = anomaly_id.lower().replace("_", "-")
    log.info("━━  Starting [%s] %s  (%s)", test_id[:8], anomaly_id, description)

    rec = TestRecord(
        test_id=test_id,
        anomaly_id=anomaly_id,
        description=description,
        expected_valid=expected_valid,
        category=category,
    )
    results.append(rec)

    cert_out = CERT_DIR / label
    artefacts: Dict[str, Any] = {}

    try:
        # ── 1. Build cert chain ────────────────────────────────────────────
        if artefacts_override:
            artefacts = artefacts_override
        else:
            artefacts = build_chain(anomaly_id, cert_out)
        artefacts["cert_dir"] = str(cert_out)
        rec.cert_dir          = str(cert_out)
        rec.spec_dict         = artefacts.get("spec", {})

        # ── 2. Compile assemblies ──────────────────────────────────────────
        compiled = compile_assemblies(label, csc)
        if not compiled["exe_ok"] or not compiled["dll_ok"]:
            log.error("[%s] Compilation failed: exe=%s  dll=%s",
                      anomaly_id, compiled["exe_err"], compiled["dll_err"])
            rec.error = "Compilation failed — exe_ok=" + str(compiled["exe_ok"]) + \
                        " dll_ok=" + str(compiled["dll_ok"])
            return

        exe_path = compiled["exe_path"]
        dll_path = compiled["dll_path"]
        artefacts["exe_path"] = exe_path
        artefacts["dll_path"] = dll_path
        rec.exe_path = exe_path
        rec.dll_path = dll_path

        # ── 3. Install certs to Windows stores ────────────────────────────
        root_thumbprint = ""
        ica_thumbprint  = ""
        sub_ica_thumb   = ""
        leaf_thumbprint = ""

        root_cer = artefacts.get("root_cer", "")
        ica_cer  = artefacts.get("ica_cer",  "")
        sub_ica  = artefacts.get("sub_ica_cer", "")
        leaf_pfx = artefacts.get("leaf_pfx",  "")

        if root_cer and artefacts.get("install_root", True):
            root_thumbprint = _import_cer_to_store(root_cer, STORE_ROOT, label + "-root")

        if ica_cer:
            ica_thumbprint  = _import_cer_to_store(ica_cer, STORE_CA, label + "-ica")

        if sub_ica:
            sub_ica_thumb   = _import_cer_to_store(sub_ica, STORE_CA, label + "-sub-ica")

        if leaf_pfx:
            leaf_thumbprint = _import_pfx_to_store(leaf_pfx, STORE_MY, label + "-leaf")

        if not leaf_thumbprint:
            rec.error = "Could not import leaf PFX to Personal store"
            log.error("[%s] %s", anomaly_id, rec.error)
            return

        # ── 4. Sign EXE and DLL ────────────────────────────────────────────
        rec.sign_exe = _sign_binary(exe_path, leaf_thumbprint, label + "-exe")
        rec.sign_dll = _sign_binary(dll_path, leaf_thumbprint, label + "-dll")
        log.info("[%s] sign_exe.Status=%s  sign_dll.Status=%s",
                 anomaly_id, rec.sign_exe.get("Status"), rec.sign_dll.get("Status"))

        # ── 5. Validate signatures ─────────────────────────────────────────
        rec.validate_exe = _validate_binary(exe_path, label + "-exe")
        rec.validate_dll = _validate_binary(dll_path, label + "-dll")
        log.info("[%s] validate_exe.IsValid=%s  validate_dll.IsValid=%s",
                 anomaly_id,
                 rec.validate_exe.get("IsValid"),
                 rec.validate_dll.get("IsValid"))

        # ── 6. Attempt to load assemblies in PowerShell ────────────────────
        rec.load_exe = _load_assembly(exe_path, label + "-load-exe")
        rec.load_dll = _load_assembly(dll_path, label + "-load-dll")
        log.info("[%s] load_exe.loaded=%s  load_dll.loaded=%s",
                 anomaly_id, rec.load_exe.get("loaded"), rec.load_dll.get("loaded"))

        # ── 7. Execute EXE directly ────────────────────────────────────────
        rec.run_exe = _run_exe(exe_path, label + "-run-exe")
        log.info("[%s] run_exe.rc=%s", anomaly_id, rec.run_exe.get("rc"))

    except Exception:
        rec.error = traceback.format_exc()
        log.error("[%s] Unhandled exception:\n%s", anomaly_id, rec.error)

    finally:
        # ── 8. Fault detection ─────────────────────────────────────────────
        is_fault, reason = _is_fault(rec)
        rec.is_fault    = is_fault
        rec.fault_reason = reason
        if is_fault:
            fd = _preserve_fault(rec, artefacts)
            rec.fault_dir = str(fd)

        # ── 9. Cleanup: remove installed certs from all stores ─────────────
        for tp, store in [
            (leaf_thumbprint, STORE_MY),
            (ica_thumbprint,  STORE_CA),
            (sub_ica_thumb,   STORE_CA),
            (root_thumbprint, STORE_ROOT),
        ]:
            if tp:
                _remove_cert(tp, store)

        status_line = (
            "  ✓ PASS" if (not is_fault and not rec.error)
            else "  ✗ FAULT" if is_fault
            else "  ! ERROR"
        )
        log.info("[%s] %s  —  %s", anomaly_id, status_line, reason or rec.error or "ok")


# =============================================================================
# §12  REPORT GENERATION
# =============================================================================

def _generate_report(records: List[TestRecord]) -> None:
    total   = len(records)
    faults  = sum(1 for r in records if r.is_fault)
    errors  = sum(1 for r in records if r.error and not r.is_fault)
    clean   = total - faults - errors

    summary = {
        "generated_utc": _NOW.isoformat(),
        "total":  total,
        "clean":  clean,
        "faults": faults,
        "errors": errors,
        "results": [asdict(r) for r in records],
    }
    REPORT_PATH.write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("REPORT  total=%d  clean=%d  faults=%d  errors=%d", total, clean, faults, errors)
    log.info("Report saved → %s", REPORT_PATH)
    if faults:
        log.warning("Fault archive → %s", FAULT_DIR)

# =============================================================================
# §13  MAIN
# =============================================================================

def main() -> int:
    _setup_logging()
    _init_dirs()

    log.info("════════════════════════════════════════════════════════════════")
    log.info("  Certificate Validation Test Battery  —  %s", _NOW.isoformat())
    log.info("  Base directory: %s", BASE_DIR)
    log.info("════════════════════════════════════════════════════════════════")

    # ── Locate C# compiler ────────────────────────────────────────────────────
    csc = _find_csc()
    if csc is None:
        log.error(
            "csc.exe / Roslyn csc.dll not found.  "
            "Install .NET Framework 4.x or the .NET SDK and re-run."
        )
        return 1
    log.info("Using compiler: %s", csc)

    # ── Platform check ────────────────────────────────────────────────────────
    if sys.platform != "win32":
        log.warning(
            "This script is designed for Windows.  "
            "Cert-store and Authenticode steps will be skipped on other platforms."
        )

    results: List[TestRecord] = []

    # ── Optional: clone real MS certs if present ──────────────────────────────
    if MS_ROOT_CER.exists() and MS_PCA_CER.exists() and MS_LEAF_CER.exists():
        log.info("MS kernel certs found — running clone test.")
        ms_artefacts = _clone_ms_certs(MS_ROOT_CER, MS_PCA_CER, MS_LEAF_CER)
        if ms_artefacts:
            ms_artefacts["cert_dir"] = str(CERT_DIR / "cloned-ms")
            _run_one(
                anomaly_id="CLONED_MS",
                description="Synthetic clone of real MS kernel32 cert chain",
                expected_valid=True,
                category="clone",
                csc=csc,
                results=results,
                artefacts_override=ms_artefacts,
            )
    else:
        log.info("MS kernel certs not present at %s — skipping clone test.", MS_CERT_DIR)

    # ── Run all anomaly test cases ────────────────────────────────────────────
    for anomaly_id, meta in ANOMALIES.items():
        try:
            _run_one(
                anomaly_id=anomaly_id,
                description=meta["desc"],
                expected_valid=meta["expected_valid"],
                category=meta["category"],
                csc=csc,
                results=results,
            )
        except Exception:
            log.error("Top-level exception for %s:\n%s", anomaly_id, traceback.format_exc())

    # ── Produce final report ──────────────────────────────────────────────────
    _generate_report(results)

    return 1 if any(r.is_fault for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
