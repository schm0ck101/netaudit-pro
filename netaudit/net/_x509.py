"""Décodage DER minimal d'un certificat X.509 : sujet, émetteur, validité,
algorithme de signature, taille de clé RSA. Sans dépendance externe."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def _tlv(b: bytes, off: int) -> tuple[int, int, int]:
    """(tag, début du contenu, fin du contenu)."""
    tag = b[off]
    off += 1
    ln = b[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    return tag, off, off + ln


def _children(b: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, off = [], start
    while off < end:
        t, s, e = _tlv(b, off)
        out.append((t, s, e))
        off = e
    return out


OID_NAMES = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST"}
SIG_ALGS = {"1.2.840.113549.1.1.4": "md5RSA", "1.2.840.113549.1.1.5": "sha1RSA", "1.2.840.113549.1.1.11": "sha256RSA",
            "1.2.840.113549.1.1.12": "sha384RSA", "1.2.840.113549.1.1.13": "sha512RSA", "1.2.840.10045.4.3.2": "sha256ECDSA",
            "1.2.840.10045.4.3.3": "sha384ECDSA", "1.2.840.10045.4.1": "sha1ECDSA", "1.3.101.112": "Ed25519",
            "1.2.840.113549.1.1.10": "RSASSA-PSS"}


def _oid(b: bytes) -> str:
    vals, v = [], 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            vals.append(v)
            v = 0
    return ".".join(str(x) for x in [b[0] // 40, b[0] % 40] + vals)


def _name(b: bytes, s: int, e: int) -> dict:
    out = {}
    for _t, rs, re_ in _children(b, s, e):              # SET
        for _t2, as_, ae in _children(b, rs, re_):      # SEQUENCE (oid, valeur)
            kids = _children(b, as_, ae)
            if len(kids) >= 2:
                oid = _oid(b[kids[0][1]:kids[0][2]])
                val = b[kids[1][1]:kids[1][2]]
                try:
                    txt = val.decode("utf-16-be") if kids[1][0] == 0x1E else val.decode("utf-8", "replace")
                except UnicodeDecodeError:
                    txt = val.decode("latin-1")
                out[OID_NAMES.get(oid, oid)] = txt
    return out


def _time(tag: int, raw: bytes) -> datetime | None:
    s = raw.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:     # UTCTime AAMMJJhhmmss
            d = datetime.strptime(s[:12], "%y%m%d%H%M%S")
        else:               # GeneralizedTime
            d = datetime.strptime(s[:14], "%Y%m%d%H%M%S")
        return d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_cert(der: bytes) -> dict:
    _t, cs, ce = _tlv(der, 0)
    top = _children(der, cs, ce)
    tbs = _children(der, top[0][1], top[0][2])
    i = 1 if tbs[0][0] == 0xA0 else 0          # [0] version facultative
    sig_seq = _children(der, tbs[i + 1][1], tbs[i + 1][2])
    sig = SIG_ALGS.get(_oid(der[sig_seq[0][1]:sig_seq[0][2]]), _oid(der[sig_seq[0][1]:sig_seq[0][2]]))
    issuer = _name(der, tbs[i + 2][1], tbs[i + 2][2])
    val = _children(der, tbs[i + 3][1], tbs[i + 3][2])
    nb = _time(val[0][0], der[val[0][1]:val[0][2]])
    na = _time(val[1][0], der[val[1][1]:val[1][2]])
    subject = _name(der, tbs[i + 4][1], tbs[i + 4][2])
    key_bits = None
    key_type = ""
    try:
        spki = _children(der, tbs[i + 5][1], tbs[i + 5][2])
        alg = _children(der, spki[0][1], spki[0][2])
        koid = _oid(der[alg[0][1]:alg[0][2]])
        if koid == "1.2.840.113549.1.1.1":
            key_type = "RSA"
            bits = der[spki[1][1] + 1:spki[1][2]]           # BIT STRING (premier octet = bits inutilisés)
            rsa = _children(bits, *_tlv(bits, 0)[1:])
            n = bits[rsa[0][1]:rsa[0][2]].lstrip(b"\x00")
            key_bits = len(n) * 8
        elif koid == "1.2.840.10045.2.1":
            key_type = "ECDSA"
        else:
            key_type = koid
    except (IndexError, ValueError):
        pass
    return {"subject": subject.get("CN") or ", ".join(f"{k}={v}" for k, v in subject.items()),
            "issuer": issuer.get("CN") or issuer.get("O") or ", ".join(f"{k}={v}" for k, v in issuer.items()),
            "self_signed": subject == issuer, "not_before": nb.isoformat() if nb else None,
            "not_after": na.isoformat() if na else None, "sig_alg": sig, "key_type": key_type, "key_bits": key_bits,
            "sha256": hashlib.sha256(der).hexdigest()}
