"""Client SNMP en lecture seule : v1, v2c et v3 (USM : MD5 / SHA-1 / SHA-256,
chiffrement AES-128). Codage BER maison, sans dépendance.

Seules des requêtes GET / GETNEXT / GETBULK sont émises : l'outil ne modifie
jamais la configuration d'un équipement.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass

from . import aes

# ------------------------------------------------------------------ BER
INT, OCTETS, NULL, OID, SEQ = 0x02, 0x04, 0x05, 0x06, 0x30
IPADDR, COUNTER32, GAUGE32, TICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB = 0x80, 0x81, 0x82
GET, GETNEXT, RESPONSE, GETBULK, REPORT = 0xA0, 0xA1, 0xA2, 0xA5, 0xA8
ERRORS = {0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
          16: "authorizationError"}


class SnmpError(Exception):
    pass


class Timeout(SnmpError):
    pass


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def enc_int(v: int, tag: int = INT) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(tag, v.to_bytes(n, "big", signed=True))


def enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


def dec(b: bytes, off: int = 0) -> tuple[int, bytes, int]:
    """(tag, contenu, position suivante)."""
    if off + 2 > len(b):
        raise SnmpError("message tronqué")
    tag = b[off]
    ln = b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    if off + ln > len(b):
        raise SnmpError("message tronqué")
    return tag, b[off:off + ln], off + ln


def dec_oid(c: bytes) -> str:
    if not c:
        return ""
    vals, v = [c[0] // 40, c[0] % 40], 0
    for x in c[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            vals.append(v)
            v = 0
    return ".".join(str(x) for x in vals)


def dec_value(tag: int, c: bytes):
    if tag == INT:
        return int.from_bytes(c, "big", signed=True) if c else 0
    if tag in (COUNTER32, GAUGE32, TICKS, COUNTER64):
        return int.from_bytes(c, "big") if c else 0
    if tag == OCTETS or tag == OPAQUE:
        return bytes(c)
    if tag == OID:
        return "." + dec_oid(c) if False else dec_oid(c)
    if tag == IPADDR:
        return socket.inet_ntoa(c) if len(c) == 4 else c.hex()
    if tag == NULL:
        return None
    if tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB):
        return _Missing(tag)
    return bytes(c)


class _Missing:
    def __init__(self, tag):
        self.tag = tag

    def __repr__(self):
        return {NO_SUCH_OBJECT: "noSuchObject", NO_SUCH_INSTANCE: "noSuchInstance", END_OF_MIB: "endOfMibView"}[self.tag]


def missing(v) -> bool:
    return isinstance(v, _Missing)


def _pdu(tag: int, reqid: int, oids: list[str], a: int = 0, b: int = 0) -> bytes:
    vbs = b"".join(tlv(SEQ, enc_oid(o) + tlv(NULL, b"")) for o in oids)
    return tlv(tag, enc_int(reqid) + enc_int(a) + enc_int(b) + tlv(SEQ, vbs))


def _parse_pdu(raw: bytes) -> tuple[int, int, int, int, list]:
    tag, c, _ = dec(raw)
    _t, rid, off = dec(c, 0)
    _t, es, off = dec(c, off)
    _t, ei, off = dec(c, off)
    _t, vbs, off = dec(c, off)
    out, o = [], 0
    while o < len(vbs):
        _t, vb, o = dec(vbs, o)
        _t, oidc, p = dec(vb, 0)
        vt, vc, _p = dec(vb, p)
        out.append((dec_oid(oidc), dec_value(vt, vc)))
    return tag, int.from_bytes(rid, "big", signed=True), int.from_bytes(es, "big"), int.from_bytes(ei, "big"), out


# ------------------------------------------------------------------ USM (v3)
AUTH = {"MD5": (hashlib.md5, 12), "SHA": (hashlib.sha1, 12), "SHA1": (hashlib.sha1, 12), "SHA256": (hashlib.sha256, 24)}


def password_to_key(password: str, engine_id: bytes, algo: str) -> bytes:
    """RFC 3414 A.2 : 1 Mo de mot de passe répété, puis localisation par l'engineID."""
    h = AUTH[algo][0]
    pw = password.encode("utf-8")
    if not pw:
        raise SnmpError("mot de passe SNMPv3 vide")
    data = (pw * (1048576 // len(pw) + 1))[:1048576]
    ku = h(data).digest()
    return h(ku + engine_id + ku).digest()


@dataclass
class Credential:
    """Identifiants SNMP (jamais enregistrés dans le rapport ni dans l'historique)."""
    version: str = "2c"              # "1", "2c", "3"
    community: str = "public"
    user: str = ""
    auth_proto: str = "SHA"          # MD5, SHA, SHA256 ou "" (noAuth)
    auth_pass: str = ""
    priv_proto: str = "AES"          # AES ou "" (noPriv)
    priv_pass: str = ""

    def label(self) -> str:
        if self.version in ("1", "2c"):
            shown = self.community[:1] + "•" * max(0, len(self.community) - 1)
            return f"v{self.version} « {shown} »"
        lvl = "authPriv" if self.auth_proto and self.priv_proto else "authNoPriv" if self.auth_proto else "noAuthNoPriv"
        return f"v3 {self.user} ({lvl})"


class Session:
    def __init__(self, ip: str, cred: Credential, timeout: float = 1.5, retries: int = 1, port: int = 161):
        self.ip, self.cred, self.timeout, self.retries, self.port = ip, cred, timeout, retries, port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self._rid = struct.unpack("!I", os.urandom(4))[0] & 0x3FFFFFFF
        self.engine_id = b""
        self.boots = self.etime = 0
        self._etime_at = 0.0
        self._kauth = self._kpriv = b""
        self.requests = 0

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _next(self) -> int:
        self._rid = (self._rid + 1) & 0x7FFFFFFF
        return self._rid

    # -------------------------------------------------------------- transport
    def _xchg(self, msg: bytes, match) -> bytes:
        for _ in range(self.retries + 1):
            self.requests += 1
            try:
                self.sock.sendto(msg, (self.ip, self.port))
            except OSError as exc:
                raise SnmpError(str(exc))
            end = time.monotonic() + self.timeout
            while time.monotonic() < end:
                try:
                    data, src = self.sock.recvfrom(65535)
                except socket.timeout:
                    break
                except OSError:          # ICMP port injoignable (WSAECONNRESET)
                    raise Timeout("port SNMP fermé")
                if src[0] == self.ip and match(data):
                    return data
        raise Timeout("pas de réponse")

    # ------------------------------------------------------------- v1 / v2c
    def _request_community(self, tag, oids, a=0, b=0) -> list:
        rid = self._next()
        ver = 0 if self.cred.version == "1" else 1
        msg = tlv(SEQ, enc_int(ver) + tlv(OCTETS, self.cred.community.encode()) + _pdu(tag, rid, oids, a, b))

        def match(d):
            try:
                _t, c, _ = dec(d)
                _t, _v, o = dec(c, 0)
                _t, _cm, o = dec(c, o)
                return _parse_pdu(c[o:])[1] == rid
            except SnmpError:
                return False
        data = self._xchg(msg, match)
        _t, c, _ = dec(data)
        _t, _v, o = dec(c, 0)
        _t, _cm, o = dec(c, o)
        _tag, _rid, es, ei, vbs = _parse_pdu(c[o:])
        if es:
            if es == 2 and self.cred.version == "1":          # v1 : fin de MIB / OID absent
                return [(oids[ei - 1] if ei else "", _Missing(NO_SUCH_OBJECT))]
            raise SnmpError(ERRORS.get(es, f"erreur {es}"))
        return vbs

    # ------------------------------------------------------------------- v3
    def _discover(self):
        rid = self._next()
        msgid = self._next()
        usm = tlv(SEQ, tlv(OCTETS, b"") + enc_int(0) + enc_int(0) + tlv(OCTETS, b"") + tlv(OCTETS, b"") + tlv(OCTETS, b""))
        scoped = tlv(SEQ, tlv(OCTETS, b"") + tlv(OCTETS, b"") + _pdu(GET, rid, []))
        msg = tlv(SEQ, enc_int(3) + tlv(SEQ, enc_int(msgid) + enc_int(65507) + tlv(OCTETS, b"\x04") + enc_int(3))
                  + tlv(OCTETS, usm) + scoped)
        data = self._xchg(msg, lambda d: self._msgid(d) == msgid)
        eid, boots, etime, _u, _a, _p = self._usm(data)
        if not eid:
            raise SnmpError("engineID non annoncé")
        self.engine_id, self.boots, self.etime, self._etime_at = eid, boots, etime, time.monotonic()
        c = self.cred
        if c.auth_proto:
            self._kauth = password_to_key(c.auth_pass, eid, c.auth_proto.upper())
            if c.priv_proto:
                self._kpriv = password_to_key(c.priv_pass, eid, c.auth_proto.upper())[:16]

    @staticmethod
    def _msgid(d: bytes) -> int | None:
        try:
            _t, c, _ = dec(d)
            _t, _v, o = dec(c, 0)
            _t, g, o = dec(c, o)
            _t, mid, _ = dec(g, 0)
            return int.from_bytes(mid, "big")
        except SnmpError:
            return None

    @staticmethod
    def _usm(d: bytes):
        _t, c, _ = dec(d)
        _t, _v, o = dec(c, 0)
        _t, _g, o = dec(c, o)
        _t, sp, o = dec(c, o)
        _t, seq, _ = dec(sp)
        vals, p = [], 0
        while p < len(seq):
            t, v, p = dec(seq, p)
            vals.append(int.from_bytes(v, "big") if t == INT else v)
        return tuple(vals[:6]) if len(vals) >= 6 else (b"", 0, 0, b"", b"", b"")

    def _request_v3(self, tag, oids, a=0, b=0, _again=True) -> list:
        if not self.engine_id:
            self._discover()
        c = self.cred
        rid, msgid = self._next(), self._next()
        auth, priv = bool(c.auth_proto), bool(c.auth_proto and c.priv_proto)
        flags = (1 if auth else 0) | (2 if priv else 0) | 4
        etime = self.etime + int(time.monotonic() - self._etime_at)
        scoped = tlv(SEQ, tlv(OCTETS, self.engine_id) + tlv(OCTETS, b"") + _pdu(tag, rid, oids, a, b))
        salt = b""
        if priv:
            salt = os.urandom(8)
            iv = struct.pack(">II", self.boots, etime) + salt
            scoped = tlv(OCTETS, aes.cfb_encrypt(self._kpriv, iv, scoped))
        alen = AUTH[c.auth_proto.upper()][1] if auth else 0

        def build(auth_param: bytes) -> bytes:
            usm = tlv(SEQ, tlv(OCTETS, self.engine_id) + enc_int(self.boots) + enc_int(etime) + tlv(OCTETS, c.user.encode())
                      + tlv(OCTETS, auth_param) + tlv(OCTETS, salt))
            return tlv(SEQ, enc_int(3) + tlv(SEQ, enc_int(msgid) + enc_int(65507) + tlv(OCTETS, bytes([flags])) + enc_int(3))
                       + tlv(OCTETS, usm) + scoped)
        msg = build(b"\x00" * alen)
        if auth:
            mac = hmac.new(self._kauth, msg, AUTH[c.auth_proto.upper()][0]).digest()[:alen]
            msg = build(mac)
        data = self._xchg(msg, lambda d: self._msgid(d) == msgid)
        # réponse : déchiffrement éventuel puis PDU
        _t, cc, _ = dec(data)
        _t, _v, o = dec(cc, 0)
        _t, g, o = dec(cc, o)
        _t, _sp, o = dec(cc, o)
        eid, boots, retime, _u, _ap, psalt = self._usm(data)
        _t, rflags, _ = dec(g, dec(g, dec(g, 0)[2])[2])
        body = cc[o:]
        if rflags and rflags[0] & 2:
            _t, enc, _ = dec(body)
            iv = struct.pack(">II", boots, retime) + psalt
            body = aes.cfb_decrypt(self._kpriv, iv, enc)
        _t, sc, _ = dec(body)
        _t, _ceid, p = dec(sc, 0)
        _t, _cname, p = dec(sc, p)
        ptag, _rid, es, ei, vbs = _parse_pdu(sc[p:])
        if ptag == REPORT:
            oid = vbs[0][0] if vbs else ""
            if oid.startswith("1.3.6.1.6.3.15.1.1.2") and _again:        # notInTimeWindows : resynchroniser
                self.boots, self.etime, self._etime_at = boots, retime, time.monotonic()
                return self._request_v3(tag, oids, a, b, _again=False)
            reasons = {"1.3.6.1.6.3.15.1.1.3": "utilisateur inconnu", "1.3.6.1.6.3.15.1.1.5": "mot de passe d'authentification incorrect",
                       "1.3.6.1.6.3.15.1.1.6": "mot de passe de chiffrement incorrect", "1.3.6.1.6.3.15.1.1.1": "niveau de sécurité non pris en charge",
                       "1.3.6.1.6.3.15.1.1.4": "engineID inconnu"}
            raise SnmpError(next((v for k, v in reasons.items() if oid.startswith(k)), f"rapport {oid}"))
        if es:
            raise SnmpError(ERRORS.get(es, f"erreur {es}"))
        return vbs

    # ------------------------------------------------------------------- API
    def _req(self, tag, oids, a=0, b=0):
        if self.cred.version == "3":
            return self._request_v3(tag, oids, a, b)
        return self._request_community(tag, oids, a, b)

    def get(self, oids: list[str]) -> dict:
        out = {}
        for i in range(0, len(oids), 20):
            for oid, v in self._req(GET, oids[i:i + 20]):
                if not missing(v):
                    out[oid] = v
        return out

    def walk(self, base: str, max_rows: int = 5000, bulk: int = 25, deadline: float | None = None) -> list[tuple[str, object]]:
        base = base.strip(".")
        prefix = base + "."
        out, cur = [], base
        use_bulk = self.cred.version != "1"
        while len(out) < max_rows:
            if deadline and time.monotonic() > deadline:
                break
            vbs = self._req(GETBULK, [cur], 0, bulk) if use_bulk else self._req(GETNEXT, [cur])
            if not vbs:
                break
            stop = False
            for oid, v in vbs:
                if not oid.startswith(prefix) or missing(v) or oid == cur:
                    stop = True
                    break
                out.append((oid, v))
                cur = oid
            if stop:
                break
        return out


def text(v) -> str:
    if isinstance(v, bytes):
        try:
            s = v.decode("utf-8")
        except UnicodeDecodeError:
            s = v.decode("latin-1")
        return s.replace("\x00", "").strip()
    return "" if v is None else str(v)


def mac_text(v) -> str:
    if isinstance(v, bytes) and len(v) == 6:
        return ":".join(f"{b:02x}" for b in v)
    return text(v)


def probe(ip: str, creds: list[Credential], timeout: float = 1.2, cancel: threading.Event | None = None):
    """Premier identifiant accepté : (Credential, sysDescr, sysObjectID, sysName) ou None."""
    for cr in creds:
        if cancel and cancel.is_set():
            return None
        try:
            with Session(ip, cr, timeout=timeout, retries=0 if cr.version != "3" else 1) as s:
                r = s.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"])
                if r:
                    return cr, text(r.get("1.3.6.1.2.1.1.1.0")), str(r.get("1.3.6.1.2.1.1.2.0") or ""), text(r.get("1.3.6.1.2.1.1.5.0"))
        except Timeout:
            if cr.version != "3":
                continue
        except SnmpError:
            continue
    return None
