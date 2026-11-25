"""Client DNS minimal (UDP) : interroger UN serveur précis, mesurer son temps de
réponse, lire les enregistrements A/AAAA/PTR/TXT/SOA/SRV/MX/CNAME.

Le résolveur de Windows (getaddrinfo) ne permet pas de choisir le serveur ni
de distinguer « pas de réponse » de « nom inexistant » : d'où ce client.
Sert aussi à décoder les réponses mDNS.
"""
from __future__ import annotations

import os
import socket
import struct
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "OK", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def build_query(name: str, qtype: str | int = "A", rd: bool = True, qid: int | None = None, unicast_response: bool = False) -> bytes:
    qid = qid if qid is not None else struct.unpack("!H", os.urandom(2))[0]
    flags = 0x0100 if rd else 0
    head = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("idna" if any(ord(c) > 127 for c in p) else "ascii") for p in name.rstrip(".").split(".") if p) + b"\x00"
    t = TYPES[qtype] if isinstance(qtype, str) else qtype
    return head + q + struct.pack("!HH", t, 0x8001 if unicast_response else 1)


def _name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while True:
        if off >= len(msg) or depth > 20:
            raise ValueError("nom tronqué")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", msg, off)[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("utf-8", "replace"))
        off += ln
    return ".".join(labels), (end if jumped else off)


def parse(msg: bytes) -> dict:
    qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", msg, 0)
    off = 12
    questions = []
    for _ in range(qd):
        n, off = _name(msg, off)
        t, c = struct.unpack_from("!HH", msg, off)
        off += 4
        questions.append((n, TYPE_NAMES.get(t, t)))
    records = []
    for section, count in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(count):
            n, off = _name(msg, off)
            t, c, ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
            off += 10
            rd = msg[off:off + rdlen]
            val: object = rd.hex()
            try:
                if t == 1 and rdlen == 4:
                    val = socket.inet_ntoa(rd)
                elif t == 28 and rdlen == 16:
                    val = socket.inet_ntop(socket.AF_INET6, rd)
                elif t in (2, 5, 12):
                    val = _name(msg, off)[0]
                elif t == 16:
                    parts, i = [], 0
                    while i < len(rd):
                        ln = rd[i]
                        parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                        i += 1 + ln
                    val = parts
                elif t == 33:
                    pr, w, port = struct.unpack_from("!HHH", rd, 0)
                    val = {"priority": pr, "weight": w, "port": port, "target": _name(msg, off + 6)[0]}
                elif t == 15:
                    val = {"pref": struct.unpack_from("!H", rd, 0)[0], "host": _name(msg, off + 2)[0]}
                elif t == 6:
                    mname, o2 = _name(msg, off)
                    rname, o2 = _name(msg, o2)
                    serial = struct.unpack_from("!I", msg, o2)[0]
                    val = {"mname": mname, "rname": rname, "serial": serial}
            except (ValueError, struct.error):
                pass
            records.append({"section": section, "name": n, "type": TYPE_NAMES.get(t, t), "ttl": ttl, "value": val})
            off += rdlen
    return {"id": qid, "rcode": RCODES.get(flags & 0xF, flags & 0xF), "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
            "ra": bool(flags & 0x0080), "questions": questions, "records": records}


def query(server: str, name: str, qtype: str = "A", timeout: float = 2.0, rd: bool = True, tries: int = 2) -> dict:
    """Interroge ``server`` ; renvoie {ok, rcode, ms, answers[], error}."""
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    last = "pas de réponse"
    for _ in range(max(1, tries)):
        pkt = build_query(name, qtype, rd)
        qid = struct.unpack_from("!H", pkt, 0)[0]
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t0 = time.perf_counter()
            try:
                s.sendto(pkt, (server, 53))
                while True:
                    data, _src = s.recvfrom(4096)
                    if len(data) >= 12 and struct.unpack_from("!H", data, 0)[0] == qid:
                        break
                ms = (time.perf_counter() - t0) * 1000
                r = parse(data)
                ans = [x for x in r["records"] if x["section"] == "an"]
                return {"ok": True, "rcode": r["rcode"], "ms": round(ms, 1), "answers": ans, "ra": r["ra"], "aa": r["aa"],
                        "authority": [x for x in r["records"] if x["section"] == "ns"]}
            except socket.timeout:
                last = "délai dépassé"
            except OSError as exc:
                last = str(exc)
                break
            except (ValueError, struct.error) as exc:
                last = f"réponse illisible ({exc})"
                break
    return {"ok": False, "rcode": None, "ms": None, "answers": [], "error": last}


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
