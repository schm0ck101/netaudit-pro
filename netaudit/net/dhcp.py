"""Test DHCP (mode approfondi) : diffusion d'une requête DHCPDISCOVER et
collecte de TOUTES les offres pendant quelques secondes.

Aucune adresse n'est réellement prise : on n'envoie jamais de DHCPREQUEST.
L'adresse MAC du poste d'audit est utilisée (pas de MAC inventée : pas
d'« appareil fantôme » dans la console du client).
Plusieurs serveurs qui répondent = serveur DHCP pirate ou box oubliée.
"""
from __future__ import annotations

import os
import socket
import struct
import time

OPT_NAMES = {1: "mask", 3: "router", 6: "dns", 15: "domain", 42: "ntp", 51: "lease", 54: "server_id", 58: "renew",
             59: "rebind", 66: "tftp", 67: "bootfile", 43: "vendor", 119: "search", 252: "wpad"}


def _ip_list(b: bytes) -> list[str]:
    return [socket.inet_ntoa(b[i:i + 4]) for i in range(0, len(b) - 3, 4)]


def build_discover(mac: bytes, xid: int) -> bytes:
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                      b"\0" * 4, mac.ljust(16, b"\0"), b"\0" * 64, b"\0" * 128)
    opts = b"\x63\x82\x53\x63"
    opts += bytes([53, 1, 1])
    opts += bytes([61, 7, 1]) + mac
    opts += bytes([55, 9, 1, 3, 6, 15, 28, 42, 51, 54, 119])
    opts += bytes([60, 11]) + b"NetAuditPro"
    opts += b"\xff"
    return (pkt + opts).ljust(300, b"\0")


def parse(data: bytes, xid: int) -> dict | None:
    if len(data) < 240 or data[0] != 2 or struct.unpack_from("!I", data, 4)[0] != xid or data[236:240] != b"\x63\x82\x53\x63":
        return None
    yi = socket.inet_ntoa(data[16:20])
    si = socket.inet_ntoa(data[20:24])
    gi = socket.inet_ntoa(data[24:28])
    off, opts, mtype = 240, {}, None
    while off < len(data):
        code = data[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        ln = data[off + 1]
        val = data[off + 2:off + 2 + ln]
        off += 2 + ln
        if code == 53 and val:
            mtype = val[0]
        name = OPT_NAMES.get(code)
        if not name:
            continue
        if code in (1, 54):
            opts[name] = socket.inet_ntoa(val[:4]) if len(val) >= 4 else ""
        elif code in (3, 6, 42):
            opts[name] = _ip_list(val)
        elif code in (51, 58, 59):
            opts[name] = struct.unpack("!I", val[:4])[0] if len(val) >= 4 else None
        else:
            opts[name] = val.decode("utf-8", "replace").strip("\0")[:120]
    return {"type": {2: "offer", 5: "ack", 6: "nak"}.get(mtype, mtype), "offered_ip": yi, "next_server": si,
            "relay": gi if gi != "0.0.0.0" else "", **opts}


def discover(local_ip: str, mac: str, wait: float = 4.0) -> dict:
    """Renvoie {ok, offers[{source, server_id, offered_ip, router, dns, …}], error}."""
    xid = struct.unpack("!I", os.urandom(4))[0]
    try:
        macb = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    except ValueError:
        return {"ok": False, "offers": [], "error": "adresse MAC du poste inconnue"}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind((local_ip, 68))
        except OSError as exc:
            return {"ok": False, "offers": [], "error": f"port 68 indisponible ({exc})"}
        s.settimeout(0.3)
        pkt = build_discover(macb, xid)
        s.sendto(pkt, ("255.255.255.255", 67))
        offers, seen = [], set()
        end = time.monotonic() + wait
        resent = False
        while time.monotonic() < end:
            if not resent and time.monotonic() > end - wait / 2:
                s.sendto(pkt, ("255.255.255.255", 67))
                resent = True
            try:
                data, (src, _p) = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                continue
            r = parse(data, xid)
            if not r:
                continue
            key = (src, r.get("server_id"))
            if key in seen:
                continue
            seen.add(key)
            offers.append({"source": src, **r})
        return {"ok": True, "offers": offers, "error": ""}
    finally:
        s.close()
