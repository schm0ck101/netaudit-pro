"""Résolution ARP via l'API Windows (iphlpapi), sans droits administrateur.

* ``send_arp(ip)`` : demande ARP active (SendARP) ; ne fonctionne que pour une
  adresse du même sous-réseau (au-delà du routeur, Windows renvoie la MAC de la
  passerelle ou une erreur : on ne l'utilise que sur les réseaux locaux).
* ``arp_table()`` : cache ARP du poste (GetIpNetTable).

Un appareil qui ne répond pas au ping (pare-feu Windows, téléphone en veille)
répond presque toujours à l'ARP : c'est la méthode de découverte la plus fiable
sur un réseau local.
"""
from __future__ import annotations

import ctypes
import socket
import struct
import sys
from ctypes import wintypes

_dll = None


def _api():
    global _dll
    if _dll is None:
        if sys.platform != "win32":
            raise OSError("Windows requis")
        d = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        d.SendARP.restype = wintypes.DWORD
        d.SendARP.argtypes = [wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG)]
        d.GetIpNetTable.restype = wintypes.DWORD
        d.GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
        _dll = d
    return _dll


def _ip_to_ulong(ip: str) -> int:
    return int.from_bytes(socket.inet_aton(ip), "little")


def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def send_arp(ip: str, src: str | None = None) -> str | None:
    """MAC de ``ip`` (format aa:bb:cc:dd:ee:ff) ou None si pas de réponse (~1 à 3 s)."""
    buf = (ctypes.c_ubyte * 8)()
    ln = wintypes.ULONG(8)
    try:
        rc = _api().SendARP(_ip_to_ulong(ip), _ip_to_ulong(src) if src else 0, buf, ctypes.byref(ln))
    except OSError:
        return None
    if rc != 0 or ln.value == 0:
        return None
    mac = bytes(buf[:ln.value])
    if not any(mac) or mac == b"\xff" * 6:
        return None
    return fmt_mac(mac)


# types d'entrée du cache ARP
ARP_TYPES = {1: "autre", 2: "invalide", 3: "dynamique", 4: "statique"}


def arp_table() -> list[dict]:
    """Cache ARP : [{ip, mac, ifindex, type}] (entrées invalides ignorées)."""
    api = _api()
    size = wintypes.ULONG(0)
    api.GetIpNetTable(None, ctypes.byref(size), False)
    if not size.value:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if api.GetIpNetTable(buf, ctypes.byref(size), True) != 0:
        return []
    raw = buf.raw
    n = struct.unpack_from("<I", raw, 0)[0]
    out = []
    # MIB_IPNETROW : dwIndex, dwPhysAddrLen, bPhysAddr[8], dwAddr, dwType  (24 octets)
    for i in range(n):
        off = 4 + i * 24
        if off + 24 > len(raw):
            break
        idx, ln = struct.unpack_from("<II", raw, off)
        mac = raw[off + 8: off + 8 + min(ln, 8)]
        addr = socket.inet_ntoa(raw[off + 16: off + 20])
        typ = struct.unpack_from("<I", raw, off + 20)[0]
        if typ == 2 or not ln or not any(mac):
            continue
        out.append({"ip": addr, "mac": fmt_mac(mac), "ifindex": idx, "type": ARP_TYPES.get(typ, str(typ))})
    return out
