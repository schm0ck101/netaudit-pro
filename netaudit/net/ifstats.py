"""Compteurs des cartes réseau (GetIfTable2, iphlpapi) sans droits administrateur.

Deux relevés espacés de quelques secondes donnent le débit de broadcast /
multicast reçu (tempête de broadcast, boucle) et l'évolution des erreurs.
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes


class GUID(ctypes.Structure):
    _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD), ("d3", wintypes.WORD), ("d4", ctypes.c_ubyte * 8)]


class MIB_IF_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64), ("InterfaceIndex", wintypes.ULONG), ("InterfaceGuid", GUID),
        ("Alias", ctypes.c_wchar * 257), ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", wintypes.ULONG), ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32), ("Mtu", wintypes.ULONG), ("Type", wintypes.ULONG),
        ("TunnelType", wintypes.ULONG), ("MediaType", wintypes.ULONG), ("PhysicalMediumType", wintypes.ULONG),
        ("AccessType", wintypes.ULONG), ("DirectionType", wintypes.ULONG), ("Flags", ctypes.c_ubyte),
        ("OperStatus", wintypes.ULONG), ("AdminStatus", wintypes.ULONG), ("MediaConnectState", wintypes.ULONG),
        ("NetworkGuid", GUID), ("ConnectionType", wintypes.ULONG),
        ("TransmitLinkSpeed", ctypes.c_uint64), ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("InOctets", ctypes.c_uint64), ("InUcastPkts", ctypes.c_uint64), ("InNUcastPkts", ctypes.c_uint64),
        ("InDiscards", ctypes.c_uint64), ("InErrors", ctypes.c_uint64), ("InUnknownProtos", ctypes.c_uint64),
        ("InUcastOctets", ctypes.c_uint64), ("InMulticastOctets", ctypes.c_uint64), ("InBroadcastOctets", ctypes.c_uint64),
        ("OutOctets", ctypes.c_uint64), ("OutUcastPkts", ctypes.c_uint64), ("OutNUcastPkts", ctypes.c_uint64),
        ("OutDiscards", ctypes.c_uint64), ("OutErrors", ctypes.c_uint64), ("OutUcastOctets", ctypes.c_uint64),
        ("OutMulticastOctets", ctypes.c_uint64), ("OutBroadcastOctets", ctypes.c_uint64), ("OutQLen", ctypes.c_uint64),
    ]


FIELDS = ["InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors", "InUnknownProtos", "InMulticastOctets",
          "InBroadcastOctets", "OutOctets", "OutUcastPkts", "OutNUcastPkts", "OutDiscards", "OutErrors"]


def snapshot() -> dict:
    """{index: {compteurs}} pour les interfaces physiques connectées (Ethernet / Wi-Fi)."""
    if ctypes.sizeof(MIB_IF_ROW2) != 1352:      # garde-fou : structure Windows x64
        return {}
    dll = ctypes.WinDLL("iphlpapi.dll")
    ptr = ctypes.c_void_p()
    if dll.GetIfTable2(ctypes.byref(ptr)) != 0 or not ptr.value:
        return {}
    try:
        n = ctypes.c_ulong.from_address(ptr.value).value
        rows = (MIB_IF_ROW2 * n).from_address(ptr.value + 8)
        out = {}
        for r in rows:
            # 6 = Ethernet, 71 = Wi-Fi ; OperStatus 1 = actif ; Flags bit 0 = interface matérielle
            if r.Type not in (6, 71) or r.OperStatus != 1 or not (r.Flags & 1):
                continue
            d = {f: int(getattr(r, f)) for f in FIELDS}
            d.update(index=int(r.InterfaceIndex), alias=r.Alias, desc=r.Description, t=time.time(),
                     speed=int(r.ReceiveLinkSpeed), mtu=int(r.Mtu))
            out[int(r.InterfaceIndex)] = d
        return out
    finally:
        dll.FreeMibTable(ptr)


def rates(a: dict, b: dict) -> dict:
    """Écarts par seconde entre deux relevés (même interface)."""
    out = {}
    for idx, rb in b.items():
        ra = a.get(idx)
        if not ra:
            continue
        dt = max(0.001, rb["t"] - ra["t"])
        d = {f: max(0, rb[f] - ra[f]) for f in FIELDS}
        out[idx] = {"alias": rb["alias"], "desc": rb["desc"], "seconds": round(dt, 1), "delta": d,
                    "nucast_pps": round(d["InNUcastPkts"] / dt, 1), "bcast_Bps": round(d["InBroadcastOctets"] / dt, 1),
                    "mcast_Bps": round(d["InMulticastOctets"] / dt, 1), "in_pps": round((d["InUcastPkts"] + d["InNUcastPkts"]) / dt, 1),
                    "totals": {f: rb[f] for f in FIELDS}, "speed": rb["speed"]}
    return out
