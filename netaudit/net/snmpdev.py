"""Relevé SNMP d'un équipement (lecture seule) : identité, interfaces et
compteurs d'erreurs, duplex, voisins LLDP / CDP, table des MAC, spanning tree,
VLAN, PoE, composants (firmware, n° de série), table ARP, charge CPU / mémoire.

Chaque table est optionnelle : un équipement qui ne la gère pas renvoie
simplement « rien ». Un délai global par équipement borne la durée.
"""
from __future__ import annotations

import logging
import time

from . import snmp
from .snmp import mac_text, text

log = logging.getLogger(__name__)

SYS = "1.3.6.1.2.1.1"
IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"
DOT3 = "1.3.6.1.2.1.10.7.2.1"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_MAN = "1.0.8802.1.1.2.1.4.2.1"
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"
CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"
BRIDGE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"
FDB_Q = "1.3.6.1.2.1.17.7.1.2.2.1.2"
FDB_D = "1.3.6.1.2.1.17.4.3.1.2"
STP = "1.3.6.1.2.1.17.2"
STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"
VLAN_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"
PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
ENT = "1.3.6.1.2.1.47.1.1.1.1"
PSE_MAIN = "1.3.6.1.2.1.105.1.3.1.1"
PSE_PORT_STATUS = "1.3.6.1.2.1.105.1.1.1.6"
ARP_MEDIA = "1.3.6.1.2.1.4.22.1.2"
HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"

ENTERPRISES = {
    9: "Cisco", 11: "HP / HPE", 25506: "HPE (Comware)", 47196: "HPE Aruba", 14823: "Aruba", 4413: "Broadcom (UniFi)",
    41112: "Ubiquiti", 10002: "Ubiquiti", 2636: "Juniper", 12356: "Fortinet", 25461: "Palo Alto", 14988: "MikroTik",
    6574: "Synology", 24681: "QNAP", 8072: "Net-SNMP (Linux)", 311: "Microsoft", 674: "Dell", 6027: "Dell (Force10)",
    4526: "Netgear", 171: "D-Link", 11863: "TP-Link", 3955: "Linksys", 2011: "Huawei", 890: "Zyxel", 1916: "Extreme",
    1991: "Brocade / Foundry", 5624: "Enterasys", 30065: "Arista", 3375: "F5", 2620: "Check Point", 8741: "SonicWall",
    318: "APC", 534: "Eaton", 6876: "VMware", 2604: "Sophos", 6486: "Alcatel-Lucent", 207: "Allied Telesis",
    1248: "Epson", 2435: "Brother", 1602: "Canon", 367: "Ricoh", 253: "Xerox", 1347: "Kyocera", 18334: "Konica Minolta",
    641: "Lexmark", 12325: "pfSense / FreeBSD", 21796: "Cambium", 17713: "Cambium", 26928: "Aerohive", 14179: "Cisco (WLC)",
    29671: "Meraki", 3076: "Cisco (VPN)", 5771: "Cisco (Linksys)", 12148: "Eltek", 3808: "CyberPower", 13742: "Raritan",
    10418: "Avocent", 1714: "Cisco (Linksys SB)", 6141: "Ciena", 9303: "Planet", 3224: "Juniper (Netscreen)",
    4329: "Siemens", 36673: "Stormshield", 1588: "Brocade", 18928: "Lantronix", 37072: "Hikvision", 39165: "Hikvision",
    1004849: "Dahua", 2021: "UCD-SNMP", 50536: "Teltonika", 48690: "Teltonika", 37447: "Zyxel", 25053: "Ruckus",
    4115: "Avaya", 5651: "Mitel", 6889: "Avaya", 6296: "D-Link", 52642: "Ruijie", 4881: "Ruijie", 1411: "Juniper (Funk)",
}

DUPLEX = {1: "inconnu", 2: "half", 3: "full"}
STP_STATES = {1: "désactivé", 2: "bloquant", 3: "écoute", 4: "apprentissage", 5: "transmission", 6: "défaillant"}
PSE_STATUS = {1: "désactivé", 2: "recherche", 3: "alimente", 4: "défaut", 5: "test", 6: "autre défaut"}


def enterprise(sys_oid: str) -> str:
    p = sys_oid.split(".")
    if len(p) > 6 and p[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            return ENTERPRISES.get(int(p[6]), f"entreprise {p[6]}")
        except ValueError:
            pass
    return ""


def _idx(oid: str, base: str) -> str:
    return oid[len(base) + 1:]


def _col(rows, base: str, col: int) -> dict:
    pre = f"{base}.{col}."
    return {oid[len(pre):]: v for oid, v in rows if oid.startswith(pre)}


class Collector:
    def __init__(self, sess: snmp.Session, budget: float = 75.0):
        self.s = sess
        self.deadline = time.monotonic() + budget
        self.errors: list[str] = []

    def walk(self, base: str, max_rows: int = 6000) -> list:
        if time.monotonic() > self.deadline:
            self.errors.append(f"{base} : délai global atteint")
            return []
        try:
            return self.s.walk(base, max_rows=max_rows, deadline=self.deadline)
        except snmp.Timeout:
            self.errors.append(f"{base} : pas de réponse")
            return []
        except snmp.SnmpError as exc:
            self.errors.append(f"{base} : {exc}")
            return []

    def get(self, oids: list[str]) -> dict:
        try:
            return self.s.get(oids)
        except snmp.SnmpError as exc:
            self.errors.append(f"get : {exc}")
            return {}


def counters(sess: snmp.Session, budget: float = 30.0) -> dict:
    """Compteurs d'erreurs / rejets / octets par interface (2e relevé)."""
    c = Collector(sess, budget)
    out: dict[str, dict] = {}
    for name, base in (("in_err", f"{IF}.14"), ("out_err", f"{IF}.20"), ("in_disc", f"{IF}.13"), ("out_disc", f"{IF}.19"),
                       ("in_oct", f"{IFX}.6"), ("out_oct", f"{IFX}.10"), ("fcs", f"{DOT3}.3")):
        for oid, v in c.walk(base):
            if isinstance(v, int):
                out.setdefault(_idx(oid, base), {})[name] = v
    return {"t": time.time(), "if": out}


def collect(sess: snmp.Session, cred_label: str, deep: bool = False, budget: float = 75.0) -> dict:
    c = Collector(sess, budget)
    t0 = time.time()
    sysv = c.get([f"{SYS}.{i}.0" for i in (1, 2, 3, 4, 5, 6)] + ["1.3.6.1.2.1.4.1.0"])
    sys_oid = str(sysv.get(f"{SYS}.2.0") or "")
    dev = {"ip": sess.ip, "credential": cred_label, "t": t0,
           "sys": {"descr": text(sysv.get(f"{SYS}.1.0")), "object_id": sys_oid, "vendor": enterprise(sys_oid),
                   "uptime_s": (sysv.get(f"{SYS}.3.0") or 0) / 100 if isinstance(sysv.get(f"{SYS}.3.0"), int) else None,
                   "contact": text(sysv.get(f"{SYS}.4.0")), "name": text(sysv.get(f"{SYS}.5.0")),
                   "location": text(sysv.get(f"{SYS}.6.0")),
                   "forwarding": sysv.get("1.3.6.1.2.1.4.1.0") == 1}}      # ipForwarding : l'équipement route

    # ------------------------------------------------------------ interfaces
    ift = c.walk(IF)
    ifx = c.walk(IFX)
    dot3 = c.walk(DOT3)
    ifs: dict[str, dict] = {}
    for col, key in ((2, "descr"), (3, "type"), (4, "mtu"), (5, "speed"), (6, "mac"), (7, "admin"), (8, "oper"),
                     (9, "last_change"), (13, "in_disc"), (14, "in_err"), (15, "in_unknown"), (19, "out_disc"), (20, "out_err")):
        for i, v in _col(ift, IF, col).items():
            ifs.setdefault(i, {"index": int(i) if i.isdigit() else i})[key] = mac_text(v) if key == "mac" else text(v) if key == "descr" else v
    for col, key in ((1, "name"), (6, "in_oct"), (10, "out_oct"), (15, "high_speed"), (18, "alias")):
        for i, v in _col(ifx, IFX, col).items():
            if i in ifs:
                ifs[i][key] = text(v) if key in ("name", "alias") else v
    for col, key in ((2, "align_err"), (3, "fcs"), (4, "single_coll"), (5, "multi_coll"), (8, "late_coll"),
                     (9, "excess_coll"), (19, "duplex")):
        for i, v in _col(dot3, DOT3, col).items():
            if i in ifs:
                ifs[i][key] = v
    for e in ifs.values():
        sp = e.get("high_speed")
        e["mbps"] = sp if isinstance(sp, int) and sp else (e["speed"] // 1_000_000 if isinstance(e.get("speed"), int) else None)
        e["duplex"] = DUPLEX.get(e.get("duplex"), None) if "duplex" in e else None
    dev["interfaces"] = list(ifs.values())

    # ------------------------------------------------------------ LLDP / CDP
    rem = c.walk(LLDP_REM, 2000)
    neigh: dict[str, dict] = {}
    for col, key in ((4, "chassis_subtype"), (5, "chassis"), (6, "port_subtype"), (7, "port"), (8, "port_desc"),
                     (9, "sys_name"), (10, "sys_desc"), (12, "caps")):
        for i, v in _col(rem, LLDP_REM, col).items():
            ent = neigh.setdefault(i, {})
            ent[key] = v
    loc = c.walk(LLDP_LOC_PORT, 1000) if neigh else []
    loc_port = {i: text(v) for i, v in _col(loc, LLDP_LOC_PORT, 3).items()}
    loc_desc = {i: text(v) for i, v in _col(loc, LLDP_LOC_PORT, 4).items()}
    man = c.walk(LLDP_MAN, 2000) if neigh else []
    man_ip: dict[str, str] = {}
    for oid, _v in man:
        p = _idx(oid, LLDP_MAN).split(".")
        # col.timeMark.localPort.remIndex.subtype.len.a.b.c.d
        if len(p) >= 10 and p[4] == "1" and p[5] == "4":
            man_ip[".".join(p[1:4])] = ".".join(p[6:10])
    lldp = []
    for i, e in neigh.items():
        p = i.split(".")
        lport = p[1] if len(p) >= 2 else ""
        lldp.append({"local_port_num": lport, "local_port": loc_desc.get(lport) or loc_port.get(lport) or lport,
                     "chassis": _chassis(e.get("chassis_subtype"), e.get("chassis")),
                     "port": _chassis(e.get("port_subtype"), e.get("port")), "port_desc": text(e.get("port_desc")),
                     "sys_name": text(e.get("sys_name")), "sys_desc": text(e.get("sys_desc"))[:200],
                     "caps": _caps(e.get("caps")), "mgmt_ip": man_ip.get(i, "")})
    dev["lldp"] = lldp
    cdp_rows = c.walk(CDP, 1000) if dev["sys"]["vendor"].startswith("Cisco") else []
    cdp = {}
    for col, key in ((4, "address"), (6, "device_id"), (7, "port"), (8, "platform")):
        for i, v in _col(cdp_rows, CDP, col).items():
            cdp.setdefault(i, {"local_if": i.split(".")[0]})[key] = (
                (".".join(str(b) for b in v) if isinstance(v, bytes) and len(v) == 4 else text(v)))
    dev["cdp"] = list(cdp.values())

    # --------------------------------------------------------- pont / FDB / STP
    bp = {i: v for i, v in _col(c.walk(BRIDGE_PORT_IF, 2000), BRIDGE_PORT_IF.rsplit(".", 1)[0], 2).items()}
    dev["bridge_ports"] = bp
    fdb = []
    rows = c.walk(FDB_Q, 20000)
    for oid, v in rows:
        p = _idx(oid, FDB_Q).split(".")
        if len(p) >= 7:
            fdb.append({"vlan": p[0], "mac": ":".join(f"{int(x):02x}" for x in p[-6:]), "bridge_port": v})
    if not rows:
        for oid, v in c.walk(FDB_D, 20000):
            p = _idx(oid, FDB_D).split(".")
            if len(p) == 6:
                fdb.append({"vlan": "", "mac": ":".join(f"{int(x):02x}" for x in p), "bridge_port": v})
    dev["fdb"] = fdb
    stp = c.get([f"{STP}.1.0", f"{STP}.2.0", f"{STP}.3.0", f"{STP}.4.0", f"{STP}.5.0", f"{STP}.6.0", f"{STP}.7.0"])
    if stp:
        tsc = stp.get(f"{STP}.3.0")
        dev["stp"] = {"protocol": stp.get(f"{STP}.1.0"), "priority": stp.get(f"{STP}.2.0"),
                      "since_change_s": tsc / 100 if isinstance(tsc, int) else None, "top_changes": stp.get(f"{STP}.4.0"),
                      "root": (stp.get(f"{STP}.5.0") or b"").hex() if isinstance(stp.get(f"{STP}.5.0"), bytes) else "",
                      "root_cost": stp.get(f"{STP}.6.0"), "root_port": stp.get(f"{STP}.7.0")}
        dev["stp_ports"] = {i: STP_STATES.get(v, v) for i, v in _col(c.walk(STP_PORT_STATE, 2000), STP_PORT_STATE.rsplit(".", 1)[0], 3).items()}
    dev["vlans"] = {i: text(v) for i, v in _col(c.walk(VLAN_NAME, 4096), VLAN_NAME.rsplit(".", 1)[0], 1).items()}
    dev["pvid"] = {i: v for i, v in _col(c.walk(PVID, 2000), PVID.rsplit(".", 1)[0], 1).items()}

    # -------------------------------------------------------------- PoE
    pse = c.walk(PSE_MAIN, 50)
    if pse:
        dev["poe"] = {"power_w": _col(pse, PSE_MAIN, 2), "status": _col(pse, PSE_MAIN, 3), "used_w": _col(pse, PSE_MAIN, 4)}
        dev["poe_ports"] = {i: PSE_STATUS.get(v, v) for i, v in _col(c.walk(PSE_PORT_STATUS, 500), PSE_PORT_STATUS.rsplit(".", 1)[0], 6).items()}

    # ---------------------------------------------------------- composants
    ent = c.walk(ENT, 3000)
    comps = {}
    for col, key in ((2, "descr"), (5, "class"), (7, "name"), (8, "hw"), (9, "fw"), (10, "sw"), (11, "serial"), (13, "model")):
        for i, v in _col(ent, ENT, col).items():
            comps.setdefault(i, {})[key] = v if key == "class" else text(v)
    dev["entities"] = [e for e in comps.values() if e.get("class") in (3, 9, 10, 11) and (e.get("serial") or e.get("sw") or e.get("model") or e.get("fw"))][:20]

    # -------------------------------------------------------- ARP (routeurs)
    arp = []
    for oid, v in c.walk(ARP_MEDIA, 8000):
        p = _idx(oid, ARP_MEDIA).split(".")
        if len(p) == 5 and isinstance(v, bytes) and len(v) == 6:
            arp.append({"ifindex": p[0], "ip": ".".join(p[1:]), "mac": mac_text(v)})
    dev["arp"] = arp

    # --------------------------------------------------- charge (Host Resources)
    cpu = [v for _o, v in c.walk(HR_CPU, 256) if isinstance(v, int)]
    if cpu:
        dev["cpu"] = {"avg": round(sum(cpu) / len(cpu)), "max": max(cpu), "n": len(cpu)}
    st = c.walk(HR_STORAGE, 400)
    stor = []
    descr, units, size, used, typ = (_col(st, HR_STORAGE, n) for n in (3, 4, 5, 6, 2))
    for i in descr:
        try:
            u = units.get(i) or 1
            if size.get(i):
                stor.append({"descr": text(descr[i])[:60], "type": str(typ.get(i, "")).rsplit(".", 1)[-1],
                             "size": size[i] * u, "used": (used.get(i) or 0) * u})
        except TypeError:
            continue
    dev["storage"] = stor[:30]
    dev["errors"] = c.errors
    dev["seconds"] = round(time.time() - t0, 1)
    dev["requests"] = sess.requests
    return dev


def _chassis(subtype, v) -> str:
    if isinstance(v, bytes):
        if subtype == 4 or (subtype == 3 and len(v) == 6) or (len(v) == 6 and subtype in (None, 4)):
            return mac_text(v)
        if subtype == 5 and len(v) == 5 and v[0] == 1:
            return ".".join(str(b) for b in v[1:])
        t = text(v)
        if t and all(32 <= ord(ch) < 127 for ch in t):
            return t
        return v.hex(":")
    return text(v)


def _caps(v) -> list[str]:
    if not isinstance(v, bytes) or not v:
        return []
    bits = int.from_bytes(v[:2].ljust(2, b"\x00"), "big")
    names = ["autre", "répéteur", "pont/switch", "borne Wi-Fi", "routeur", "téléphone", "câble DOCSIS", "station",
             "C-VLAN", "S-VLAN", "TPMR"]
    return [n for i, n in enumerate(names) if bits & (0x8000 >> i)]
