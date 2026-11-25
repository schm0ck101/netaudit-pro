"""Contexte partagé par les règles : instantané, appareils classés, aides."""
from __future__ import annotations

import re

from .classify import NETWORK_GEAR, classify_all
from .model import NOT_CHECKED, OK, Finding

PHYS_TYPES = {6, 7, 62, 69, 71, 117}            # Ethernet, Fast/Gigabit Ethernet, Wi-Fi
VIRTUAL_NAME = re.compile(r"^(lo|dummy|docker|veth|virbr|vnet|tap|tun|wg|gre|gretap|erspan|sit|ip6|ip_vti|ifb|vxlan|"
                          r"br[-0-9]|br$|bond\d+\.\d+|cpu|null|vlan|vl\d|loopback|stack|trk|lag|port-channel|po\d|tunnel|"
                          r"ipsec|ppp|wlan\d+-|ath\d|wifi\d|switch\d|eth\d+\.\d+|zt|tailscale|nat|imq|teql|ovs|cali|flannel)",
                          re.I)


class Ctx:
    def __init__(self, snap: dict, prev: dict | None = None):
        self.snap = snap
        self.prev = prev
        self.findings: list[Finding] = []
        self.hosts = classify_all(snap)
        self.snmp: dict = snap.get("snmp") or {}
        self.c2: dict = snap.get("snmp_counters2") or {}
        self.ssh: dict = snap.get("ssh") or {}
        self.connect: dict = snap.get("connect") or {}
        self.opts: dict = snap.get("options") or {}
        self.deep = bool(self.opts.get("deep"))
        self.networks: list = snap.get("networks") or []
        self.gateways = {n.get("gateway") for n in self.networks if n.get("gateway")}
        if snap.get("default_gateway"):
            self.gateways.add(snap["default_gateway"])

    # ----------------------------------------------------------------- ajout
    def add(self, fid: str, domain: str, sev: int, title: str, detail: str = "", impact: str = "", fix: str = "",
            evidence: list | None = None, predictive: bool = False):
        self.findings.append(Finding(fid, domain, sev, title, detail, impact, fix, [str(e) for e in (evidence or [])][:40], predictive))

    def ok(self, fid: str, domain: str, title: str, detail: str = ""):
        self.findings.append(Finding(fid, domain, OK, title, detail))

    def nc(self, fid: str, domain: str, title: str, why: str):
        self.findings.append(Finding(fid, domain, NOT_CHECKED, title, why))

    # ---------------------------------------------------------------- appareils
    def label(self, ip: str) -> str:
        h = self.hosts.get(ip) or {}
        name = h.get("name") or (self.snmp.get(ip, {}).get("sys") or {}).get("name") or ""
        kind = h.get("kind_label") if h.get("kind") not in (None, "unknown") else ""
        if name:
            return f"{name} ({ip})"
        return f"{ip}" + (f" — {kind.lower()}" if kind else "")

    def active(self) -> list[dict]:
        return [h for h in self.hosts.values() if not h.get("inactive") and h.get("kind") != "honeypot"]

    def gear(self) -> list[dict]:
        return [h for h in self.active() if h.get("kind") in NETWORK_GEAR]

    # --------------------------------------------------------------- interfaces
    def phys_ifaces(self, ip: str, only_up: bool = True) -> list[dict]:
        out = []
        for i in (self.snmp.get(ip) or {}).get("interfaces") or []:
            nm = i.get("name") or i.get("descr") or ""
            if i.get("type") not in PHYS_TYPES or VIRTUAL_NAME.match(nm):
                continue
            if only_up and i.get("oper") != 1:
                continue
            out.append(i)
        return out

    def if_label(self, i: dict) -> str:
        nm = i.get("name") or i.get("descr") or f"#{i.get('index')}"
        al = (i.get("alias") or "").strip()
        return f"{nm}" + (f" « {al} »" if al and al != nm else "")

    def delta(self, ip: str, i: dict, key: str) -> int | None:
        """Évolution d'un compteur entre le 1er relevé SNMP et le 2e (fin du diagnostic)."""
        c2 = ((self.c2.get(ip) or {}).get("if") or {}).get(str(i.get("index"))) or {}
        a, b = i.get(key), c2.get(key)
        if not isinstance(a, int) or not isinstance(b, int) or b < a:
            return None
        return b - a

    def interval(self, ip: str) -> float | None:
        t1 = (self.snmp.get(ip) or {}).get("t")
        t2 = (self.c2.get(ip) or {}).get("t")
        return (t2 - t1) if t1 and t2 and t2 > t1 else None

    def macs_per_if(self, ip: str) -> dict[str, int]:
        """Nombre d'adresses MAC apprises par interface (table MAC du switch) : un port qui
        voit beaucoup de MAC mène à un autre switch ou à une borne Wi-Fi."""
        d = self.snmp.get(ip) or {}
        bp = {str(k): str(v) for k, v in (d.get("bridge_ports") or {}).items()}
        out: dict[str, set] = {}
        for e in d.get("fdb") or []:
            port = str(e.get("bridge_port"))
            out.setdefault(bp.get(port, port), set()).add(e.get("mac"))
        return {k: len(v) for k, v in out.items()}

    def lldp_neighbor(self, ip: str, i: dict) -> dict | None:
        names = {str(i.get("name") or ""), str(i.get("descr") or ""), str(i.get("index"))}
        for n in (self.snmp.get(ip) or {}).get("lldp") or []:
            if n.get("local_port") in names or n.get("local_port_num") == str(i.get("index")):
                return n
        return None


def nc_finding(fid, domain, title, why):
    return Finding(fid, domain, NOT_CHECKED, title, why)
