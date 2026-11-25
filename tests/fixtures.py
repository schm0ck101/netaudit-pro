"""Instantanés simulés de réseaux clients variés (cas non reproductibles sur
le banc d'essai) : construits champ par champ comme ceux du scanner."""
from __future__ import annotations

import copy
import time

T0 = 1_790_000_000.0


def host(ip, mac=None, vendor="", ports=(), ttl=64, **kw):
    h = {"ip": ip, "mac": mac, "vendor": vendor, "random_mac": False, "seen_by": ["icmp", "arp"], "ports": list(ports),
         "names": {}, "ttl": ttl, "network": "10.0.0.0/24", "local_net": True}
    h.update(kw)
    return h


def iface(idx, name, mbps=1000, oper=1, duplex="full", in_err=0, out_err=0, fcs=0, in_oct=10**11, alias="", typ=6, **kw):
    d = {"index": idx, "name": name, "descr": name, "type": typ, "mbps": mbps, "oper": oper, "admin": 1, "duplex": duplex,
         "in_err": in_err, "out_err": out_err, "fcs": fcs, "in_oct": in_oct, "out_oct": in_oct, "in_disc": 0, "out_disc": 0,
         "alias": alias}
    d.update(kw)
    return d


def base() -> dict:
    """Petit réseau sain : routeur, switch, serveur AD, 3 postes, une imprimante."""
    hosts = {
        "10.0.0.1": host("10.0.0.1", "00:0c:29:aa:00:01", "Fortinet", [22, 443], 255,
                         snmp={"name": "FW-SIEGE", "descr": "FortiGate-60F v7.4.3", "vendor": "Fortinet", "version": "3"}),
        "10.0.0.2": host("10.0.0.2", "00:1a:2b:00:00:02", "Hewlett Packard Enterprise", [22, 80, 443], 64,
                         snmp={"name": "SW-CORE", "descr": "Aruba JL260A 2930F-24G-4SFP Switch, revision WC.16.11", "vendor": "HPE Aruba",
                               "version": "3"}),
        "10.0.0.10": host("10.0.0.10", "00:15:5d:00:00:10", "Microsoft", [53, 88, 135, 389, 445, 3268, 3389], 128,
                          names={"netbios": {"name": "SRV-AD1", "workgroup": "CORP", "dc": True}}),
        "10.0.0.50": host("10.0.0.50", "3c:52:82:00:00:50", "HP Inc.", [80, 443, 631, 9100], 64),
        "10.0.0.101": host("10.0.0.101", "a4:bb:6d:00:01:01", "Dell", [135, 445], 128, names={"netbios": {"name": "PC-01"}}),
        "10.0.0.102": host("10.0.0.102", "a4:bb:6d:00:01:02", "Dell", [135, 445], 128, names={"netbios": {"name": "PC-02"}}),
        "10.0.0.103": host("10.0.0.103", "a4:bb:6d:00:01:03", "Dell", [135, 445], 128, names={"netbios": {"name": "PC-03"}}),
    }
    for h in hosts.values():
        h.setdefault("smb1", False if 445 in h["ports"] else None)
    sw_ifs = [iface(i, f"{i}", 1000 if i < 20 else 100) for i in range(1, 25)]
    snmp = {
        "10.0.0.1": {"ip": "10.0.0.1", "t": T0, "version": "3", "default_community": False, "credential": "v3 audit (authPriv)",
                     "sys": {"name": "FW-SIEGE", "descr": "FortiGate-60F v7.4.3", "vendor": "Fortinet", "uptime_s": 40 * 86400,
                             "forwarding": True},
                     "interfaces": [iface(1, "wan1"), iface(2, "internal1")], "lldp": [], "cdp": [], "fdb": [], "bridge_ports": {},
                     "arp": [], "entities": [], "storage": []},
        "10.0.0.2": {"ip": "10.0.0.2", "t": T0, "version": "3", "default_community": False, "credential": "v3 audit (authPriv)",
                     "sys": {"name": "SW-CORE", "descr": "Aruba JL260A 2930F-24G-4SFP Switch, revision WC.16.11", "vendor": "HPE Aruba",
                             "uptime_s": 90 * 86400, "forwarding": False},
                     "interfaces": sw_ifs, "lldp": [], "cdp": [], "fdb": [], "bridge_ports": {str(i): i for i in range(1, 25)},
                     "stp": {"top_changes": 12, "since_change_s": 5 * 86400}, "arp": [], "entities": [], "storage": [],
                     "poe": {"power_w": {"1": 370}, "used_w": {"1": 80}}},
    }
    c2 = {ip: {"t": T0 + 60, "if": {str(i["index"]): {k: i[k] for k in ("in_err", "out_err", "in_disc", "out_disc", "fcs")}
                                     for i in d["interfaces"]}} for ip, d in snmp.items()}
    good_ping = {"sent": 20, "received": 20, "loss_pct": 0.0, "avg": 0.6, "max": 1.2, "jitter": 0.1, "ttl": 255}
    inet = {"sent": 15, "received": 15, "loss_pct": 0.0, "avg": 12.0, "max": 14.0, "jitter": 0.5}
    return {
        "app": "test", "started": T0 - 120, "finished": T0 + 60, "options": {"deep": True, "snmp": ["v3 audit (authPriv)"], "ssh": []},
        "steps": {}, "errors": [], "host_name": "PC-AUDIT",
        "local": {"host": {"name": "PC-AUDIT", "domain": "corp.local", "part_of_domain": True},
                  "adapters": [{"index": 7, "desc": "Intel(R) Ethernet I219-LM", "speed": 1_000_000_000, "full_duplex": True, "media": "802.3"}]},
        "networks": [{"network": "10.0.0.0/24", "prefix": 24, "local_ip": "10.0.0.200", "ifindex": 7, "gateway": "10.0.0.1",
                      "dns": ["10.0.0.10"], "dhcp": True, "mac": "aa:bb:cc:dd:ee:ff", "source": "local", "scanned": 253, "alive": 7}],
        "default_gateway": "10.0.0.1", "dns_domain": "corp.local",
        "connect": {"gateway_ping": {"target": "10.0.0.1", **good_ping},
                    "pings": {"1.1.1.1": dict(inet), "8.8.8.8": dict(inet)},
                    "https": {"www.google.com": {"ok": True, "issuer": "Google Trust Services"}},
                    "ncsi": {"ok": True}, "public": {"ok": True, "ip": "203.0.113.7", "isp": ""}, "direct_dns": {"ok": False},
                    "ntp": {"time.windows.com": {"ok": True, "offset_s": 0.02}},
                    "mtu": {"ok": True, "mtu": 1500, "payload": 1472, "target": "1.1.1.1"},
                    "dns": {"10.0.0.10": {"ok": True, "avg_ms": 2.0, "failed": 0, "queries": [{}, {}, {}], "nxdomain": "NXDOMAIN",
                                          "internal": {"has_soa": True}, "ad_dc": ["srv-ad1.corp.local"]},
                            "10.0.0.11": {"ok": True, "avg_ms": 3.0, "failed": 0, "queries": [{}, {}, {}], "nxdomain": "NXDOMAIN",
                                          "internal": {"has_soa": True}, "ad_dc": ["srv-ad1.corp.local"]}}},
        "hosts": hosts, "snmp": snmp, "snmp_counters2": c2, "ssh": {},
        "dhcp": {"10.0.0.0/24": {"ok": True, "offers": [{"source": "10.0.0.10", "server_id": "10.0.0.10", "offered_ip": "10.0.0.150",
                                                          "router": ["10.0.0.1"], "dns": ["10.0.0.10"], "lease": 8 * 3600}]}},
        "ifstats_a": {"7": {"t": T0, "alias": "Ethernet", **{k: 0 for k in ("InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards",
                                                                           "InErrors", "InUnknownProtos", "InMulticastOctets",
                                                                           "InBroadcastOctets", "OutOctets", "OutUcastPkts",
                                                                           "OutNUcastPkts", "OutDiscards", "OutErrors")}}},
        "ifstats_b": None, "mdns_elsewhere": {}, "other_networks": {},
    }


def with_b(s: dict, bcast_bps: float = 2000.0, nucast_pps: float = 5.0, errors: int = 0) -> dict:
    a = s["ifstats_a"]["7"]
    b = dict(a)
    b["t"] = a["t"] + 30
    b["InBroadcastOctets"] = int(bcast_bps * 30)
    b["InNUcastPkts"] = int(nucast_pps * 30)
    b["InErrors"] = errors
    s["ifstats_b"] = {"7": b}
    return s


def healthy() -> dict:
    return with_b(base())


def clone(s):
    return copy.deepcopy(s)


_ = time
