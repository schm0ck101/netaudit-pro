"""Règles d'analyse sur des réseaux simulés variés (constructeurs, AD,
pannes) : chaque problème doit être détecté, et un réseau sain ne doit rien
signaler d'important."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("NETAUDIT_DATA_DIR", str(Path(os.environ.get("TEMP", "/tmp")) / "netaudit-tests"))

from netaudit.analyze.engine import analyze  # noqa: E402
from netaudit.analyze.model import CRIT, MAJOR, MINOR  # noqa: E402

from fixtures import clone, healthy, iface, host  # noqa: E402


def ids(a, min_sev=MINOR):
    return {f.id.split(".")[0] + "." + f.id.split(".")[1] + ("." + f.id.split(".")[2] if f.id.count(".") >= 2 else ""): f.severity
            for f in a.findings if f.severity >= min_sev}


def find(a, prefix):
    return [f for f in a.findings if f.id.startswith(prefix)]


def test_healthy_network_has_no_major_problem():
    a = analyze(healthy())
    assert not a.rule_errors, a.rule_errors
    bad = [(f.id, f.title) for f in a.findings if f.severity >= MAJOR]
    assert not bad, bad
    assert a.scores["global"] >= 85
    assert a.hosts["10.0.0.10"]["kind"] == "server"
    assert a.hosts["10.0.0.2"]["kind"] == "switch"
    assert a.hosts["10.0.0.1"]["kind"] == "router"
    assert a.hosts["10.0.0.50"]["kind"] == "printer"


def test_two_dhcp_servers_is_critical():
    s = healthy()
    s["dhcp"]["10.0.0.0/24"]["offers"].append({"source": "10.0.0.77", "server_id": "192.168.1.1", "offered_ip": "192.168.1.20",
                                                "router": ["192.168.1.1"], "dns": ["192.168.1.1"], "lease": 86400})
    f = find(analyze(s), "svc.dhcp.multi")
    assert f and f[0].severity == CRIT


def test_dhcp_not_tested_in_quick_mode_is_reported_not_checked():
    s = healthy()
    s["dhcp"] = None
    a = analyze(s)
    assert any(f.id == "svc.dhcp.test" and f.severity == -1 for f in a.findings)


def test_dead_dns_and_public_dns_in_ad_domain():
    s = healthy()
    s["connect"]["dns"]["10.0.0.11"] = {"ok": False, "queries": [{}, {}, {}], "failed": 3}
    s["connect"]["dns"]["8.8.8.8"] = {"ok": True, "avg_ms": 15, "failed": 0, "queries": [{}], "internal": {"has_soa": False}}
    a = analyze(s)
    assert find(a, "svc.dns.partial")[0].severity == MAJOR
    assert find(a, "svc.dns.ad_public")[0].severity == MAJOR


def test_all_dns_dead_is_critical():
    s = healthy()
    for r in s["connect"]["dns"].values():
        r.update(ok=False, avg_ms=None)
    assert find(analyze(s), "svc.dns.down")[0].severity == CRIT


def test_internet_down_and_gateway_loss():
    s = healthy()
    for p in s["connect"]["pings"].values():
        p.update(received=0, loss_pct=100.0, avg=None)
    s["connect"]["https"]["www.google.com"] = {"ok": False, "error": "timeout"}
    s["connect"]["gateway_ping"].update(received=17, loss_pct=15.0)
    a = analyze(s)
    assert find(a, "svc.inet.down")[0].severity == CRIT
    assert find(a, "svc.gw.loss")[0].severity == MAJOR
    assert a.scores["global"] <= 49


def test_clock_skew_breaks_kerberos():
    s = healthy()
    s["connect"]["ntp"]["time.windows.com"]["offset_s"] = 420.0
    assert find(analyze(s), "svc.ntp.skew")[0].severity == CRIT


def test_cisco_switch_problems():
    s = healthy()
    sw = s["snmp"]["10.0.0.2"]
    sw["sys"].update(descr="Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE", vendor="Cisco")
    s["hosts"]["10.0.0.2"]["snmp"]["descr"] = sw["sys"]["descr"]
    ifs = sw["interfaces"]
    ifs[2].update(duplex="half", mbps=100, late_coll=5400)                   # duplex mismatch
    ifs[3].update(in_err=1500)                                               # erreurs qui augmentent pendant le diagnostic
    s["snmp_counters2"]["10.0.0.2"]["if"]["4"]["in_err"] = 1580
    ifs[4].update(mbps=100)                                                  # lien vers une borne en 100 Mb/s (LLDP)
    sw["lldp"] = [{"local_port": "5", "local_port_num": "5", "sys_name": "AP-ETAGE", "caps": ["borne Wi-Fi"], "port": "eth0"}]
    sw["stp"] = {"top_changes": 9000, "since_change_s": 120}
    sw["poe"] = {"power_w": {"1": 370}, "used_w": {"1": 355}}
    sw["default_community"] = True
    sw["version"] = "2c"
    a = analyze(s)
    got = {f.id: f.severity for f in a.findings}
    assert got.get("lan.duplex.10.0.0.2") == MAJOR
    assert got.get("lan.err.live.10.0.0.2") == MAJOR
    assert got.get("lan.100m.10.0.0.2") == MAJOR
    assert got.get("lan.stp.10.0.0.2") == MAJOR
    assert got.get("lan.poe.10.0.0.2.1") == MAJOR
    assert got.get("sec.snmp.public") == MAJOR
    assert got.get("lan.eol") == MAJOR                       # Catalyst 2960 (non X/S)


def test_uplink_at_100_without_lldp_detected_from_mac_table():
    s = healthy()
    sw = s["snmp"]["10.0.0.2"]
    sw["interfaces"][7].update(mbps=100)
    sw["fdb"] = [{"vlan": "1", "mac": f"00:11:22:33:44:{i:02x}", "bridge_port": 8} for i in range(12)]
    assert find(analyze(s), "lan.100m")


def test_historic_errors_vs_live():
    s = healthy()
    sw = s["snmp"]["10.0.0.2"]
    sw["interfaces"][0].update(in_err=250_000, in_oct=50 * 10**9)
    s["snmp_counters2"]["10.0.0.2"]["if"]["1"]["in_err"] = 250_000
    a = analyze(s)
    assert find(a, "lan.err.hist")[0].severity == MINOR
    assert not find(a, "lan.err.live")


def test_virtual_interfaces_are_ignored():
    s = healthy()
    sw = s["snmp"]["10.0.0.2"]
    sw["interfaces"] += [iface(100, "docker0", 10, duplex="half", in_err=10**6), iface(101, "br-1234", 10, in_err=10**6),
                         iface(102, "veth12ab", 10)]
    s["snmp_counters2"]["10.0.0.2"]["if"]["100"] = {"in_err": 2 * 10**6}
    a = analyze(s)
    assert not find(a, "lan.duplex") and not find(a, "lan.err") and not find(a, "lan.10m")


def test_ssh_logs_loop_and_macflap():
    from netaudit.net import ssh
    procurve_log = ("I 11/20/26 08:12:01 00077 ports: port 12 is now off-line\n"
                    "W 11/20/26 08:12:03 00332 loop-protect: port 12 disabled - loop detected\n"
                    "W 11/20/26 08:15:44 00436 FFI: port 7-Excessive CRC/alignment errors. See help.\n")
    cisco_log = ("%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 10 is flapping between port Gi0/3 and port Gi0/7\n"
                 "%PM-4-ERR_DISABLE: bpduguard error detected on Gi0/5, putting Gi0/5 in err-disable state\n"
                 "%CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on GigabitEthernet0/2 (not half duplex)\n")
    s = healthy()
    s["options"]["ssh"] = ["admin"]
    s["ssh"] = {"10.0.0.2": {"ok": True, "profile": "procurve", "outputs": {"show logging -r": procurve_log}},
                "10.0.0.3": {"ok": True, "profile": "cisco-ios", "outputs": {"show logging": cisco_log}}}
    for r in s["ssh"].values():
        r["events"] = ssh.scan_logs(r["outputs"])
    assert set(s["ssh"]["10.0.0.2"]["events"]) >= {"loop", "crc"}
    assert set(s["ssh"]["10.0.0.3"]["events"]) >= {"mac_flap", "err_disabled", "duplex"}
    a = analyze(s)
    assert find(a, "lan.logs.loop")[0].severity == CRIT
    assert find(a, "lan.logs.mac_flap")[0].severity == CRIT


def test_broadcast_storm_and_audit_pc_link():
    from fixtures import with_b, base
    s = with_b(base(), bcast_bps=3_000_000, nucast_pps=8000)
    s["local"]["adapters"][0].update(speed=100_000_000, full_duplex=False)
    a = analyze(s)
    assert find(a, "perf.bcast.storm")[0].severity == CRIT
    assert find(a, "perf.audit.half")[0].severity == MAJOR
    assert find(a, "perf.audit.speed")


def test_exposed_services_and_smb1():
    s = healthy()
    s["hosts"]["10.0.0.2"]["ports"].append(23)                      # Telnet sur un switch
    s["hosts"]["10.0.0.10"]["smb1"] = True                          # SMBv1 sur le contrôleur de domaine
    s["hosts"]["10.0.0.60"] = host("10.0.0.60", "00:50:56:00:00:60", "VMware", [22, 2375], 64)
    a = analyze(s)
    got = {f.id: f.severity for f in a.findings}
    assert got["sec.port.23"] == CRIT
    assert got["sec.port.2375"] == CRIT
    assert got["sec.smb1"] == CRIT


def test_flat_network_with_cameras_and_iot():
    s = healthy()
    for i in range(6):
        s["hosts"][f"10.0.0.{150 + i}"] = host(f"10.0.0.{150 + i}", f"c0:56:e3:00:00:{i:02x}", "Hikvision", [80, 554, 8000])
    for i in range(3):
        s["hosts"][f"10.0.0.{170 + i}"] = host(f"10.0.0.{170 + i}", f"24:0a:c4:00:00:{i:02x}", "Espressif", [80])
    f = find(analyze(s), "sec.flat")
    assert f and f[0].severity == MAJOR


def test_honeypot_is_recognised_and_excluded():
    s = healthy()
    s["hosts"]["10.0.0.254"] = host("10.0.0.254", s["hosts"]["10.0.0.1"]["mac"], "Fortinet", [21, 22, 23, 25, 445, 1433])
    a = analyze(s)
    assert a.hosts["10.0.0.254"]["kind"] == "honeypot"
    assert not find(a, "sec.port.23")


def test_network_almost_full():
    s = healthy()
    s["networks"][0]["network"] = "10.0.0.0/27"
    for i in range(11, 30):
        s["hosts"][f"10.0.0.{i}"] = host(f"10.0.0.{i}", f"00:00:00:00:01:{i:02x}", "", [], network="10.0.0.0/27")
    for h in s["hosts"].values():
        h["network"] = "10.0.0.0/27"
    assert find(analyze(s), "svc.addr.full")


def test_new_devices_against_previous_audit():
    prev = healthy()
    s = clone(prev)
    s["hosts"]["10.0.0.120"] = host("10.0.0.120", "de:ad:be:ef:00:01", "", [])
    f = find(analyze(s, prev), "sec.new")
    assert f and "10.0.0.120" in f[0].evidence[0]


def test_empty_and_partial_snapshots_do_not_crash():
    for snap in ({}, {"hosts": {}}, {"networks": [], "connect": {}}, {"snmp": {"1.2.3.4": {}}, "hosts": {"1.2.3.4": {"ip": "1.2.3.4"}}}):
        a = analyze(snap)
        assert not a.rule_errors, a.rule_errors
