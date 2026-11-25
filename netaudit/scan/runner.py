"""Orchestration du diagnostic : enchaîne les étapes, produit l'instantané
(dictionnaire JSON) qui sera analysé et archivé.

Aucune hypothèse sur le réseau du client : plages, constructeurs, présence
ou non de DHCP / DNS / SNMP sont découverts. Les identifiants saisis ne sont
JAMAIS écrits dans l'instantané (seulement un libellé masqué).
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .. import config
from ..net import arp, dhcp, icmp, ifstats, local, names, oui, ports, snmp, snmpdev, ssh, tests

log = logging.getLogger(__name__)

STEPS = [("local", "Configuration du poste d'audit"), ("connect", "Passerelle, Internet, DNS et heure"),
         ("discover", "Découverte des appareils"), ("names", "Identification (noms, services annoncés)"),
         ("ports", "Ports et services ouverts"), ("snmp", "Équipements interrogés en SNMP"),
         ("ssh", "Équipements interrogés en SSH"), ("dhcp", "Serveurs DHCP"), ("final", "Mesures de stabilité (2e relevé)")]
STEP_LABELS = dict(STEPS)

MAX_HOSTS_PER_NET = 4096        # au-delà (/19 et plus grand) : on analyse le /22 du poste
TCP_PING_PORTS = [80, 443, 22, 445, 3389, 8080, 53, 9100]


@dataclass
class Options:
    deep: bool = False
    extra_ranges: list[str] = field(default_factory=list)      # « 10.0.20.0/24 », « 10.0.30.10-10.0.30.50 »
    exclude: list[str] = field(default_factory=list)
    snmp_creds: list[snmp.Credential] = field(default_factory=list)
    snmp_try_public: bool = True
    ssh_creds: list[ssh.SshCred] = field(default_factory=list)
    ssh_targets: list[str] = field(default_factory=list)       # IP à interroger en SSH en plus des équipements réseau détectés
    skip_internet: bool = False

    def public(self) -> dict:
        """Ce qui est conservé dans l'instantané (sans secret)."""
        return {"deep": self.deep, "extra_ranges": self.extra_ranges, "exclude": self.exclude,
                "snmp": [c.label() for c in self.snmp_creds], "snmp_try_public": self.snmp_try_public,
                "ssh": [c.label() for c in self.ssh_creds], "ssh_targets": self.ssh_targets}


class Cancelled(Exception):
    pass


def parse_ranges(items: list[str]) -> tuple[list[ipaddress.IPv4Network], list[tuple[int, int]], list[str]]:
    """Plages saisies : CIDR, adresse seule, « a-b » (complet ou dernier octet). Renvoie (réseaux, intervalles, erreurs)."""
    nets, spans, errs = [], [], []
    for raw in items:
        s = raw.strip()
        if not s:
            continue
        try:
            if "-" in s:
                a, b = (x.strip() for x in s.split("-", 1))
                ia = ipaddress.IPv4Address(a)
                ib = ipaddress.IPv4Address(b) if "." in b else ipaddress.IPv4Address(".".join(a.split(".")[:3] + [b]))
                if int(ib) < int(ia):
                    ia, ib = ib, ia
                spans.append((int(ia), int(ib)))
            else:
                nets.append(ipaddress.IPv4Network(s, strict=False))
        except ValueError:
            errs.append(s)
    return nets, spans, errs


def _excluded(exclude: list[str]):
    nets, spans, _e = parse_ranges(exclude)

    def test(ip: str) -> bool:
        a = ipaddress.IPv4Address(ip)
        return any(a in n for n in nets) or any(lo <= int(a) <= hi for lo, hi in spans)
    return test


class Runner:
    def __init__(self, opts: Options, progress=None, cancel: threading.Event | None = None):
        self.o = opts
        self.cancel = cancel or threading.Event()
        self._progress = progress
        self.snap: dict = {"app": f"{config.APP_NAME} {config.APP_VERSION}", "started": time.time(),
                           "options": opts.public(), "steps": {}, "errors": []}
        self.hosts: dict[str, dict] = {}
        self.is_excluded = _excluded(opts.exclude)

    # ---------------------------------------------------------------- outils
    def progress(self, step: str, state: str, detail: str = ""):
        if self._progress:
            try:
                self._progress(step, STEP_LABELS.get(step, step), state, detail)
            except Exception:
                log.exception("progression")

    def check(self):
        if self.cancel.is_set():
            raise Cancelled()

    def host(self, ip: str) -> dict:
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = {"ip": ip, "seen_by": [], "mac": None, "ports": [], "names": {}}
        return h

    def step(self, key: str, fn):
        self.check()
        self.progress(key, "start")
        t0 = time.monotonic()
        detail = ""
        try:
            detail = fn() or ""
        except Cancelled:
            raise
        except Exception as exc:
            log.exception("Étape %s", key)
            self.snap["errors"].append(f"{STEP_LABELS.get(key, key)} : {exc}")
            detail = f"erreur : {exc}"
            self.snap["steps"][key] = {"seconds": round(time.monotonic() - t0, 1), "error": str(exc)}
            self.progress(key, "error", detail)
            return
        self.snap["steps"][key] = {"seconds": round(time.monotonic() - t0, 1), "detail": detail}
        self.progress(key, "skip" if detail == "non demandé" else "done", detail)

    # ----------------------------------------------------------------- étapes
    def run(self) -> dict:
        try:
            self.step("local", self.s_local)
            self.step("connect", self.s_connect)
            self.step("discover", self.s_discover)
            self.step("names", self.s_names)
            self.step("ports", self.s_ports)
            self.step("snmp", self.s_snmp)
            self.step("ssh", self.s_ssh)
            self.step("dhcp", self.s_dhcp)
            self.step("final", self.s_final)
        finally:
            self.snap["hosts"] = self.hosts
            self.snap["finished"] = time.time()
        return self.snap

    def s_local(self):
        self.snap["ifstats_a"] = ifstats.snapshot()
        loc = local.collect(self.cancel)
        self.snap["local"] = loc
        nets = local.networks(loc)
        nets_x, spans_x, bad = parse_ranges(self.o.extra_ranges)
        if bad:
            self.snap["errors"].append("Plages ignorées (format non reconnu) : " + ", ".join(bad))
        known = {n["network"] for n in nets}
        for n in nets_x:
            if str(n) not in known and not any(ipaddress.IPv4Network(k).overlaps(n) for k in known):
                nets.append({"network": str(n), "prefix": n.prefixlen, "source": "added"})
        for lo, hi in spans_x:
            nets.append({"network": f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}", "span": [lo, hi],
                         "source": "added"})
        self.snap["networks"] = nets
        self.snap["default_gateway"] = local.default_gateway(loc)
        self.snap["host_name"] = (loc.get("host") or {}).get("name") or socket.gethostname()
        return f"{len(nets)} réseau(x) : " + ", ".join(n["network"] for n in nets)

    def s_connect(self):
        gw = self.snap.get("default_gateway")
        if self.o.skip_internet:
            res = {"gateway_ping": tests.ping_series(gw, 20, 0.2, 1000, 32, self.cancel) if gw else None}
        else:
            res = tests.internet_tests(gw, self.cancel)
        self.check()
        # passerelles des autres réseaux locaux
        res["other_gateways"] = {}
        for n in self.snap.get("networks", []):
            g = n.get("gateway")
            if g and g != gw:
                res["other_gateways"][g] = tests.ping_series(g, 10, 0.2, 1000, 32, self.cancel)
        dns_servers, domain = [], ""
        for n in self.snap.get("networks", []):
            for d in n.get("dns") or []:
                if d not in dns_servers and ":" not in d:
                    dns_servers.append(d)
            domain = domain or n.get("domain") or ""
        h = (self.snap.get("local") or {}).get("host") or {}
        if h.get("part_of_domain"):
            domain = h.get("domain") or domain
        self.snap["dns_domain"] = domain
        res["dns"] = tests.dns_server_tests(dns_servers, domain, self.cancel) if dns_servers else {}
        self.snap["connect"] = res
        g = res.get("gateway_ping") or {}
        parts = []
        if gw:
            parts.append(f"passerelle {gw} : {g.get('loss_pct', '?')} % de pertes")
        if not self.o.skip_internet:
            ok = sum(1 for p in res.get("pings", {}).values() if p.get("received"))
            parts.append(f"Internet {'joignable' if ok else 'injoignable'}")
        parts.append(f"{len(res['dns'])} serveur(s) DNS testé(s)")
        return " · ".join(parts)

    def _targets(self, n: dict) -> tuple[list[str], bool, str]:
        """(adresses, réseau local ?, remarque)."""
        if n.get("span"):
            lo, hi = n["span"]
            ips = [str(ipaddress.IPv4Address(i)) for i in range(lo, min(hi, lo + MAX_HOSTS_PER_NET - 1) + 1)]
            return ips, False, "" if hi - lo < MAX_HOSTS_PER_NET else "plage tronquée"
        net = ipaddress.IPv4Network(n["network"])
        note = ""
        if net.num_addresses - 2 > MAX_HOSTS_PER_NET:
            if n.get("local_ip"):
                net = ipaddress.IPv4Network(f"{n['local_ip']}/22", strict=False)
            else:
                net = ipaddress.IPv4Network(f"{net.network_address}/22")
            note = f"réseau trop grand : seul {net} est analysé"
        ips = [str(i) for i in net.hosts()] if net.prefixlen < 31 else [str(i) for i in net]
        return ips, n.get("source") == "local", note

    def s_discover(self):
        own = {n.get("local_ip") for n in self.snap.get("networks", []) if n.get("local_ip")}
        total = 0
        notes = []
        for n in self.snap.get("networks", []):
            self.check()
            ips, is_local, note = self._targets(n)
            if note:
                notes.append(note)
                n["note"] = note
            ips = [i for i in ips if i not in own and not self.is_excluded(i)]
            n["scanned"] = len(ips)
            self.progress("discover", "info", f"{n['network']} : {len(ips)} adresses")
            found = self._sweep(ips, is_local, n.get("local_ip"))
            for ip, how in found.items():
                h = self.host(ip)
                h["network"] = n["network"]
                h["local_net"] = is_local
                for k, v in how.items():
                    if k == "via":
                        for x in v:
                            if x not in h["seen_by"]:
                                h["seen_by"].append(x)
                    elif v is not None and h.get(k) in (None, "", []):
                        h[k] = v
            n["alive"] = len(found)
            total += len(found)
        # cache ARP (appareils muets entre-temps vus par Windows)
        cache = arp.arp_table()
        self.snap["arp_cache"] = cache
        nets = [(ipaddress.IPv4Network(n["network"]), n) for n in self.snap["networks"] if not n.get("span")]
        for e in cache:
            if e["type"] not in ("dynamique", "statique") or e["ip"] in own or self.is_excluded(e["ip"]):
                continue
            a = ipaddress.IPv4Address(e["ip"])
            if a.is_multicast or str(a).endswith(".255"):
                continue
            for net, n in nets:
                if a in net and n.get("source") == "local" and a not in (net.network_address, net.broadcast_address):
                    h = self.host(e["ip"])
                    h.setdefault("network", n["network"])
                    h["local_net"] = True
                    if not h.get("mac"):
                        h["mac"] = e["mac"]
                    if "arp-cache" not in h["seen_by"]:
                        h["seen_by"].append("arp-cache")
        # ARP ciblé, au calme, pour les appareils joignables dont la MAC manque encore
        miss = [(ip, n.get("local_ip")) for ip, h in self.hosts.items() if h.get("local_net") and not h.get("mac")
                for n in self.snap["networks"] if n["network"] == h.get("network")]
        if miss:
            with ThreadPoolExecutor(8) as ex:
                for (ip, _s), m in zip(miss, ex.map(lambda t: arp.send_arp(*t), miss)):
                    if m:
                        self.hosts[ip]["mac"] = m
        for h in self.hosts.values():
            if h.get("mac"):
                h["vendor"] = oui.vendor(h["mac"])
                h["random_mac"] = oui.is_random(h["mac"])
        return f"{len(self.hosts)} appareil(s) trouvé(s)" + (f" ({'; '.join(notes)})" if notes else "")

    def _sweep(self, ips: list[str], is_local: bool, src: str | None) -> dict[str, dict]:
        found: dict[str, dict] = {}
        lock = threading.Lock()
        timeout = 900 if self.o.deep else 700

        def mark(ip, via, **kw):
            with lock:
                e = found.setdefault(ip, {"via": []})
                if via not in e["via"]:
                    e["via"].append(via)
                for k, v in kw.items():
                    if v is not None and e.get(k) is None:
                        e[k] = v

        def ping(ip):
            if self.cancel.is_set():
                return
            for _ in range(2 if self.o.deep else 1):
                r = icmp.probe(ip, timeout_ms=timeout)
                if r.reached:
                    mark(ip, "icmp", rtt=r.rtt, ttl=r.ttl)
                    return

        def arpq(ip):
            if self.cancel.is_set():
                return
            m = arp.send_arp(ip, src)
            if m:
                mark(ip, "arp", mac=m)

        def tcp(ip):
            if self.cancel.is_set() or ip in found:
                return
            for p in TCP_PING_PORTS:
                if ports.tcp_open(ip, p, 0.6):
                    mark(ip, "tcp", first_port=p)
                    return

        with ThreadPoolExecutor(128) as ex:
            jobs = [ex.submit(ping, ip) for ip in ips]
            if is_local:
                jobs += [ex.submit(arpq, ip) for ip in ips]
            for j in jobs:
                j.result()
        self.check()
        if not is_local:          # au-delà d'un routeur : appareils qui ignorent le ping
            with ThreadPoolExecutor(128) as ex:
                list(ex.map(tcp, [i for i in ips if i not in found]))
        return found

    def s_names(self):
        ips = sorted(self.hosts, key=_ipkey)
        # UNE adresse source par carte (celle qui a une passerelle de préférence) : un répondeur mDNS
        # ne répond qu'une fois par seconde à une même question (RFC 6762), une 2e adresse sur la même
        # carte « consommerait » la réponse.
        per_if: dict = {}
        for n in sorted(self.snap.get("networks", []), key=lambda n: not n.get("gateway")):
            if n.get("local_ip") and n.get("ifindex") not in per_if:
                per_if[n.get("ifindex")] = n["local_ip"]
        lips = list(per_if.values())
        dns_servers = [s for s in (self.snap.get("connect", {}).get("dns") or {}) if
                       (self.snap["connect"]["dns"][s] or {}).get("ok")]
        with ThreadPoolExecutor(4) as ex:
            f_nb = ex.submit(names.netbios, ips, 2.5, self.cancel)
            f_md = ex.submit(names.mdns, lips, ips, 3.0, self.cancel)
            f_ss = ex.submit(names.ssdp, lips, 3.0, True, self.cancel)
            f_rd = ex.submit(names.reverse_dns, ips, dns_servers, 1.5, self.cancel)
            nb, md, ss, rd = f_nb.result(), f_md.result(), f_ss.result(), f_rd.result()
        self.check()
        elsewhere = {}
        for ip, e in nb.items():
            if ip in self.hosts:
                self.hosts[ip]["names"]["netbios"] = e
        for ip, e in md.items():
            if ip in self.hosts:
                self.hosts[ip]["names"]["mdns"] = e
            else:
                elsewhere[ip] = e         # annoncé via un relais mDNS : autre réseau / VLAN
        for ip, e in ss.items():
            if ip in self.hosts:
                self.hosts[ip]["names"]["ssdp"] = e
            elif not self.is_excluded(ip):
                elsewhere.setdefault(ip, {})["ssdp"] = e
        for ip, n in rd.items():
            self.hosts[ip]["names"]["dns"] = n
        self.snap["mdns_elsewhere"] = elsewhere
        return (f"DNS {len(rd)} · NetBIOS {len(nb)} · mDNS {sum(1 for i in md if i in self.hosts)} · "
                f"UPnP {sum(1 for i in ss if i in self.hosts)}" + (f" · {len(elsewhere)} annoncé(s) depuis d'autres réseaux" if elsewhere else ""))

    def s_ports(self):
        plist = ports.PORTS_DEEP if self.o.deep else ports.PORTS_QUICK
        ips = sorted(self.hosts, key=_ipkey)
        local_ips = [i for i in ips if self.hosts[i].get("local_net")]
        remote = [i for i in ips if not self.hosts[i].get("local_net")]

        def prog(done, total):
            self.progress("ports", "info", f"{done} / {total} tests")
        res = ports.scan(local_ips, plist, 0.8, 256, self.cancel, prog)
        if remote:
            res.update(ports.scan(remote, plist, 1.5, 256, self.cancel, prog))
        self.check()
        for ip, ps in res.items():
            self.hosts[ip]["ports"] = ps
        extra = ports.enrich({i: p for i, p in res.items() if p}, self.o.deep, self.cancel)
        for ip, e in extra.items():
            self.hosts[ip].update(e)
        n_open = sum(len(p) for p in res.values())
        return f"{len(plist)} ports testés sur {len(ips)} appareil(s) : {n_open} ouvert(s)"

    def s_snmp(self):
        creds = list(self.o.snmp_creds)
        if self.o.snmp_try_public and not any(c.version in ("1", "2c") and c.community == "public" for c in creds):
            creds.append(snmp.Credential("2c", "public"))
        if not creds:
            return "non demandé"
        ips = sorted(self.hosts, key=_ipkey)
        found = {}

        def pr(ip):
            r = snmp.probe(ip, creds, timeout=1.0 if self.hosts[ip].get("local_net") else 2.0, cancel=self.cancel)
            return ip, r
        with ThreadPoolExecutor(48) as ex:
            for ip, r in ex.map(pr, ips):
                if r:
                    found[ip] = r
        self.check()
        devices = {}
        user_given = {c.label() for c in self.o.snmp_creds}

        def coll(item):
            ip, (cred, _descr, _oid, _name) = item
            if self.cancel.is_set():
                return ip, None, cred
            try:
                with snmp.Session(ip, cred, timeout=2.0, retries=1) as s:
                    return ip, snmpdev.collect(s, cred.label(), self.o.deep, 150 if self.o.deep else 75), cred
            except Exception as exc:
                log.exception("SNMP %s", ip)
                return ip, {"ip": ip, "error": str(exc)}, cred
        with ThreadPoolExecutor(6) as ex:
            for ip, dev, cred in ex.map(coll, found.items()):
                if dev is None:
                    continue
                dev["default_community"] = cred.version in ("1", "2c") and cred.community in ("public", "private") \
                    and cred.label() not in user_given
                dev["version"] = cred.version
                devices[ip] = dev
                self.hosts[ip]["snmp"] = {"name": dev.get("sys", {}).get("name"), "descr": dev.get("sys", {}).get("descr"),
                                          "vendor": dev.get("sys", {}).get("vendor"), "version": cred.version,
                                          "default_community": dev["default_community"]}
        self.snap["snmp"] = devices
        self._snmp_creds_ok = {ip: c for ip, (c, *_r) in found.items()}
        self.snap["snmp_t1"] = time.time()
        # Table ARP des PASSERELLES (routeur, pare-feu, switch de niveau 3) : MAC manquantes, appareils
        # muets ou en veille (vus récemment par le routeur), réseaux non analysés.
        # (Les autres équipements sont ignorés : un serveur Linux avec Docker « route » aussi.)
        gws = {n.get("gateway") for n in self.snap["networks"] if n.get("gateway")} | {self.snap.get("default_gateway")}
        seen_nets = {}
        own_nets = [(ipaddress.IPv4Network(n["network"]), n) for n in self.snap["networks"] if not n.get("span")]
        own_ips = {n.get("local_ip") for n in self.snap["networks"]}
        passive = 0
        for gip, dev in devices.items():
            if gip not in gws:
                continue
            per_if: dict = {}
            for a in dev.get("arp") or []:
                per_if.setdefault((a["ifindex"], a["ip"]), set()).add(a["mac"])
            for a in dev.get("arp") or []:
                try:
                    ip = ipaddress.IPv4Address(a["ip"])
                except ValueError:
                    continue
                if ip.is_link_local or ip.is_multicast or a["mac"] in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue
                net = next((n for nn, n in own_nets if ip in nn), None)
                if net is None:
                    if ip.is_private:
                        key = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                        seen_nets.setdefault(key, set()).add(str(ip))
                    continue
                if a["ip"] in own_ips or self.is_excluded(a["ip"]):
                    continue
                h = self.hosts.get(a["ip"])
                if h is None:
                    h = self.host(a["ip"])
                    h.update(network=net["network"], local_net=net.get("source") == "local", inactive=True)
                    passive += 1
                if not h.get("mac"):
                    h["mac"] = a["mac"]
                    h["vendor"] = oui.vendor(a["mac"])
                    h["random_mac"] = oui.is_random(a["mac"])
                if "arp-routeur" not in h["seen_by"]:
                    h["seen_by"].append("arp-routeur")
        self.snap["other_networks"] = {k: len(v) for k, v in sorted(seen_nets.items(), key=lambda kv: _ipkey(kv[0].split("/")[0]))}
        self.snap["passive_hosts"] = passive
        return f"{len(devices)} équipement(s) répondent" + (f" · {len(seen_nets)} autre(s) réseau(x) repéré(s)" if seen_nets else "")

    def s_ssh(self):
        if not self.o.ssh_creds:
            return "non demandé"
        import copy

        from ..analyze.classify import NETWORK_GEAR, classify
        gws = {n.get("gateway") for n in self.snap.get("networks", []) if n.get("gateway")} | {self.snap.get("default_gateway")}
        gmacs = {self.hosts[g].get("mac") for g in gws if g in self.hosts and self.hosts[g].get("mac")}
        targets = []
        for ip, h in self.hosts.items():
            if 22 not in (h.get("ports") or []):
                continue
            snmpd = (self.snap.get("snmp") or {}).get(ip, {}).get("sys", {})
            banner = (h.get("banners") or {}).get("22", "")
            prof = ssh.guess_profile(snmpd.get("descr", ""), banner, snmpd.get("object_id", ""))
            # équipement réseau d'après la classification (routeurs / bornes sous Linux compris)
            kind = classify(copy.deepcopy(h), gws, gmacs).get("kind")
            if ip in self.o.ssh_targets or kind in NETWORK_GEAR:
                targets.append((ip, prof or "linux"))
        res = {}

        def one(t):
            ip, prof = t
            last = None
            for c in self.o.ssh_creds:
                if self.cancel.is_set():
                    break
                r = ssh.run(ip, c, prof)
                if r.get("ok"):
                    r["credential"] = c.label()
                    r["events"] = ssh.scan_logs(r.get("outputs", {}))
                    return ip, r
                last = r
                if r.get("error") != "authentification refusée":
                    break
            return ip, last or {"ok": False, "error": "aucun identifiant"}
        with ThreadPoolExecutor(4) as ex:
            for ip, r in ex.map(one, targets):
                res[ip] = r
        self.snap["ssh"] = res
        ok = sum(1 for r in res.values() if r.get("ok"))
        return f"{ok} / {len(res)} équipement(s) interrogé(s)" if res else "aucun équipement réseau avec SSH ouvert"

    def s_dhcp(self):
        if not self.o.deep:
            return "non demandé"
        out, done_if = {}, set()
        for n in sorted(self.snap.get("networks", []), key=lambda n: not n.get("gateway")):
            if n.get("source") != "local" or n.get("ifindex") in done_if or not n.get("mac"):
                continue
            done_if.add(n.get("ifindex"))
            out[n["network"]] = dhcp.discover(n["local_ip"], n["mac"])
        self.snap["dhcp"] = out
        servers = {o.get("server_id") or o.get("source") for r in out.values() for o in r.get("offers", [])}
        return f"{len(servers)} serveur(s) DHCP ont répondu"

    def s_final(self):
        # au moins 20 s entre les deux relevés de compteurs
        t_a = min((x.get("t", 0) for x in (self.snap.get("ifstats_a") or {}).values()), default=time.time())
        wait = 20 - (time.time() - t_a)
        while wait > 0 and not self.cancel.is_set():
            time.sleep(min(1, wait))
            wait -= 1
        self.snap["ifstats_b"] = ifstats.snapshot()
        c2 = {}
        creds = getattr(self, "_snmp_creds_ok", {})

        def one(ip):
            try:
                with snmp.Session(ip, creds[ip], timeout=2.0, retries=1) as s:
                    return ip, snmpdev.counters(s)
            except Exception as exc:
                return ip, {"error": str(exc)}
        with ThreadPoolExecutor(8) as ex:
            for ip, r in ex.map(one, [i for i in (self.snap.get("snmp") or {}) if i in creds]):
                c2[ip] = r
        self.snap["snmp_counters2"] = c2
        return f"compteurs relevés à nouveau ({len(c2)} équipement(s) SNMP)"


def _ipkey(ip: str):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0


def collect(opts: Options, progress=None, cancel: threading.Event | None = None) -> dict:
    return Runner(opts, progress, cancel).run()
