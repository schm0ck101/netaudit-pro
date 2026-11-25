"""Tests de connectivité : passerelle, Internet, DNS, MTU, accès web, IP
publique, heure (SNTP)."""
from __future__ import annotations

import socket
import ssl
import statistics
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import dnsmsg, icmp


def ping_series(ip: str, count: int = 20, interval: float = 0.2, timeout_ms: int = 1000, size: int = 32,
                cancel: threading.Event | None = None) -> dict:
    rtts, ttl, sent = [], None, 0
    for i in range(count):
        if cancel and cancel.is_set():
            break
        t0 = time.monotonic()
        r = icmp.probe(ip, timeout_ms=timeout_ms, size=size)
        sent += 1
        if r.reached and r.rtt is not None:
            rtts.append(r.rtt)
            ttl = r.ttl
        wait = interval - (time.monotonic() - t0)
        if wait > 0 and i < count - 1:
            time.sleep(wait)
    out = {"target": ip, "sent": sent, "received": len(rtts), "loss_pct": round(100 * (1 - len(rtts) / sent), 1) if sent else None,
           "ttl": ttl}
    if rtts:
        out.update(min=round(min(rtts), 2), avg=round(statistics.mean(rtts), 2), max=round(max(rtts), 2),
                   jitter=round(statistics.mean(abs(a - b) for a, b in zip(rtts, rtts[1:])), 2) if len(rtts) > 1 else 0.0)
    return out


def path_mtu(ip: str, lo: int = 1200, hi: int = 1472) -> dict:
    """Plus grande taille ICMP passant sans fragmentation (bit DF) : 1472 octets
    de données = MTU 1500 (Ethernet). 1464 = PPPoE (1492)."""
    if not icmp.probe(ip, timeout_ms=1500, size=lo, df=True).reached:
        if not icmp.probe(ip, timeout_ms=1500, size=56).reached:
            return {"target": ip, "ok": False}
        return {"target": ip, "ok": True, "payload": None, "mtu": None, "note": f"moins de {lo + 28} octets"}
    best = lo
    while lo <= hi:
        mid = (lo + hi) // 2
        r = icmp.probe(ip, timeout_ms=1500, size=mid, df=True)
        if not r.reached:                 # parfois une perte isolée : on confirme
            r = icmp.probe(ip, timeout_ms=1500, size=mid, df=True)
        if r.reached:
            best, lo = mid, mid + 1
        else:
            hi = mid - 1
    return {"target": ip, "ok": True, "payload": best, "mtu": best + 28}


def tcp_connect_ms(host: str, port: int, timeout: float = 3.0) -> float | None:
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.perf_counter() - t0) * 1000, 1)
    except OSError:
        return None


def https_check(host: str, timeout: float = 5.0) -> dict:
    """Résolution système + poignée de main TLS vérifiée (proxy/inspection TLS : certificat inattendu)."""
    out = {"host": host}
    t0 = time.perf_counter()
    try:
        ip = socket.gethostbyname(host)
        out["dns_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        out["ip"] = ip
    except OSError as exc:
        out["error"] = f"résolution impossible : {exc}"
        return out
    ctx = ssl.create_default_context()
    t1 = time.perf_counter()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                out["tls_ms"] = round((time.perf_counter() - t1) * 1000, 1)
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                out["issuer"] = issuer.get("organizationName") or issuer.get("commonName") or ""
                out["ok"] = True
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"certificat refusé : {exc.verify_message}"
        out["tls_intercept"] = True
        try:
            c2 = ssl.create_default_context()
            c2.check_hostname = False
            c2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=timeout) as raw, c2.wrap_socket(raw, server_hostname=host) as s:
                from .ports import cert_info
                out["cert"] = cert_info(s.getpeercert(binary_form=True))
        except Exception:
            pass
    except (OSError, ssl.SSLError) as exc:
        out["error"] = str(exc)[:160]
    return out


def captive_check(timeout: float = 5.0) -> dict:
    """Test de connectivité Windows (NCSI) : un portail captif ou un proxy renvoie autre chose."""
    try:
        with urllib.request.urlopen("http://www.msftconnecttest.com/connecttest.txt", timeout=timeout) as r:
            body = r.read(200).decode("utf-8", "replace")
            return {"ok": body.strip() == "Microsoft Connect Test", "body": body[:80], "final_url": r.geturl()}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160]}


def public_ip() -> dict:
    """IP publique par DNS (resolver OpenDNS), sans service web tiers ; nom inverse = indice sur l'opérateur."""
    r = dnsmsg.query("208.67.222.222", "myip.opendns.com", "A", timeout=3)
    ips = [a["value"] for a in r.get("answers", []) if a["type"] == "A"]
    if not ips:
        return {"ok": False, "error": r.get("error") or r.get("rcode")}
    ip = ips[0]
    try:
        host = socket.gethostbyaddr(ip)[0]
    except OSError:
        host = ""
    return {"ok": True, "ip": ip, "ptr": host, "isp": isp_from_ptr(host)}


ISP_HINTS = {"proxad.net": "Free", "free.fr": "Free", "wanadoo.fr": "Orange", "orange.fr": "Orange", "sfr.net": "SFR",
             "neufbox": "SFR", "bbox.fr": "Bouygues Telecom", "bouyguestelecom": "Bouygues Telecom", "red-by-sfr": "SFR",
             "numericable": "SFR", "ovh.net": "OVH", "ovhcloud": "OVH", "kosc": "Kosc", "nerim.net": "Nerim",
             "adista": "Adista", "completel": "SFR Business", "colt.net": "Colt", "celeste.fr": "Celeste",
             "sewan": "Sewan", "starlink": "Starlink", "k-net": "K-Net", "videofutur": "Videofutur"}


def isp_from_ptr(host: str) -> str:
    h = (host or "").lower()
    return next((v for k, v in ISP_HINTS.items() if k in h), "")


def sntp_offset(server: str, timeout: float = 2.0) -> dict:
    """Décalage de l'horloge du poste par rapport à un serveur NTP (SNTP, RFC 4330)."""
    pkt = b"\x1b" + 47 * b"\0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t1 = time.time()
            s.sendto(pkt, (server, 123))
            data, _ = s.recvfrom(128)
            t4 = time.time()
    except OSError as exc:
        return {"server": server, "ok": False, "error": str(exc)[:100]}
    if len(data) < 48:
        return {"server": server, "ok": False, "error": "réponse courte"}

    def ts(off):
        sec, frac = struct.unpack("!II", data[off:off + 8])
        return sec - 2208988800 + frac / 2 ** 32
    t2, t3 = ts(32), ts(40)
    offset = ((t2 - t1) + (t3 - t4)) / 2
    return {"server": server, "ok": True, "offset_s": round(offset, 3), "stratum": data[1], "delay_ms": round((t4 - t1) * 1000, 1)}


TEST_NAMES = ["www.google.com", "www.microsoft.com", "www.cloudflare.com"]


def dns_server_tests(servers: list[str], internal_domain: str = "", cancel: threading.Event | None = None) -> dict:
    """Chaque serveur DNS configuré : temps de réponse, récursion, nom interne."""
    out = {}

    def one(srv):
        res = {"server": srv, "queries": []}
        for name in TEST_NAMES:
            r = dnsmsg.query(srv, name, "A", timeout=2.5, tries=2)
            res["queries"].append({"name": name, "ok": r["ok"], "rcode": r.get("rcode"), "ms": r.get("ms"),
                                   "answers": [a["value"] for a in r.get("answers", []) if a["type"] == "A"][:4],
                                   "error": r.get("error")})
        nx = dnsmsg.query(srv, "netaudit-test-inexistant.example.invalid", "A", timeout=2.5)
        res["nxdomain"] = nx.get("rcode")         # NOERROR avec réponse = DNS qui « redirige » les erreurs
        res["nx_answers"] = [a["value"] for a in nx.get("answers", []) if a["type"] == "A"][:2]
        if internal_domain:
            soa = dnsmsg.query(srv, internal_domain, "SOA", timeout=2.5)
            res["internal"] = {"domain": internal_domain, "ok": soa["ok"], "rcode": soa.get("rcode"),
                               "has_soa": any(a["type"] == "SOA" for a in soa.get("answers", []))}
            srvr = dnsmsg.query(srv, f"_ldap._tcp.dc._msdcs.{internal_domain}", "SRV", timeout=2.5)
            res["ad_dc"] = [a["value"].get("target") for a in srvr.get("answers", []) if a["type"] == "SRV" and isinstance(a["value"], dict)]
        oks = [q["ms"] for q in res["queries"] if q["ok"] and q["rcode"] == "OK"]
        res["ok"] = bool(oks)
        res["avg_ms"] = round(statistics.mean(oks), 1) if oks else None
        res["failed"] = sum(1 for q in res["queries"] if not q["ok"] or q["rcode"] != "OK")
        return srv, res
    with ThreadPoolExecutor(8) as ex:
        for srv, res in ex.map(one, servers):
            out[srv] = res
    return out


def internet_tests(gateway: str | None, cancel: threading.Event | None = None) -> dict:
    out: dict = {}
    with ThreadPoolExecutor(8) as ex:
        f_gw = ex.submit(ping_series, gateway, 30, 0.2, 1000, 32, cancel) if gateway else None
        f_pings = {t: ex.submit(ping_series, t, 15, 0.25, 1500, 32, cancel) for t in ("1.1.1.1", "8.8.8.8", "9.9.9.9")}
        f_https = {h: ex.submit(https_check, h) for h in ("www.google.com", "www.microsoft.com")}
        f_ncsi = ex.submit(captive_check)
        f_pub = ex.submit(public_ip)
        f_dns53 = ex.submit(lambda: dnsmsg.query("8.8.8.8", "www.google.com", "A", timeout=2.5))
        f_ntp = {s: ex.submit(sntp_offset, s) for s in ("time.windows.com", "pool.ntp.org")}
        if gateway:
            f_ntp_gw = ex.submit(sntp_offset, gateway, 1.5)
        out["gateway_ping"] = f_gw.result() if f_gw else None
        out["pings"] = {t: f.result() for t, f in f_pings.items()}
        out["https"] = {h: f.result() for h, f in f_https.items()}
        out["ncsi"] = f_ncsi.result()
        out["public"] = f_pub.result()
        d = f_dns53.result()
        out["direct_dns"] = {"ok": d["ok"], "ms": d.get("ms")}
        out["ntp"] = {s: f.result() for s, f in f_ntp.items()}
        if gateway:
            out["ntp_gateway"] = f_ntp_gw.result()
    reach = [t for t, r in out["pings"].items() if r.get("received")]
    out["mtu"] = path_mtu(reach[0]) if reach else None
    return out
