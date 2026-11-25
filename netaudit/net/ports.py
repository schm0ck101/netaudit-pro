"""Scan de ports TCP par connexion complète (aucun paquet forgé, pas de droits
administrateur), lecture des bannières, des pages d'administration web et des
certificats TLS, détection de SMBv1."""
from __future__ import annotations

import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .names import http_title

# Mode discret : ports qui identifient un appareil ou signalent un risque
PORTS_QUICK = [21, 22, 23, 25, 53, 80, 81, 88, 135, 139, 161, 389, 443, 445, 515, 548, 554, 631, 1433, 3306, 3389,
               5000, 5001, 5900, 8000, 8080, 8291, 8443, 9100, 10000]
# Mode approfondi : en plus
PORTS_DEEP_EXTRA = [20, 37, 49, 79, 110, 111, 113, 119, 143, 179, 199, 427, 465, 500, 502, 587, 593, 623, 636, 873,
                    902, 989, 990, 993, 995, 1080, 1194, 1723, 1883, 1900, 2000, 2049, 2082, 2083, 2222, 2375, 2376, 3000,
                    3128, 3260, 3268, 3283, 3389, 4000, 4443, 4567, 4840, 5060, 5061, 5222, 5353, 5357, 5432, 5555, 5601,
                    5672, 5985, 5986, 6000, 6379, 6443, 6667, 7000, 7001, 7070, 7443, 7547, 8001, 8008, 8009, 8081, 8086,
                    8088, 8123, 8181, 8200, 8243, 8291, 8333, 8400, 8834, 8880, 8883, 8888, 9000, 9001, 9080, 9090, 9200,
                    9418, 9443, 9999, 10001, 10443, 11211, 27017, 32400, 37777, 47808, 49152, 50000, 51413, 62078]
PORTS_DEEP = sorted(set(PORTS_QUICK + PORTS_DEEP_EXTRA))
PORTS_UDP_ONLY = {161, 1900, 5353}     # testés autrement (SNMP, SSDP, mDNS)

SERVICES = {20: "FTP-données", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 37: "Time", 49: "TACACS", 53: "DNS",
            79: "Finger", 80: "HTTP", 81: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 113: "Ident", 119: "NNTP",
            135: "RPC Microsoft", 139: "NetBIOS", 143: "IMAP", 179: "BGP", 389: "LDAP", 427: "SLP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 500: "IKE", 502: "Modbus", 515: "LPD", 548: "AFP", 554: "RTSP", 587: "SMTP",
            593: "RPC HTTP", 623: "IPMI", 631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware", 993: "IMAPS",
            995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "SQL Server", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
            2375: "Docker (non chiffré)", 2376: "Docker", 3000: "HTTP", 3128: "Proxy", 3260: "iSCSI", 3268: "LDAP GC",
            3306: "MySQL", 3389: "Bureau à distance", 4840: "OPC UA", 5000: "HTTP / UPnP", 5001: "HTTPS", 5060: "SIP",
            5061: "SIP TLS", 5357: "WSD", 5432: "PostgreSQL", 5555: "ADB Android", 5672: "AMQP", 5900: "VNC",
            5985: "WinRM", 5986: "WinRM HTTPS", 6379: "Redis", 6443: "Kubernetes", 7547: "TR-069", 8000: "HTTP",
            8008: "HTTP", 8009: "AJP", 8080: "HTTP", 8081: "HTTP", 8086: "InfluxDB", 8123: "Home Assistant",
            8291: "Winbox MikroTik", 8443: "HTTPS", 8880: "HTTP", 8883: "MQTT TLS", 8888: "HTTP", 9000: "HTTP",
            9090: "HTTP", 9100: "Impression RAW", 9200: "Elasticsearch", 9443: "HTTPS", 10000: "Webmin / NDMP",
            11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 37777: "DVR Dahua", 47808: "BACnet",
            51413: "BitTorrent", 62078: "iPhone (synchro)"}

WEB_PLAIN = {80, 81, 3000, 5000, 7000, 7001, 7070, 8000, 8001, 8008, 8080, 8081, 8088, 8123, 8181, 8200, 8880, 8888,
             9000, 9080, 9090, 32400}
WEB_TLS = {443, 4443, 5001, 6443, 7443, 8243, 8443, 9443, 10443}
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 2222}


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def scan(hosts: list[str], ports: list[int], timeout: float = 0.8, workers: int = 256,
         cancel: threading.Event | None = None, progress=None) -> dict[str, list[int]]:
    """{ip: [ports ouverts]} ; ``progress(fait, total)`` facultatif."""
    jobs = [(h, p) for h in hosts for p in ports if p not in PORTS_UDP_ONLY]
    out: dict[str, list[int]] = {h: [] for h in hosts}
    lock = threading.Lock()
    done = [0]

    def one(hp):
        if cancel and cancel.is_set():
            return
        h, p = hp
        if tcp_open(h, p, timeout):
            with lock:
                out[h].append(p)
        with lock:
            done[0] += 1
            if progress and done[0] % 200 == 0:
                progress(done[0], len(jobs))
    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, jobs))
    for h in out:
        out[h].sort()
    return out


def banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            t0 = time.monotonic()
            while len(data) < 512 and time.monotonic() - t0 < timeout:
                try:
                    chunk = s.recv(512)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if port == 23:
                    data = _strip_telnet(data)
                if b"\n" in data and port != 23:
                    break
            line = data.split(b"\n", 1)[0] if port != 23 else data     # SSH : la négociation binaire suit la 1re ligne
            txt = line.decode("utf-8", "replace").replace("\r", "")
            return "".join(ch for ch in txt if ch.isprintable() or ch == "\n").strip()[:200]
    except OSError:
        return ""


def _strip_telnet(b: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(b):
        if b[i] == 255 and i + 2 < len(b):
            i += 3
            continue
        out.append(b[i])
        i += 1
    return bytes(out)


def http_probe(ip: str, port: int, tls: bool, timeout: float = 3.0) -> dict:
    """GET / : code, en-tête Server, titre de la page, redirection ; certificat si TLS."""
    info: dict = {"port": port, "tls": tls}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        return {**info, "error": str(exc)}
    sock = raw
    try:
        sock.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (ValueError, AttributeError):
                pass
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            sock = ctx.wrap_socket(raw, server_hostname=ip)
            info["tls_version"] = sock.version()
            der = sock.getpeercert(binary_form=True)
            if der:
                info["cert"] = cert_info(der)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetAuditPro\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        data = b""
        t0 = time.monotonic()
        while len(data) < 65536 and time.monotonic() - t0 < timeout:
            try:
                chunk = sock.recv(8192)
            except (socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            data += chunk
        head, _sep, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split(" ", 2)
            info["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        for ln in lines[1:]:
            k, sep, v = ln.partition(":")
            k = k.strip().lower()
            if k in ("server", "location", "www-authenticate", "x-powered-by") and sep:
                info[k.replace("-", "_")] = v.strip()[:160]
        info["title"] = http_title(body)
    except (OSError, ssl.SSLError, ValueError) as exc:
        info["error"] = str(exc)[:160]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return info


def cert_info(der: bytes) -> dict:
    """Sujet, émetteur, dates du certificat (décodage DER minimal, sans dépendance)."""
    try:
        from ._x509 import parse_cert
        return parse_cert(der)
    except Exception as exc:  # certificat exotique : on garde au moins l'empreinte
        import hashlib
        return {"sha256": hashlib.sha256(der).hexdigest(), "error": str(exc)[:100]}


def smb1_enabled(ip: str, timeout: float = 2.0) -> bool | None:
    """Négociation SMB proposant uniquement le dialecte « NT LM 0.12 » (SMBv1).
    True = le serveur accepte SMBv1 ; False = refusé ; None = indéterminé."""
    dialect = b"\x02NT LM 0.12\x00"
    smb = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18" + b"\x01\x28" + b"\x00" * 12 + b"\x00\x00" + b"\xff\xfe"
           + b"\x00\x00" + b"\x00\x00" + b"\x00" + struct.pack("<H", len(dialect)) + dialect)
    pkt = struct.pack(">I", len(smb)) + smb
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(pkt)
            data = s.recv(256)
    except OSError:
        return None
    if len(data) < 9:
        return False                    # connexion fermée : dialecte refusé
    if data[4:8] == b"\xffSMB":
        # DialectIndex 0xFFFF = aucun dialecte accepté
        if len(data) >= 39:
            idx = struct.unpack_from("<H", data, 37)[0]
            return idx != 0xFFFF
        return True
    return False


def enrich(open_ports: dict[str, list[int]], deep: bool, cancel: threading.Event | None = None) -> dict[str, dict]:
    """Bannières, pages web, certificats et SMBv1 pour les ports ouverts."""
    jobs = []
    for ip, ports in open_ports.items():
        for p in ports:
            if p in WEB_PLAIN or p in WEB_TLS:
                jobs.append(("web", ip, p))
            elif p in BANNER_PORTS:
                jobs.append(("banner", ip, p))
            elif p == 445:
                jobs.append(("smb1", ip, p))
    out: dict[str, dict] = {}

    def run(job):
        if cancel and cancel.is_set():
            return job, None
        kind, ip, p = job
        if kind == "web":
            r = http_probe(ip, p, p in WEB_TLS)
            if r.get("error") and p not in WEB_TLS and ("400" in str(r.get("status")) or not r.get("status")):
                r2 = http_probe(ip, p, True)
                if not r2.get("error"):
                    r = r2
            return job, r
        if kind == "banner":
            return job, banner(ip, p)
        return job, smb1_enabled(ip)
    with ThreadPoolExecutor(32) as ex:
        for (kind, ip, p), res in ex.map(run, jobs):
            if res is None and kind != "smb1":
                continue
            e = out.setdefault(ip, {"web": [], "banners": {}, "smb1": None})
            if kind == "web":
                e["web"].append(res)
            elif kind == "banner":
                if res:
                    e["banners"][str(p)] = res
            else:
                e["smb1"] = res
    return out


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
