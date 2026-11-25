"""Identification des appareils : NetBIOS, mDNS (Bonjour), SSDP (UPnP) et DNS
inverse. Toutes les requêtes partent d'un port éphémère (aucun port à
réserver, pas de droits administrateur) ; les réponses sont collectées en
parallèle pendant quelques secondes.
"""
from __future__ import annotations

import html
import re
import socket
import struct
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from . import dnsmsg

# ------------------------------------------------------------------ NetBIOS
_NB_NAME = b"\x20" + b"CK" + b"A" * 30 + b"\x00"     # « * » encodé (requête NBSTAT)


def _nb_query(tid: int) -> bytes:
    return struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + _NB_NAME + struct.pack("!HH", 0x21, 1)


def _nb_parse(data: bytes) -> dict | None:
    try:
        off = 12
        # nom de la question renvoyé tel quel (34 octets) ou pointeur
        off += 2 if data[off] & 0xC0 == 0xC0 else 34
        off += 8          # type, classe, TTL
        rdlen = struct.unpack_from("!H", data, off)[0]
        off += 2
        n = data[off]
        off += 1
        names = []
        for _ in range(n):
            raw = data[off:off + 15].decode("latin-1").rstrip(" \x00")
            suffix = data[off + 15]
            flags = struct.unpack_from("!H", data, off + 16)[0]
            names.append((raw, suffix, bool(flags & 0x8000)))
            off += 18
        mac = data[off:off + 6]
    except (IndexError, struct.error):
        return None
    host = next((nm for nm, sfx, grp in names if sfx == 0x00 and not grp), None)
    group = next((nm for nm, sfx, grp in names if sfx == 0x00 and grp), None)
    return {"name": host, "workgroup": group, "file_server": any(sfx == 0x20 for _n, sfx, _g in names),
            "dc": any(sfx == 0x1C and grp for _n, sfx, grp in names),
            "master_browser": any(sfx == 0x1D for _n, sfx, _g in names),
            "mac": ":".join(f"{b:02x}" for b in mac) if len(mac) == 6 and any(mac) else None}


def netbios(ips: list[str], wait: float = 2.5, cancel: threading.Event | None = None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not ips:
        return out
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        s.settimeout(0.2)
        for i, ip in enumerate(ips):
            try:
                s.sendto(_nb_query(0x4E00 + i % 255), (ip, 137))
            except OSError:
                pass
            if i % 64 == 63:
                time.sleep(0.01)
        end = time.monotonic() + wait
        while time.monotonic() < end and not (cancel and cancel.is_set()):
            try:
                data, (src, _p) = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:            # ICMP port injoignable renvoyé par Windows (WSAECONNRESET)
                continue
            r = _nb_parse(data)
            if r and r.get("name"):
                out[src] = r
    return out


# --------------------------------------------------------------------- mDNS
MDNS_ADDR = ("224.0.0.251", 5353)
MDNS_SERVICES = ["_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local", "_ipp._tcp.local",
                 "_ipps._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local", "_scanner._tcp.local",
                 "_uscan._tcp.local", "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
                 "_spotify-connect._tcp.local", "_smb._tcp.local", "_afpovertcp._tcp.local", "_workstation._tcp.local",
                 "_device-info._tcp.local", "_hap._tcp.local", "_homekit._tcp.local", "_matter._tcp.local",
                 "_meshcop._udp.local", "_sonos._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local",
                 "_rfb._tcp.local", "_companion-link._tcp.local", "_amzn-wplay._tcp.local", "_androidtvremote2._tcp.local",
                 "_hue._tcp.local", "_esphomelib._tcp.local", "_home-assistant._tcp.local", "_axis-video._tcp.local",
                 "_rtsp._tcp.local", "_onvif._tcp.local", "_nvstream._tcp.local", "_adisk._tcp.local", "_daap._tcp.local"]

SERVICE_LABELS = {"_ipp": "Impression IPP", "_ipps": "Impression IPP", "_printer": "Impression LPD",
                  "_pdl-datastream": "Impression RAW", "_scanner": "Scanner", "_uscan": "Scanner", "_airplay": "AirPlay",
                  "_raop": "AirPlay audio", "_googlecast": "Chromecast", "_spotify-connect": "Spotify Connect",
                  "_smb": "Partage SMB", "_afpovertcp": "Partage AFP", "_hap": "HomeKit", "_homekit": "HomeKit",
                  "_matter": "Matter", "_meshcop": "Thread", "_sonos": "Sonos", "_ssh": "SSH", "_sftp-ssh": "SFTP",
                  "_rfb": "VNC", "_hue": "Philips Hue", "_esphomelib": "ESPHome", "_home-assistant": "Home Assistant",
                  "_axis-video": "Caméra Axis", "_rtsp": "Flux vidéo RTSP", "_onvif": "Caméra ONVIF",
                  "_amzn-wplay": "Amazon Fire TV", "_androidtvremote2": "Android TV", "_nvstream": "NVIDIA",
                  "_adisk": "Time Machine", "_daap": "iTunes", "_workstation": "Poste", "_http": "Web", "_https": "Web"}


def mdns(local_ips: list[str], targets: list[str] | None = None, wait: float = 3.0,
         cancel: threading.Event | None = None) -> dict[str, dict]:
    """Requêtes « legacy unicast » : réponses renvoyées à notre port éphémère.
    Renvoie {ip: {"names": [...], "services": [...], "model": ...}}."""
    out: dict[str, dict] = {}
    socks = []
    for lip in local_ips or ["0.0.0.0"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((lip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if lip != "0.0.0.0":
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lip))
            s.settimeout(0.1)
            socks.append(s)
        except OSError:
            continue
    try:
        for s in socks:
            for svc in MDNS_SERVICES:
                try:
                    s.sendto(dnsmsg.build_query(svc, "PTR", rd=False, qid=0, unicast_response=True), MDNS_ADDR)
                except OSError:
                    pass
        # DNS inverse en mDNS, adressé directement à chaque appareil (nom en .local)
        if targets and socks:
            for i, ip in enumerate(targets):
                try:
                    socks[0].sendto(dnsmsg.build_query(dnsmsg.reverse_name(ip), "PTR", rd=False, qid=0), (ip, 5353))
                except OSError:
                    pass
                if i % 64 == 63:
                    time.sleep(0.01)
        # Les enregistrements sont rassemblés globalement puis rattachés à l'IP de leur
        # enregistrement A : un relais mDNS (UniFi, Meraki…) répond au nom de TOUS les appareils.
        ptr_rev: dict[str, str] = {}                 # ip -> nom (PTR inverse)
        svc_inst: dict[str, set] = {}                # instance -> services
        srv: dict[str, str] = {}                     # instance -> cible
        a_rec: dict[str, str] = {}                   # nom -> ip
        txt: dict[str, dict] = {}                    # instance -> clés utiles
        direct: dict[str, set] = {}                  # source -> noms annoncés en propre

        def absorb(src: str, r: dict):
            for rec in r["records"]:
                t, n, v = rec["type"], rec["name"].rstrip("."), rec["value"]
                if t == "PTR" and n.endswith(".in-addr.arpa") and isinstance(v, str):
                    ip = ".".join(reversed(n[:-len(".in-addr.arpa")].split(".")))
                    ptr_rev[ip] = v.rstrip(".")
                elif t == "PTR" and isinstance(v, str) and n != "_services._dns-sd._udp.local":
                    svc_inst.setdefault(v.rstrip("."), set()).add(n.split(".")[0])
                elif t == "SRV" and isinstance(v, dict):
                    srv[n] = v.get("target", "").rstrip(".")
                elif t == "A" and isinstance(v, str):
                    a_rec[n] = v
                    if v == src:
                        direct.setdefault(src, set()).add(n)
                elif t == "TXT" and isinstance(v, list):
                    d = txt.setdefault(n, {})
                    for kv in v:
                        k, _sep, val = kv.partition("=")
                        if k.lower() in ("md", "model", "ty", "usb_mdl", "product", "manufacturer", "usb_mfg", "fn", "am", "rpmd"):
                            d[k.lower()] = val[:80]

        def listen(seconds: float):
            end = time.monotonic() + seconds
            while time.monotonic() < end and not (cancel and cancel.is_set()):
                for s in socks:
                    try:
                        data, (src, _p) = s.recvfrom(9000)
                    except (socket.timeout, OSError):
                        continue
                    try:
                        absorb(src, dnsmsg.parse(data))
                    except (ValueError, struct.error, IndexError):
                        continue
        listen(wait)
        # 2e passe : SRV/TXT des instances et A des cibles encore inconnues
        todo = [(i, "SRV") for i in svc_inst if i not in srv] + [(i, "TXT") for i in svc_inst if i not in txt]
        todo += [(t, "A") for t in set(srv.values()) if t and t not in a_rec]
        if todo and socks and not (cancel and cancel.is_set()):
            for name, qt in todo[:400]:
                try:
                    socks[0].sendto(dnsmsg.build_query(name, qt, rd=False, qid=0, unicast_response=True), MDNS_ADDR)
                except OSError:
                    pass
            listen(1.5)
            late = [(t, "A") for t in set(srv.values()) if t and t not in a_rec]
            for name, qt in late[:200]:
                try:
                    socks[0].sendto(dnsmsg.build_query(name, qt, rd=False, qid=0, unicast_response=True), MDNS_ADDR)
                except OSError:
                    pass
            if late:
                listen(1.0)

        def ent(ip):
            return out.setdefault(ip, {"names": [], "services": [], "instances": [], "txt": {}})
        for n, ip in a_rec.items():
            if n.endswith(".local"):
                _add(ent(ip)["names"], n)
        for ip, n in ptr_rev.items():
            _add(ent(ip)["names"], n)
        for inst, svcs in svc_inst.items():
            ip = a_rec.get(srv.get(inst, ""))
            if not ip:
                continue
            e = ent(ip)
            for sv in sorted(svcs):
                _add(e["services"], sv)
            short = inst.split("._")[0]
            _add(e["instances"], short)
            for k, v in (txt.get(inst) or {}).items():
                e["txt"].setdefault(k, v)
        for e in out.values():
            e["model"] = (e["txt"].get("ty") or e["txt"].get("md") or e["txt"].get("model") or e["txt"].get("am")
                          or e["txt"].get("rpmd") or e["txt"].get("usb_mdl") or "")
        return {ip: e for ip, e in out.items() if e["names"] or e["services"]}
    finally:
        for s in socks:
            s.close()


def _add(lst: list, v):
    if v and v not in lst:
        lst.append(v)


# --------------------------------------------------------------------- SSDP
SSDP_ADDR = ("239.255.255.250", 1900)


def ssdp(local_ips: list[str], wait: float = 3.0, fetch: bool = True,
         cancel: threading.Event | None = None) -> dict[str, dict]:
    """M-SEARCH ssdp:all ; renvoie {ip: {server, locations, types, friendly, manufacturer, model}}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    out: dict[str, dict] = {}
    socks = []
    for lip in local_ips or ["0.0.0.0"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((lip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            if lip != "0.0.0.0":
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lip))
            s.settimeout(0.1)
            socks.append(s)
        except OSError:
            continue
    try:
        for _ in range(2):
            for s in socks:
                try:
                    s.sendto(msg, SSDP_ADDR)
                except OSError:
                    pass
            time.sleep(0.1)
        end = time.monotonic() + wait
        while time.monotonic() < end and not (cancel and cancel.is_set()):
            for s in socks:
                try:
                    data, (src, _p) = s.recvfrom(4096)
                except (socket.timeout, OSError):
                    continue
                hdr = {}
                for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                    k, sep, v = line.partition(":")
                    if sep:
                        hdr[k.strip().lower()] = v.strip()
                e = out.setdefault(src, {"server": "", "locations": [], "types": []})
                if hdr.get("server") and not e["server"]:
                    e["server"] = hdr["server"][:160]
                if hdr.get("location"):
                    _add(e["locations"], hdr["location"][:300])
                if hdr.get("st"):
                    _add(e["types"], hdr["st"][:120])
    finally:
        for s in socks:
            s.close()
    if fetch and out:
        with ThreadPoolExecutor(16) as ex:
            for ip, info in zip(out, ex.map(lambda kv: _ssdp_desc(kv[1]["locations"], kv[0]), out.items())):
                out[ip].update(info or {})
    return out


def _ssdp_desc(locations: list[str], ip: str) -> dict:
    """Lit la description UPnP (XML) annoncée par l'appareil lui-même."""
    for loc in locations[:3]:
        if f"//{ip}:" not in loc and f"//{ip}/" not in loc:
            continue                       # n'interroger que l'appareil qui a répondu
        try:
            with urllib.request.urlopen(loc, timeout=2.5) as r:
                raw = r.read(200_000)
            root = ET.fromstring(raw)
        except Exception:
            continue
        dev = None
        for el in root.iter():
            if el.tag.endswith("device"):
                dev = el
                break
        if dev is None:
            continue

        def g(tag):
            for el in dev:
                if el.tag.endswith(tag) and (el.text or "").strip():
                    return el.text.strip()[:120]
            return ""
        return {"friendly": g("friendlyName"), "manufacturer": g("manufacturer"), "model": g("modelName"),
                "model_number": g("modelNumber"), "device_type": g("deviceType"), "presentation": g("presentationURL")}
    return {}


# --------------------------------------------------------------- DNS inverse
def reverse_dns(ips: list[str], servers: list[str], timeout: float = 1.5,
                cancel: threading.Event | None = None) -> dict[str, str]:
    """PTR auprès des serveurs DNS du réseau (le premier qui répond)."""
    out: dict[str, str] = {}
    if not servers:
        return out

    def one(ip):
        if cancel and cancel.is_set():
            return ip, None
        for srv in servers[:2]:
            r = dnsmsg.query(srv, dnsmsg.reverse_name(ip), "PTR", timeout=timeout, tries=1)
            if r["ok"]:
                ptr = [a["value"] for a in r["answers"] if a["type"] == "PTR" and isinstance(a["value"], str)]
                return ip, (ptr[0].rstrip(".") if ptr else None)
        return ip, None
    with ThreadPoolExecutor(32) as ex:
        for ip, name in ex.map(one, ips):
            if name:
                out[ip] = name
    return out


_HTTP_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def http_title(body: bytes) -> str:
    m = _HTTP_TITLE.search(body or b"")
    if not m:
        return ""
    t = re.sub(rb"\s+", b" ", m.group(1)).strip()[:200]
    for enc in ("utf-8", "latin-1"):
        try:
            return html.unescape(t.decode(enc)).replace("\xa0", " ").strip()[:100]
        except UnicodeDecodeError:
            continue
    return ""


def local_ips() -> list[str]:
    try:
        return [a for a in socket.gethostbyname_ex(socket.gethostname())[2] if not a.startswith("127.")]
    except OSError:
        return []

