"""Classification des appareils à partir de TOUS les indices recueillis :
SNMP (sysDescr, constructeur), ports ouverts, services annoncés (mDNS, UPnP),
NetBIOS, fabricant de la carte (OUI), TTL, pages web, bannières.

Le résultat est une hypothèse lisible (« Switch · HPE Aruba 2530-24G ») ;
chaque indice a un poids, le plus fort l'emporte. Aucune règle n'est propre
à un réseau particulier.
"""
from __future__ import annotations

import re

# types d'appareils (code -> libellé)
KINDS = {
    "router": "Routeur / pare-feu", "switch": "Switch", "ap": "Borne Wi-Fi", "server": "Serveur", "hypervisor": "Hyperviseur",
    "nas": "Stockage (NAS)", "printer": "Imprimante / scanner", "camera": "Caméra / enregistreur", "pc": "Poste Windows",
    "mac": "Mac", "linux": "Poste / serveur Linux", "phone": "Téléphone / tablette", "voip": "Téléphone IP",
    "media": "TV / multimédia", "iot": "Domotique / objet connecté", "ups": "Onduleur", "mgmt": "Carte d'administration (iLO, iDRAC…)",
    "modem": "Box / modem opérateur", "honeypot": "Leurre (honeypot)", "unknown": "Indéterminé",
}
NETWORK_GEAR = {"router", "switch", "ap", "modem"}

VENDOR_HINTS = [   # (motif sur le fabricant OUI, type, poids)
    (r"ubiquiti|ruckus|aerohive|meraki|aruba|cambium|mist systems|extreme", "ap", 2),
    (r"cisco|juniper|hewlett packard enterprise|hpe|netgear|tp-link|d-link|zyxel|mikrotik|routerboard|allied telesis|"
     r"edgecore|planet|draytek|fortinet|sonicwall|watchguard|palo alto|stormshield|sophos|teltonika|lancom|h3c|ruijie|"
     r"huawei|alcatel|arista|brocade|dell emc networking", "switch", 2),
    (r"synology|qnap|western digital|asustor|buffalo|terramaster|netapp", "nas", 4),
    (r"brother|canon|epson|kyocera|lexmark|ricoh|xerox|konica|sharp corp|oki electric|toshiba tec|zebra|sato|"
     r"hp inc|hewlett[- ]packard", "printer", 2),
    (r"hikvision|dahua|axis comm|hanwha|vivotek|uniview|reolink|mobotix|bosch security|avigilon|foscam|"
     r"china dragon|tiandy|amcrest", "camera", 4),
    (r"yealink|snom|polycom|grandstream|gigaset|fanvil|avaya|mitel|alcatel-lucent ent|unify", "voip", 4),
    (r"apple", "phone", 1), (r"samsung|xiaomi|oppo|vivo|oneplus|huawei device|motorola|google|realme|honor", "phone", 2),
    (r"sonos|roku|amazon|lg electronics|sony|vizio|tcl|bose|denon|yamaha|harman|nvidia|chromecast", "media", 3),
    (r"espressif|tuya|shelly|signify|philips lighting|lumi|xiaomi.*iot|athom|netatmo|somfy|nest|ring|ecobee|"
     r"silicon labs|texas instruments|sercomm|smlight|itead|ezviz|tado|legrand|schneider", "iot", 3),
    (r"american power|apc|eaton|cyberpower|riello|socomec|legrand ups", "ups", 4),
    (r"vmware|xensource|microsoft corporation.*hyper|proxmox|qemu|red hat|parallels", "server", 1),
    (r"freebox|sagemcom|technicolor|arcadyan|askey|nokia shanghai|zte|sercomm|bouygues|vantiva|actiontec", "modem", 3),
    (r"intel corporate|realtek|gigabyte|giga-byte|asustek|micro-star|msi|dell|lenovo|lcfc|wistron|quanta|"
     r"pegatron|liteon|hon hai|azurewave|compal|fujitsu", "pc", 1),
]

PORT_HINTS = {   # port -> (type, poids)
    9100: ("printer", 4), 515: ("printer", 3), 631: ("printer", 2), 554: ("camera", 3), 37777: ("camera", 5),
    8291: ("router", 5), 179: ("router", 3), 3389: ("pc", 2), 135: ("pc", 1), 88: ("server", 4), 389: ("server", 4),
    3268: ("server", 5), 1433: ("server", 3), 5985: ("pc", 1), 902: ("hypervisor", 5), 8006: ("hypervisor", 5),
    5060: ("voip", 2), 62078: ("phone", 5), 548: ("mac", 2), 5000: ("nas", 1), 5001: ("nas", 1), 623: ("mgmt", 4),
    32400: ("server", 1), 8123: ("iot", 3), 1883: ("iot", 2), 7547: ("modem", 4), 9000: ("media", 0),
}

MDNS_HINTS = {"_ipp": "printer", "_ipps": "printer", "_printer": "printer", "_pdl-datastream": "printer",
              "_scanner": "printer", "_uscan": "printer", "_airplay": "media", "_raop": "media", "_googlecast": "media",
              "_spotify-connect": "media", "_sonos": "media", "_amzn-wplay": "media", "_androidtvremote2": "media",
              "_hap": "iot", "_homekit": "iot", "_matter": "iot", "_hue": "iot", "_esphomelib": "iot",
              "_home-assistant": "iot", "_axis-video": "camera", "_onvif": "camera", "_rtsp": "camera",
              "_afpovertcp": "mac", "_adisk": "nas", "_companion-link": "phone", "_meshcop": "iot"}

DESCR_HINTS = [   # motif sur sysDescr SNMP / modèle / description UPnP -> type, poids
    (r"\b(switch|procurve|catalyst|nexus|usw|us-\d|us\d|flex ?mini|sg\d{3}|cbs\d{3}|gs\d{3,4}|jgs\d|t\d{4}g|crs\d|"
     r"css\d|2530|2540|2920|2930|3810|5400|6300|aruba ?cx|icx\d|ex\d{4}|summit|dgs-|tl-sg|\d{4}-\d{2}g)", "switch", 6),
    (r"\b(uap|u6|u7|unifi ap|ac-lr|ac-pro|nanohd|access ?point|ap\d{2,3}|iap|instant on ap|air-ap|aironet|"
     r"wap\d|eap\d|cap ac|wifi ?6 ap|uap-)", "ap", 6),
    (r"\b(udm|usg|ucg|uxg|gateway|router|routeros|fortigate|fortios|pfsense|opnsense|sophos|sonicwall|asa\d|isr\d|"
     r"edgerouter|firewall|mx\d{2,3}|draytek|vigor|stormshield|watchguard|forti)", "router", 6),
    (r"\b(synology|diskstation|qnap|readynas|truenas|freenas|unraid|nas)\b", "nas", 6),
    (r"\b(printer|laserjet|officejet|pagewide|deskjet|imagerunner|bizhub|ecosys|taskalfa|aficio|workcentre|"
     r"versalink|mfp|scanner|ads-\d|mfc-|dcp-)", "printer", 6),
    (r"\b(hikvision|ds-2cd|ds-7|ds-9|nvr|dvr|ipc|camera|webcam|dahua)", "camera", 6),
    (r"\b(esxi|vmware|hyper-v|proxmox|xenserver|xcp-ng)", "hypervisor", 6),
    (r"\b(windows server|microsoft windows)", "pc", 3),
    (r"\b(ups|smart-ups|network management card|eaton|powerware)", "ups", 6),
    (r"\b(ilo|idrac|xclarity|xcc|ipmi|bmc|imm2?)\b", "mgmt", 6),
    (r"\b(livebox|freebox|bbox|neufbox|box internet|fritz)", "modem", 6),
    (r"\b(u-lte|lte-pro|lte router|4g router|5g router|cpe\d|nighthawk m|rut\d{3})", "router", 7),
    (r"\b(sonos|chromecast|roku|apple tv|fire ?tv|smart tv|bravia|webos|tizen)", "media", 5),
    (r"\b(yealink|snom|polycom|grandstream|cisco ip phone|sip-t)", "voip", 6),
]


def _add(scores: dict, kind: str, w: float, why: str, ev: list):
    if w <= 0:
        return
    scores[kind] = scores.get(kind, 0) + w
    ev.append(f"{why} → {KINDS[kind]}")


def best_name(h: dict) -> str:
    n = h.get("names") or {}
    snmpd = h.get("snmp") or {}
    for cand in ((snmpd.get("name") or "").strip(), (n.get("netbios") or {}).get("name"), (n.get("ssdp") or {}).get("friendly"),
                 next(iter((n.get("mdns") or {}).get("instances") or []), None),
                 (n.get("dns") or "").split(".")[0], next(iter((n.get("mdns") or {}).get("names") or []), "").replace(".local", "")):
        if cand and cand.lower() not in ("localhost", "(none)", "unknown") and not re.fullmatch(r"[0-9a-f-]{20,}", cand.lower()):
            return cand[:60]
    return ""


def model_of(h: dict) -> str:
    n = h.get("names") or {}
    snmpd = h.get("snmp") or {}
    ss = n.get("ssdp") or {}
    md = n.get("mdns") or {}
    if ss.get("model"):
        return " ".join(x for x in (ss.get("manufacturer"), ss.get("model"), ss.get("model_number")) if x)[:80]
    # Samba annonce un faux modèle Apple (Xserve, RackMac…) pour l'icône dans le Finder : ignoré
    if md.get("model") and not re.fullmatch(r"[\d,]+", md["model"]) and not re.match(r"(xserve|rackmac|macsamba|timecapsule|macpro)", md["model"], re.I):
        return md["model"][:80]
    d = (snmpd.get("descr") or "").strip()
    if d:
        return d.split("\n")[0][:80]
    for w in h.get("web") or []:
        t = (w or {}).get("title") or ""
        if t and not re.match(r"^\d{3} |^(index|login|home|bad request|error|document)", t, re.I) and "Status" not in t:
            return t[:80]
    return ""


def os_guess(h: dict, kind: str) -> str:
    ttl = h.get("ttl")
    d = ((h.get("snmp") or {}).get("descr") or "").lower()
    if "windows" in d:
        return "Windows"
    if "linux" in d:
        return "Linux"
    if kind in ("pc",) or (ttl and 65 <= ttl <= 128 and {135, 445} & set(h.get("ports") or [])):
        return "Windows"
    if kind == "mac":
        return "macOS"
    if ttl and ttl > 128:
        return "Système réseau"
    if ttl and ttl <= 64:
        return "Linux / Unix"
    return ""


def classify(h: dict, gateways: set, gateway_macs: set) -> dict:
    """Ajoute à l'hôte : kind, kind_label, name, model, os, evidence, confidence."""
    scores: dict[str, float] = {}
    ev: list[str] = []
    ip = h["ip"]
    ports_ = set(h.get("ports") or [])
    vendor = (h.get("vendor") or "").lower()
    snmpd = h.get("snmp") or {}
    names = h.get("names") or {}
    md = names.get("mdns") or {}
    ss = names.get("ssdp") or {}
    nb = names.get("netbios") or {}
    text = " ".join(str(x) for x in (snmpd.get("descr"), snmpd.get("name"), ss.get("model"), ss.get("friendly"),
                                       ss.get("device_type"), ss.get("server"), md.get("model"), " ".join(md.get("instances") or []),
                                       names.get("dns"), " ".join((w or {}).get("title") or "" for w in h.get("web") or []),
                                       " ".join((h.get("banners") or {}).values()))).lower()

    # leurre : même MAC que la passerelle mais pas la passerelle, plein de services « appâts »
    if h.get("mac") and h["mac"] in gateway_macs and ip not in gateways and len(ports_ & {21, 23, 25, 110, 445, 1433, 2222}) >= 3:
        _add(scores, "honeypot", 20, "MAC de la passerelle + services leurres (FTP, Telnet, SMTP…)", ev)
    if ip in gateways:
        _add(scores, "router", 12, "passerelle d'un réseau analysé", ev)
    for pat, kind, w in DESCR_HINTS:
        if re.search(pat, text):
            _add(scores, kind, w, f"description « {re.search(pat, text).group(0).strip()} »", ev)
    for pat, kind, w in VENDOR_HINTS:
        if vendor and re.search(pat, vendor):
            _add(scores, kind, w, f"fabricant {h.get('vendor')}", ev)
            break
    for p in ports_:
        if p in PORT_HINTS:
            k, w = PORT_HINTS[p]
            _add(scores, k, w, f"port {p} ouvert", ev)
    for s in md.get("services") or []:
        if s in MDNS_HINTS:
            _add(scores, MDNS_HINTS[s], 3, f"service annoncé {s}", ev)
    dt = (ss.get("device_type") or "").lower()
    if "internetgatewaydevice" in dt:
        _add(scores, "router", 6, "UPnP passerelle Internet", ev)
    elif "printer" in dt:
        _add(scores, "printer", 6, "UPnP imprimante", ev)
    elif "mediarenderer" in dt or "mediaserver" in dt:
        _add(scores, "media", 3, "UPnP multimédia", ev)
    if nb.get("dc"):
        _add(scores, "server", 8, "contrôleur de domaine (NetBIOS)", ev)
    elif nb.get("name"):
        _add(scores, "pc", 1, "nom NetBIOS", ev)
    if {88, 389, 445, 53} <= ports_ or 3268 in ports_:
        _add(scores, "server", 6, "Kerberos + LDAP (contrôleur de domaine)", ev)
    if h.get("ttl") == 255 and not scores:
        _add(scores, "switch", 2, "TTL 255 (système réseau)", ev)
    if h.get("random_mac"):
        _add(scores, "phone", 1, "adresse MAC aléatoire (téléphone, tablette, PC récent)", ev)
    if "apple" in vendor and (548 in ports_ or "macbook" in text or "imac" in text or "mac mini" in text):
        _add(scores, "mac", 5, "Apple + partage AFP / nom de Mac", ev)
    if re.search(r"\b(iphone|ipad|android|galaxy|pixel|redmi)\b", text):
        _add(scores, "phone", 5, "nom de téléphone", ev)
    if "linux" in text and not scores:
        _add(scores, "linux", 2, "Linux", ev)

    if scores:
        kind = max(scores, key=lambda k: scores[k])
        conf = "élevée" if scores[kind] >= 8 else "moyenne" if scores[kind] >= 4 else "faible"
    else:
        kind, conf = "unknown", ""
    h["kind"] = kind
    h["kind_label"] = KINDS[kind]
    h["name"] = best_name(h)
    h["model"] = model_of(h)
    h["os"] = os_guess(h, kind)
    h["evidence"] = ev[:12]
    h["confidence"] = conf
    h["network_gear"] = kind in NETWORK_GEAR
    return h


def classify_all(snap: dict) -> dict[str, dict]:
    hosts = snap.get("hosts") or {}
    gws = {n.get("gateway") for n in snap.get("networks") or [] if n.get("gateway")}
    if snap.get("default_gateway"):
        gws.add(snap["default_gateway"])
    gmacs = {hosts[g]["mac"] for g in gws if g in hosts and hosts[g].get("mac")}
    for h in hosts.values():
        classify(h, gws, gmacs)
    return hosts
