"""Règles « Sécurité » : services exposés sur le réseau interne, protocoles
non chiffrés, SNMP par défaut, SMBv1, certificats, segmentation, appareils
inconnus ou nouveaux. Constat depuis le réseau (vue d'un poste branché), pas
un test d'intrusion : aucun mot de passe n'est essayé."""
from __future__ import annotations

from datetime import datetime, timezone

from .context import Ctx
from .model import CRIT, INFO, MAJOR, MINOR, SEC, parse_dt

R = []


def rule(fn):
    R.append(fn)
    return fn


# (ports, titre, gravité, gravité si équipement réseau, impact, action)
EXPOSED = [
    ({23}, "Telnet (administration non chiffrée)", MAJOR, CRIT,
     "Les identifiants et toute la session circulent en clair : n'importe quel poste du réseau peut les capturer.",
     "Désactiver Telnet et administrer en SSH."),
    ({21}, "FTP (transfert non chiffré)", MINOR, MINOR,
     "Identifiants et fichiers circulent en clair.", "Remplacer par SFTP ou FTPS, ou désactiver le service s'il est inutile."),
    ({2375}, "API Docker sans chiffrement ni authentification", CRIT, CRIT,
     "Quiconque atteint ce port prend le contrôle total du serveur.", "Fermer le port 2375 ou exiger TLS mutuel (2376)."),
    ({6379}, "Redis accessible sur le réseau", MAJOR, MAJOR,
     "Redis n'a souvent aucun mot de passe : lecture/écriture des données, voire prise de contrôle.",
     "Limiter l'écoute à localhost ou au réseau serveurs, activer l'authentification."),
    ({11211}, "Memcached accessible sur le réseau", MAJOR, MAJOR, "Données en cache lisibles sans authentification.",
     "Limiter l'écoute à localhost."),
    ({27017}, "MongoDB accessible sur le réseau", MAJOR, MAJOR, "Base souvent sans authentification.",
     "Activer l'authentification et filtrer l'accès."),
    ({9200}, "Elasticsearch accessible sur le réseau", MAJOR, MAJOR, "Données indexées lisibles et modifiables.",
     "Activer la sécurité d'Elasticsearch et filtrer l'accès."),
    ({5555}, "Débogage Android (ADB) ouvert", MAJOR, MAJOR, "Prise de contrôle complète de l'appareil Android.",
     "Désactiver le débogage réseau sur l'appareil."),
    ({5900}, "Partage d'écran VNC", MINOR, MINOR, "VNC est souvent protégé par un mot de passe faible et non chiffré.",
     "Désactiver VNC ou le restreindre ; préférer une solution chiffrée avec authentification forte."),
    ({623}, "Interface IPMI (administration matérielle)", MINOR, MINOR,
     "IPMI a des failles connues (récupération des empreintes de mots de passe).",
     "Placer les cartes d'administration (iLO, iDRAC, XCC) dans un réseau d'administration séparé."),
    ({1433, 3306, 5432}, "Base de données accessible depuis le réseau des utilisateurs", INFO, INFO,
     "Une base de données joignable de partout augmente la surface d'attaque.",
     "Limiter l'accès aux seuls serveurs d'application (pare-feu)."),
    ({502, 47808, 4840}, "Protocole industriel / GTB (Modbus, BACnet, OPC UA)", MAJOR, MAJOR,
     "Ces protocoles n'ont pas d'authentification : commande des automatismes depuis n'importe quel poste.",
     "Isoler la GTB / les automates dans un réseau dédié."),
    ({7547}, "Interface TR-069 (gestion opérateur) joignable", MINOR, MINOR,
     "Service de télégestion des box, historiquement très attaqué.", "Vérifier que ce port n'est joignable que par l'opérateur."),
]


@rule
def exposed_services(c: Ctx):
    for ports_, title, sev, sev_gear, impact, fix in EXPOSED:
        hits, gear_hit = [], False
        for h in c.active():
            if set(h.get("ports") or []) & ports_:
                p = sorted(set(h["ports"]) & ports_)
                hits.append(f"{c.label(h['ip'])} : port {', '.join(map(str, p))}"
                            + (f" — {h['banners'].get(str(p[0]))}" if (h.get("banners") or {}).get(str(p[0])) else ""))
                gear_hit = gear_hit or h.get("network_gear")
        if hits:
            key = "-".join(map(str, sorted(ports_)))
            c.add(f"sec.port.{key}", SEC, sev_gear if gear_hit else sev, f"{title} : {len(hits)} appareil(s)",
                  "Service détecté ouvert depuis le poste d'audit.", impact, fix, hits)


@rule
def snmp_security(c: Ctx):
    default, v12 = [], []
    for ip, d in c.snmp.items():
        if d.get("default_community"):
            default.append(c.label(ip))
        elif d.get("version") in ("1", "2c"):
            v12.append(c.label(ip))
    if default:
        c.add("sec.snmp.public", SEC, MAJOR, f"Communauté SNMP par défaut « public » acceptée ({len(default)} appareil(s))",
              "Ces appareils répondent à la communauté SNMP connue de tous.",
              "N'importe quel poste lit la configuration réseau (interfaces, tables ARP et MAC, routes, voire comptes) — "
              "information précieuse pour un attaquant. Si l'écriture est permise, la configuration peut être modifiée.",
              "Changer la communauté (ou passer en SNMPv3 avec authentification et chiffrement) et limiter SNMP aux IP de supervision.",
              default)
    if v12:
        c.add("sec.snmp.v2", SEC, MINOR, f"SNMP v1/v2c (non chiffré) utilisé sur {len(v12)} appareil(s)",
              "La communauté SNMP circule en clair à chaque requête.", "Elle peut être capturée sur le réseau.",
              "Passer en SNMPv3 (authPriv) quand l'équipement le permet ; sinon restreindre SNMP aux IP de supervision.", v12)
    if c.snmp and not default and not v12:
        c.ok("sec.snmp", SEC, "SNMP protégé (v3) sur les équipements interrogés")


@rule
def smb1(c: Ctx):
    hh = [h for h in c.active() if h.get("smb1") is True]
    hits = [c.label(h["ip"]) for h in hh]
    tested = [h for h in c.active() if h.get("smb1") is not None]
    if hits:
        srv = any(h.get("kind") in ("server", "nas") for h in hh)
        c.add("sec.smb1", SEC, CRIT if srv else MAJOR, f"SMBv1 encore accepté par {len(hits)} appareil(s)",
              "Le protocole de partage de fichiers SMB version 1 est activé.",
              "Protocole obsolète exploité par les rançongiciels WannaCry / NotPetya pour se propager.",
              "Désactiver SMBv1 (Windows : fonctionnalité « Support de partage de fichiers SMB 1.0 » ; NAS : SMB minimum = SMB2). "
              "Remplacer les vieux copieurs/scanners qui l'exigent.", hits)
    elif tested:
        c.ok("sec.smb1", SEC, f"SMBv1 refusé par les {len(tested)} appareil(s) testé(s)")


@rule
def web_admin(c: Ctx):
    clear, expired, soon, weak, selfsigned, oldtls = [], [], [], [], [], []
    now = datetime.now(timezone.utc)
    for h in c.active():
        webs = [w for w in h.get("web") or [] if w and not w.get("error")]
        if not webs:
            continue
        has_tls = any(w.get("tls") for w in webs)
        plain_login = [w for w in webs if not w.get("tls") and w.get("status") in (200, 401)
                       and not str(w.get("location", "")).startswith("https")]
        if plain_login and not has_tls and h.get("kind") in ("router", "switch", "ap", "printer", "camera", "nas", "ups", "mgmt", "modem"):
            clear.append(f"{c.label(h['ip'])} : http://{h['ip']}:{plain_login[0]['port']} « {plain_login[0].get('title') or ''} »")
        for w in webs:
            cert = w.get("cert") or {}
            if not cert.get("not_after"):
                continue
            na = parse_dt(cert["not_after"])
            tag = f"{c.label(h['ip'])} port {w['port']} : {cert.get('subject') or '?'}"
            if na and na < now:
                expired.append(f"{tag}, expiré le {na:%d/%m/%Y}")
            elif na and (na - now).days < 30:
                soon.append(f"{tag}, expire le {na:%d/%m/%Y}")
            if cert.get("key_type") == "RSA" and cert.get("key_bits") and cert["key_bits"] < 2048:
                weak.append(f"{tag}, clé RSA {cert['key_bits']} bits")
            if str(cert.get("sig_alg", "")).startswith(("md5", "sha1")):
                weak.append(f"{tag}, signature {cert['sig_alg']}")
            if cert.get("self_signed"):
                selfsigned.append(tag)
            if w.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                oldtls.append(f"{tag} : {w['tls_version']}")
    if clear:
        c.add("sec.web.clear", SEC, MINOR, f"Interfaces d'administration en HTTP non chiffré ({len(clear)})",
              "Ces équipements ne proposent leur administration qu'en HTTP.",
              "Le mot de passe administrateur circule en clair sur le réseau.",
              "Activer HTTPS (et désactiver HTTP) dans les réglages de chaque équipement.", clear)
    if expired:
        c.add("sec.cert.expired", SEC, MINOR, f"Certificats expirés ({len(expired)})", "",
              "Avertissements de sécurité que les utilisateurs apprennent à ignorer ; certaines applications refusent la connexion.",
              "Renouveler les certificats.", expired)
    if soon:
        c.add("sec.cert.soon", SEC, MINOR, f"Certificats qui expirent dans moins de 30 jours ({len(soon)})", "",
              "Interruption de service à l'échéance.", "Planifier le renouvellement.", soon, True)
    if weak:
        c.add("sec.cert.weak", SEC, MINOR, "Certificats faibles (clé courte ou signature obsolète)", "",
              "Chiffrement attaquable ; refusés par les navigateurs récents.", "Régénérer un certificat RSA 2048+ / SHA-256.", weak)
    if oldtls:
        c.add("sec.tls.old", SEC, MINOR, "Protocoles TLS obsolètes acceptés (TLS 1.0 / 1.1)", "",
              "Versions vulnérables, désactivées par les navigateurs.", "Mettre à jour le firmware ; n'autoriser que TLS 1.2 et 1.3.", oldtls)
    if selfsigned:
        c.add("sec.cert.self", SEC, INFO, f"Certificats auto-signés sur {len(selfsigned)} interface(s)",
              "Courant sur les équipements ; provoque un avertissement du navigateur.", "",
              "Facultatif : utiliser des certificats émis par une autorité interne pour pouvoir détecter une usurpation.", selfsigned)


@rule
def segmentation(c: Ctx):
    """Réseau « à plat » : postes, serveurs, caméras, objets connectés et imprimantes dans le même sous-réseau."""
    for n in c.networks:
        if n.get("source") != "local":
            continue
        hs = [h for h in c.active() if h.get("network") == n["network"]]
        kinds = {}
        for h in hs:
            kinds.setdefault(h.get("kind"), []).append(h)
        users = len(kinds.get("pc", [])) + len(kinds.get("mac", [])) + len(kinds.get("phone", []))
        risky = {k: kinds[k] for k in ("camera", "iot", "media", "printer", "voip", "mgmt", "ups") if kinds.get(k)}
        n_risky = sum(len(v) for v in risky.values())
        if users and n_risky >= 3:
            ev = [f"{len(v)} {c.hosts[v[0]['ip']]['kind_label'].lower()}" for v in risky.values()]
            sev = MAJOR if any(k in risky for k in ("camera", "iot", "mgmt")) and n_risky >= 6 else MINOR
            c.add(f"sec.flat.{n['network']}", SEC, sev, f"Réseau à plat : postes et objets connectés mélangés ({n['network']})",
                  f"{users} poste(s)/téléphone(s) partagent le même réseau que {n_risky} appareils moins sûrs.",
                  "Caméras, objets connectés et imprimantes reçoivent rarement des mises à jour : un seul compromis donne accès à tous les postes.",
                  "Créer des VLAN séparés (postes / serveurs / caméras / objets / invités) avec un filtrage entre eux.", ev)
        if kinds.get("mgmt"):
            c.add(f"sec.mgmt.{n['network']}", SEC, MINOR, "Cartes d'administration de serveurs sur le réseau des utilisateurs",
                  "", "Ces cartes donnent un contrôle total du serveur (console, alimentation).",
                  "Les placer dans un VLAN d'administration réservé.", [c.label(h["ip"]) for h in kinds["mgmt"]])


@rule
def upnp(c: Ctx):
    for ip in c.gateways:
        h = c.hosts.get(ip) or {}
        ss = (h.get("names") or {}).get("ssdp") or {}
        if "internetgatewaydevice" in " ".join(ss.get("types") or []).lower() + (ss.get("device_type") or "").lower():
            c.add(f"sec.upnp.{ip}", SEC, MINOR, f"UPnP activé sur la passerelle {c.label(ip)}",
                  "N'importe quel appareil du réseau peut ouvrir lui-même des ports vers Internet.",
                  "Un appareil compromis (caméra, objet connecté) peut s'exposer sur Internet sans que personne ne le sache.",
                  "Désactiver UPnP sur la box / le routeur et créer à la main les redirections nécessaires.")


@rule
def unknown_devices(c: Ctx):
    unk = [h for h in c.active() if h.get("kind") == "unknown" and not h.get("name")]
    if unk:
        c.add("sec.unknown", SEC, INFO, f"{len(unk)} appareil(s) non identifié(s)",
              "Ni nom, ni service annoncé, ni fabricant reconnu.",
              "Un appareil inconnu peut être légitime (objet connecté discret) ou indésirable.",
              "Les identifier (étiquette, fabricant de la carte, port du switch) et les documenter.",
              [f"{h['ip']} — MAC {h.get('mac') or '?'} {h.get('vendor') or ''}" for h in unk[:40]])
    rnd = [h for h in c.active() if h.get("random_mac")]
    if rnd:
        c.add("sec.randmac", SEC, INFO, f"{len(rnd)} appareil(s) avec une adresse MAC aléatoire",
              "Téléphones, tablettes et PC récents changent d'adresse MAC par réseau (confidentialité Wi-Fi).",
              "Ces appareils ne peuvent pas être suivis ni autorisés par leur MAC (filtrage MAC, réservations DHCP).",
              "Réseau d'entreprise : désactiver l'adresse privée sur les appareils de la société, ou authentifier en 802.1X.",
              [f"{h['ip']} — {h.get('name') or h.get('kind_label')}" for h in rnd[:30]])
    hp = [h for h in c.hosts.values() if h.get("kind") == "honeypot"]
    if hp:
        c.add("sec.honeypot", SEC, INFO, "Leurre de sécurité (honeypot) détecté",
              "Une adresse partage la MAC de la passerelle et expose des services « appâts » ; elle est exclue des autres constats.",
              "Bonne pratique : les connexions vers ce leurre signalent un appareil qui explore le réseau.", "",
              [h["ip"] for h in hp])


@rule
def new_devices(c: Ctx):
    if not c.prev:
        return
    before = {(h.get("mac") or ip) for ip, h in (c.prev.get("hosts") or {}).items()}
    new = [h for h in c.active() if (h.get("mac") or h["ip"]) not in before]
    gone = [h for ip, h in (c.prev.get("hosts") or {}).items() if (h.get("mac") or ip) not in
            {(x.get("mac") or x["ip"]) for x in c.hosts.values()} and not h.get("inactive")]
    if new:
        c.add("sec.new", SEC, INFO, f"{len(new)} nouvel(le)(s) appareil(s) depuis le précédent diagnostic",
              "", "", "Vérifier qu'ils sont tous connus.",
              [f"{h['ip']} — {h.get('name') or h.get('kind_label')} {h.get('vendor') or ''}" for h in new[:40]])
    if gone:
        c.add("sec.gone", SEC, INFO, f"{len(gone)} appareil(s) absent(s) depuis le précédent diagnostic", "", "", "",
              [f"{h['ip']} — {h.get('name') or h.get('kind_label') or ''}" for h in gone[:40]])


@rule
def mdns_relay(c: Ctx):
    el = c.snap.get("mdns_elsewhere") or {}
    if el:
        c.add("sec.mdns.relay", SEC, INFO, f"{len(el)} appareil(s) d'autres réseaux annoncés ici (relais mDNS)",
              "Le routeur relaie les annonces Bonjour/mDNS d'autres VLAN vers ce réseau (imprimantes, TV, enceintes…).",
              "Pratique, mais cela affaiblit la séparation entre réseaux (ex. invités ↔ entreprise).",
              "Limiter le relais mDNS aux services et réseaux nécessaires.",
              [f"{ip} — {', '.join((e.get('instances') or e.get('names') or ['?'])[:1])}" for ip, e in list(el.items())[:30]])


RULES = R
