"""Règles « Câblage et équipements » : erreurs de ports, duplex, débits
négociés, spanning tree, PoE, charge des équipements, firmware et fin de
support, événements relevés dans les journaux (SSH)."""
from __future__ import annotations

import re

from .context import Ctx
from .model import CRIT, INFO, LAN, MAJOR, MINOR, fr_num

R = []


def rule(fn):
    R.append(fn)
    return fn


def _gb(x) -> float:
    return (x or 0) / 1e9


@rule
def port_errors(c: Ctx):
    """Erreurs de réception (CRC, alignement…) : câble, prise, cordon ou port défectueux."""
    for ip in c.snmp:
        live, hist = [], []
        for i in c.phys_ifaces(ip):
            err = (i.get("in_err") or 0)
            fcs = i.get("fcs") or 0
            d_err = c.delta(ip, i, "in_err")
            d_fcs = c.delta(ip, i, "fcs")
            dt = c.interval(ip)
            vol = _gb(i.get("in_oct"))
            if (d_err or 0) + (d_fcs or 0) > 0:
                live.append(f"{c.if_label(i)} : +{(d_err or 0) + (d_fcs or 0)} erreur(s) en {dt:.0f} s pendant le diagnostic"
                            + (f" (total {fr_num(err)})" if err else ""))
            elif err + fcs >= 1000 and (vol == 0 or (err + fcs) / max(vol, 0.001) > 50):
                hist.append(f"{c.if_label(i)} : {fr_num(max(err, fcs))} erreurs en réception depuis le démarrage"
                            + (f" pour {vol:,.0f} Go reçus".replace(",", " ") if vol else ""))
        if live:
            c.add(f"lan.err.live.{ip}", LAN, MAJOR, f"Erreurs de transmission EN COURS sur {c.label(ip)}",
                  f"{len(live)} port(s) reçoivent des trames corrompues en ce moment.",
                  "Câble abîmé, prise murale ou cordon défectueux, port qui lâche, ou interférences : retransmissions, lenteurs, coupures.",
                  "Remplacer le cordon, tester le câblage (testeur / certification), changer de port ; vérifier le duplex.",
                  live, True)
        if hist:
            c.add(f"lan.err.hist.{ip}", LAN, MINOR, f"Erreurs de réception accumulées sur {c.label(ip)}",
                  f"{len(hist)} port(s) ont enregistré beaucoup d'erreurs depuis le démarrage (pas pendant le diagnostic).",
                  "Problème passé ou intermittent (câble déplacé, appareil défectueux débranché depuis).",
                  "Remettre les compteurs à zéro et revérifier ; inspecter le câblage de ces ports.", hist, True)


@rule
def discards(c: Ctx):
    for ip in c.snmp:
        hot = []
        for i in c.phys_ifaces(ip):
            d = c.delta(ip, i, "out_disc")
            dt = c.interval(ip)
            if d and dt and d / dt > 5:
                hot.append(f"{c.if_label(i)} : {d / dt:.0f} paquets rejetés / s en sortie")
        if hot:
            c.add(f"lan.disc.{ip}", LAN, MINOR, f"Paquets rejetés faute de place sur {c.label(ip)}",
                  "Les files d'attente de sortie débordent : le lien est saturé par moments.",
                  "Lenteurs et coupures de visio aux heures chargées.",
                  "Identifier le flux (sauvegarde, vidéosurveillance…), agréger des liens ou passer le lien en débit supérieur ; activer la QoS.",
                  hot, True)


@rule
def duplex_speed(c: Ctx):
    for ip in c.snmp:
        half, slow10, slow100 = [], [], []
        dev_gear = (c.hosts.get(ip) or {}).get("network_gear")
        macs = c.macs_per_if(ip)
        for i in c.phys_ifaces(ip):
            mb = i.get("mbps") or 0
            if i.get("duplex") == "half" and mb:
                half.append(f"{c.if_label(i)} : {mb} Mb/s half-duplex"
                            + (f", {fr_num(i.get('late_coll'))} collisions tardives" if i.get("late_coll") else ""))
            if dev_gear and i.get("type") != 71:
                nb = c.lldp_neighbor(ip, i)
                who = f" → {nb.get('sys_name') or nb.get('chassis')}" if nb else ""
                if mb == 10:
                    slow10.append(f"{c.if_label(i)} : 10 Mb/s{who}")
                elif mb == 100 and nb and any(x in (nb.get("caps") or []) for x in ("pont/switch", "borne Wi-Fi", "routeur")):
                    slow100.append(f"{c.if_label(i)} : 100 Mb/s{who}")
                elif mb == 100 and not nb and macs.get(str(i.get("index")), 0) >= 4:
                    slow100.append(f"{c.if_label(i)} : 100 Mb/s, {macs[str(i.get('index'))]} adresses MAC derrière ce port "
                                   "(switch, borne ou boîtier en aval)")
        if half:
            c.add(f"lan.duplex.{ip}", LAN, MAJOR, f"Port(s) en half-duplex sur {c.label(ip)}",
                  "Un lien Ethernet moderne doit fonctionner en full-duplex.",
                  "Typique d'un « duplex mismatch » (un côté forcé, l'autre en automatique) : collisions, débit effondré, coupures.",
                  "Mettre les deux extrémités en négociation automatique (ou les deux forcées identiquement) ; vérifier le câble.",
                  half)
        if slow10:
            c.add(f"lan.10m.{ip}", LAN, MINOR, f"Port(s) négocié(s) à 10 Mb/s sur {c.label(ip)}",
                  "Le lien s'est établi à la vitesse minimale.",
                  "Câble à 2 paires abîmées, appareil très ancien ou prise défectueuse.", "Tester le câble et la prise ; remplacer le cordon.",
                  slow10)
        if slow100:
            c.add(f"lan.100m.{ip}", LAN, MAJOR, f"Lien entre équipements réseau limité à 100 Mb/s sur {c.label(ip)}",
                  "Un lien vers un autre switch ou une borne Wi-Fi est négocié à 100 Mb/s.",
                  "Tout le trafic des appareils situés derrière passe dans ce « goulot ».",
                  "Vérifier le câble (une paire coupée limite à 100 Mb/s) et la configuration des ports.", slow100)


@rule
def stp(c: Ctx):
    for ip, d in c.snmp.items():
        s = d.get("stp")
        if not s or s.get("top_changes") is None:
            continue
        since = s.get("since_change_s")
        up = (d.get("sys") or {}).get("uptime_s") or 0
        n = s.get("top_changes") or 0
        ev = [f"{n} changements de topologie depuis le démarrage ({up / 86400:.0f} j)",
              f"dernier il y a {since / 60:.0f} min" if since is not None else ""]
        rate = n / max(1, up / 86400)
        if since is not None and since < 900 and rate > 20:
            c.add(f"lan.stp.{ip}", LAN, MAJOR, f"Spanning tree instable sur {c.label(ip)}",
                  f"La topologie change très souvent ({rate:.0f} fois par jour en moyenne, la dernière il y a {since / 60:.0f} min).",
                  "À chaque changement, les tables MAC sont purgées : microcoupures et inondation de trafic sur tout le réseau.",
                  "Identifier le port qui « bagotte » (journaux) ; passer les ports des postes en « edge / portfast » ; vérifier les boucles.",
                  ev, True)
        elif rate > 50:
            c.add(f"lan.stp.{ip}", LAN, MINOR, f"Nombreux changements de topologie sur {c.label(ip)}",
                  f"{rate:.0f} changements par jour en moyenne.", "Microcoupures à chaque changement.",
                  "Configurer les ports d'accès en « edge / portfast » pour qu'un poste allumé ou éteint ne déclenche pas de changement.", ev)
        else:
            c.ok(f"lan.stp.{ip}", LAN, f"Spanning tree stable sur {c.label(ip)}", "; ".join(x for x in ev if x))
        blocking = [k for k, v in (d.get("stp_ports") or {}).items() if v == "bloquant"]
        if blocking:
            c.add(f"lan.stp.block.{ip}", LAN, INFO, f"{len(blocking)} port(s) bloqué(s) par le spanning tree sur {c.label(ip)}",
                  "Le spanning tree bloque des liens redondants pour éviter une boucle : normal si ces liens de secours sont voulus.",
                  "", "Vérifier que ces liens redondants sont intentionnels.", [f"port de pont {b}" for b in blocking])


@rule
def poe(c: Ctx):
    for ip, d in c.snmp.items():
        p = d.get("poe")
        if not p:
            continue
        for k, power in (p.get("power_w") or {}).items():
            used = (p.get("used_w") or {}).get(k)
            if not power or used is None:
                continue
            pct = 100 * used / power
            ev = [f"{used} W consommés sur {power} W disponibles ({pct:.0f} %)"]
            if pct >= 90:
                c.add(f"lan.poe.{ip}.{k}", LAN, MAJOR, f"Budget PoE presque épuisé sur {c.label(ip)} ({pct:.0f} %)",
                      "Le switch alimente presque à pleine capacité.",
                      "Un appareil de plus (ou un pic de consommation : caméra infrarouge la nuit, chauffage) et des ports s'éteignent.",
                      "Répartir les appareils PoE sur un autre switch ou utiliser un switch au budget plus élevé.", ev, True)
            elif pct >= 75:
                c.add(f"lan.poe.{ip}.{k}", LAN, MINOR, f"Budget PoE chargé sur {c.label(ip)} ({pct:.0f} %)", "", "",
                      "Prévoir de la marge avant d'ajouter des appareils alimentés.", ev, True)
            else:
                c.ok(f"lan.poe.{ip}.{k}", LAN, f"Budget PoE correct sur {c.label(ip)}", ev[0])
        faults = [k for k, v in (d.get("poe_ports") or {}).items() if v in ("défaut", "autre défaut")]
        if faults:
            c.add(f"lan.poe.fault.{ip}", LAN, MINOR, f"Port(s) PoE en défaut sur {c.label(ip)}",
                  "L'alimentation a été coupée sur ces ports (surconsommation, court-circuit, appareil incompatible).",
                  "L'appareil branché n'est pas alimenté ou redémarre.", "Vérifier l'appareil et le câble ; contrôler la classe PoE.",
                  [f"port {f}" for f in faults])


@rule
def device_load(c: Ctx):
    for ip, d in c.snmp.items():
        h = c.hosts.get(ip) or {}
        cpu = d.get("cpu")
        if cpu and cpu.get("avg", 0) >= 85:
            c.add(f"lan.cpu.{ip}", LAN, MAJOR if h.get("network_gear") else MINOR, f"Processeur saturé sur {c.label(ip)} ({cpu['avg']} %)",
                  "Charge processeur relevée par SNMP au moment du diagnostic.",
                  "Un routeur ou un pare-feu saturé ralentit tout le réseau (inspection, VPN, filtrage).",
                  "Identifier la cause (inspection, VPN, attaque, boucle) ; dimensionner l'équipement.", [f"moyenne {cpu['avg']} %, max {cpu['max']} %"])
        for s in d.get("storage") or []:
            if s.get("type") == "2" and s.get("size") and s["used"] / s["size"] > 0.95 and h.get("network_gear"):
                c.add(f"lan.mem.{ip}", LAN, MINOR, f"Mémoire presque pleine sur {c.label(ip)}",
                      f"{100 * s['used'] / s['size']:.0f} % de la mémoire vive utilisée.",
                      "Un équipement réseau à court de mémoire peut redémarrer ou perdre des fonctions.",
                      "Vérifier les fonctions actives (IDS, journalisation) et la version du firmware.", predictive=True)


@rule
def uptime(c: Ctx):
    long_up, recent = [], []
    for ip, d in c.snmp.items():
        h = c.hosts.get(ip) or {}
        if not h.get("network_gear"):
            continue
        up = (d.get("sys") or {}).get("uptime_s")
        if up is None:
            continue
        if up > 400 * 86400:
            long_up.append(f"{c.label(ip)} : allumé depuis {up / 86400:.0f} jours")
        elif up < 86400:
            recent.append(f"{c.label(ip)} : redémarré il y a {up / 3600:.1f} h")
    if long_up:
        c.add("lan.uptime.long", LAN, MINOR, "Équipements réseau sans redémarrage depuis plus d'un an",
              "Aucune mise à jour de firmware n'a donc pu être appliquée depuis.",
              "Failles de sécurité et bogues corrigés depuis non appliqués.",
              "Planifier une mise à jour du firmware (avec redémarrage) dans une fenêtre de maintenance.", long_up, True)
    if recent:
        c.add("lan.uptime.recent", LAN, INFO, "Équipements réseau redémarrés récemment",
              "Redémarrage volontaire, coupure de courant ou plantage ?", "Des redémarrages inexpliqués signalent un équipement ou une alimentation instable.",
              "Vérifier si ce redémarrage était prévu ; sinon, envisager un onduleur.", recent)


# modèles en fin de support (motif sur sysDescr / modèle) : (motif, libellé, depuis)
EOL = [
    (r"procurve.*\b(2510|2610|2626|2650|2810|2824|2848|2900|2910|3500|5300|5400zl)\b|\bJ9(019|020|085|086|087|088|145|146|147|148)A\b",
     "HP ProCurve (gamme arrêtée)", "fin de support logiciel"),
    (r"catalyst (2950|2960[^-xs]|3550|3560[^-cx]|3750[^-x]|4500)|c29(50|60)[^x]|c3(55|56|75)0[^x]|ws-c2960-",
     "Cisco Catalyst ancienne génération", "fin de support Cisco"),
    (r"\basa ?55(05|10|20|40|50|80|85)\b|\bpix\b", "Cisco ASA 5500 / PIX", "fin de support Cisco"),
    (r"\bfortigate[- ]?(30|40|50|60|80|90|100)[cd]\b", "FortiGate (ancienne génération)", "fin de support Fortinet"),
    (r"\b(usg[- ]?3p|usg-pro-4|unifi security gateway)\b", "UniFi Security Gateway (USG)", "fin de vie Ubiquiti"),
    (r"\b(dgs-1210-(10|16|24|28|48)|des-\d{4})\b", "D-Link ancienne génération", "plus de mises à jour"),
    (r"\bnetgear (gs108t|gs110t|fs\d{3})\b|\bfs\d{3}t?\b", "Netgear ancienne génération", "plus de mises à jour"),
    (r"windows server 20(03|08|12)", "Windows Server 2012 ou antérieur", "plus de correctifs de sécurité"),
    (r"\bsonicwall (tz ?(100|105|180|190|200|205|210|215)|nsa ?(240|2400)\b)", "SonicWall ancienne génération", "fin de support"),
    (r"\bsynology.*\b(ds(1\d|2\d|4\d|7\d)[0-9]?\+?)\b.*dsm ?[56]\.", "Synology sous DSM 6 ou antérieur", "fin des correctifs DSM 6"),
    (r"\bmikrotik.*routeros (5|6\.[0-3]\d)\.", "MikroTik RouterOS ancien", "version obsolète"),
]


@rule
def end_of_life(c: Ctx):
    hits = []
    for h in c.active():
        text = " ".join(str(x) for x in ((h.get("snmp") or {}).get("descr"), h.get("model"), (h.get("names") or {}).get("ssdp", {}).get("model")) if x)
        for pat, label, why in EOL:
            if text and re.search(pat, text, re.I):
                hits.append(f"{c.label(h['ip'])} : {label} ({why})")
                break
    if hits:
        c.add("lan.eol", LAN, MAJOR, f"{len(hits)} équipement(s) en fin de support",
              "Ces modèles ou versions ne reçoivent plus de correctifs de sécurité.",
              "Failles connues non corrigées, pas de remplacement sous garantie, pièces introuvables.",
              "Prévoir le remplacement dans le budget ; en attendant, isoler leur administration.", hits, True)


@rule
def firmware_inventory(c: Ctx):
    rows = []
    for ip, d in c.snmp.items():
        h = c.hosts.get(ip) or {}
        if not h.get("network_gear"):
            continue
        sw = next((e.get("sw") or e.get("fw") for e in d.get("entities") or [] if e.get("sw") or e.get("fw")), "")
        descr = (d.get("sys") or {}).get("descr") or ""
        rows.append(f"{c.label(ip)} : {sw or descr[:90]}")
    if rows:
        c.add("lan.fw.inv", LAN, INFO, f"Versions logicielles des {len(rows)} équipement(s) réseau interrogé(s)",
              "À comparer avec les dernières versions publiées par chaque constructeur.", "", "", rows)


@rule
def ssh_logs(c: Ctx):
    labels = {"loop": ("Boucle réseau détectée", CRIT, "Une boucle fait tourner le trafic indéfiniment : saturation et coupure générale.",
                       "Repérer le port indiqué, débrancher le câble en double (souvent une prise murale reliée à une autre) ; activer loop-protect / BPDU guard."),
              "mac_flap": ("Adresses MAC qui changent de port (« flapping »)", CRIT, "Signe classique d'une boucle ou d'un mauvais agrégat de liens.",
                           "Rechercher la boucle ou le lien agrégé mal configuré entre les ports cités."),
              "storm": ("Tempête de broadcast signalée", MAJOR, "Le réseau est inondé de diffusions : tout ralentit.",
                        "Rechercher la boucle ou l'appareil bavard ; activer le contrôle de tempête."),
              "err_disabled": ("Ports désactivés automatiquement pour erreur", MAJOR, "Le switch a coupé des ports (boucle, sécurité, câble).",
                               "Identifier la cause sur chaque port avant de le réactiver."),
              "duplex": ("Désaccord de duplex signalé", MAJOR, "Débit effondré et erreurs sur le lien concerné.",
                         "Mettre les deux extrémités en négociation automatique."),
              "crc": ("Erreurs CRC / alignement signalées", MAJOR, "Câblage ou port défectueux.", "Tester le câblage des ports cités."),
              "collision": ("Collisions anormales signalées", MAJOR, "Duplex incorrect ou câble trop long.", "Vérifier duplex et câble."),
              "stp": ("Changements de topologie spanning tree", MINOR, "Microcoupures à chaque changement.",
                      "Passer les ports d'accès en edge/portfast ; rechercher le port instable."),
              "link_down": ("Liens qui tombent et remontent souvent", MINOR, "Appareil, câble ou alimentation instable.",
                            "Identifier les ports concernés dans le journal."),
              "poe": ("Incidents d'alimentation PoE", MINOR, "Appareils alimentés qui s'éteignent.", "Vérifier le budget et les appareils."),
              "hw_temp": ("Alerte de température ou de ventilation", MAJOR, "Risque de panne matérielle.", "Vérifier la ventilation de la baie."),
              "hw_psu": ("Défaut d'alimentation électrique", MAJOR, "L'équipement peut s'arrêter.", "Remplacer le bloc d'alimentation."),
              "ip_conflict": ("Conflit d'adresse IP signalé", MAJOR, "Deux appareils utilisent la même adresse : coupures.",
                              "Identifier les deux appareils (MAC citées) et corriger l'adressage."),
              "auth_fail": ("Échecs de connexion à l'administration", INFO, "Tentatives d'accès avec un mauvais mot de passe.",
                            "Vérifier leur origine.")}
    refused = [f"{c.label(ip)} : {r.get('error') or 'échec'}" for ip, r in c.ssh.items() if not r.get("ok")]
    if refused:
        c.nc("lan.ssh.refused", LAN, f"Journaux non lus sur {len(refused)} équipement(s) (accès SSH refusé ou impossible)",
             " · ".join(refused[:15]) + ". Fournir un identifiant en lecture valable pour ces équipements.")
    for ip, r in c.ssh.items():
        if not r.get("ok"):
            continue
        from ..net.ssh import scan_logs
        evs = scan_logs(r.get("outputs") or {}) if r.get("outputs") else (r.get("events") or {})
        if not evs:
            c.ok(f"lan.logs.{ip}", LAN, f"Aucun incident notable dans le journal de {c.label(ip)}")
        for cat, e in evs.items():
            title, sev, impact, fix = labels.get(cat, (cat, MINOR, "", ""))
            if cat == "link_down" and e["n"] < 5:
                continue
            c.add(f"lan.logs.{cat}.{ip}", LAN, sev, f"{title} sur {c.label(ip)}",
                  f"{e['n']} ligne(s) de journal correspondante(s).", impact, fix, e.get("samples"), cat in ("stp", "link_down", "hw_temp"))


@rule
def gear_not_checked(c: Ctx):
    gear = [h for h in c.gear() if h["ip"] not in c.snmp]
    if gear:
        c.nc("lan.nosnmp", LAN, f"{len(gear)} équipement(s) réseau non interrogé(s)",
             "Sans accès SNMP, les erreurs de ports, le duplex, le spanning tree et le PoE de ces équipements n'ont pas pu être "
             "contrôlés : " + ", ".join(c.label(h["ip"]) for h in gear[:12])
             + ". Activer SNMP (lecture seule, v3 de préférence) ou saisir la communauté / l'utilisateur dans le diagnostic.")
    if not c.snmp:
        c.nc("lan.snmp", LAN, "Contrôle des ports des switchs", "Aucun équipement n'a répondu en SNMP.")
    elif not any(c.phys_ifaces(ip) for ip in c.snmp):
        c.nc("lan.ports", LAN, "Contrôle des ports des switchs", "Les équipements interrogés ne publient pas de compteurs de ports.")
    if not c.opts.get("ssh"):
        c.nc("lan.ssh", LAN, "Journaux des équipements (boucles, MAC qui changent de port, ports désactivés)",
             "Nécessite un accès SSH en lecture aux switchs et routeurs (identifiants à saisir dans le diagnostic).")


RULES = R
