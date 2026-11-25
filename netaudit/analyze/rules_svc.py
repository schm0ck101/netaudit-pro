"""Règles « Services réseau » : passerelle, accès Internet, DNS, DHCP, MTU,
heure, plan d'adressage."""
from __future__ import annotations

import ipaddress

from .context import Ctx
from .model import CRIT, INFO, MAJOR, MINOR, SVC

R = []


def rule(fn):
    R.append(fn)
    return fn


@rule
def gateway(c: Ctx):
    gw = c.snap.get("default_gateway")
    g = c.connect.get("gateway_ping") or {}
    if not gw:
        c.add("svc.gw.none", SVC, MAJOR, "Aucune passerelle par défaut sur le poste d'audit",
              "Le poste branché pour le diagnostic n'a pas de passerelle : Internet et les autres réseaux ne sont pas joignables.",
              "Sans passerelle, les postes de ce réseau n'accèdent qu'aux appareils du même sous-réseau.",
              "Vérifier la configuration DHCP (option « routeur ») ou la configuration IP fixe de ce réseau.")
        return
    if not g.get("received"):
        c.add("svc.gw.down", SVC, CRIT, f"La passerelle {gw} ne répond pas",
              f"{g.get('sent', 0)} requêtes ping sans réponse.",
              "La passerelle est hors service, ou elle filtre le ping (à vérifier : Internet est-il joignable ?).",
              "Vérifier l'état du routeur / pare-feu ; si le ping est volontairement bloqué, autoriser l'ICMP depuis le LAN pour la supervision.")
        return
    loss, avg, jit = g.get("loss_pct") or 0, g.get("avg") or 0, g.get("jitter") or 0
    ev = [f"{g['received']}/{g['sent']} réponses, moyenne {avg} ms, max {g.get('max')} ms, gigue {jit} ms"]
    if loss >= 5:
        c.add("svc.gw.loss", SVC, MAJOR, f"Pertes de paquets vers la passerelle ({loss:.0f} %)",
              f"{loss:.0f} % des requêtes vers {gw} sont perdues, sur le réseau local.",
              "Des pertes sur le LAN, avant même Internet, provoquent coupures de visio, lenteurs et déconnexions.",
              "Rechercher un câble ou un port défectueux, un switch saturé, une boucle ou un routeur surchargé (voir les autres constats).",
              ev)
    elif loss > 0:
        c.add("svc.gw.loss", SVC, MINOR, f"Pertes ponctuelles vers la passerelle ({loss:.0f} %)", ev[0],
              "Quelques pertes sur le réseau local ne sont pas normales sur un réseau filaire.",
              "Surveiller ; si le poste d'audit est en Wi-Fi, refaire la mesure en filaire.", ev)
    if avg > 10 or jit > 10:
        c.add("svc.gw.slow", SVC, MAJOR if avg > 30 else MINOR, f"Passerelle lente à répondre ({avg} ms en moyenne)",
              f"Sur un réseau local filaire, la passerelle répond normalement en moins de 2 ms.",
              "Routeur surchargé (processeur), lien saturé, ou mesure faite en Wi-Fi.",
              "Contrôler la charge du routeur et des liens ; refaire la mesure en filaire si besoin.", ev)
    if loss == 0 and avg <= 10 and jit <= 10:
        c.ok("svc.gw", SVC, f"Passerelle {gw} joignable et réactive", ev[0])
    for ip, r in (c.connect.get("other_gateways") or {}).items():
        if not r.get("received"):
            c.add(f"svc.gw2.{ip}", SVC, MINOR, f"Passerelle secondaire {ip} injoignable",
                  "Une autre carte ou adresse du poste d'audit déclare cette passerelle, qui ne répond pas.",
                  "Configuration résiduelle ou équipement arrêté.", "Vérifier si cette passerelle est encore utilisée.")


@rule
def internet(c: Ctx):
    if not c.connect.get("pings"):
        c.nc("svc.inet", SVC, "Accès Internet", "Tests Internet désactivés pour ce diagnostic.")
        return
    pings = c.connect["pings"]
    up = {t: r for t, r in pings.items() if r.get("received")}
    https = c.connect.get("https") or {}
    https_ok = [h for h, r in https.items() if r.get("ok")]
    ev = [f"{t} : {r.get('received')}/{r.get('sent')} réponses, moyenne {r.get('avg')} ms, gigue {r.get('jitter')} ms" for t, r in pings.items()]
    ev += [f"HTTPS {h} : {'OK' if r.get('ok') else r.get('error')}" for h, r in https.items()]
    if not up and not https_ok:
        c.add("svc.inet.down", SVC, CRIT, "Pas d'accès à Internet", "Ni le ping ni les connexions HTTPS n'aboutissent.",
              "Le site n'a pas d'accès Internet depuis ce réseau.",
              "Vérifier la box / le routeur, la ligne opérateur, les règles du pare-feu et le proxy éventuel.", ev)
        return
    if not up and https_ok:
        c.add("svc.inet.icmp", SVC, INFO, "Le ping vers Internet est bloqué", "Le web fonctionne mais le ping sortant est filtré.",
              "Sans conséquence pour les utilisateurs ; gêne seulement le diagnostic et la supervision.",
              "Facultatif : autoriser l'ICMP sortant pour faciliter les diagnostics.", ev)
    if not https_ok:
        c.add("svc.inet.web", SVC, MAJOR, "Les sites web en HTTPS ne sont pas joignables directement",
              "Le ping vers Internet fonctionne, mais pas les connexions HTTPS de test.",
              "Un proxy obligatoire, un filtrage ou un problème DNS empêche l'accès au web.",
              "Vérifier le proxy, le filtrage web et la résolution DNS.", ev)
    loss = max((r.get("loss_pct") or 0) for r in up.values()) if up else 0
    best = min(up.values(), key=lambda r: r.get("avg") or 1e9) if up else {}
    if loss >= 3:
        c.add("svc.inet.loss", SVC, MAJOR, f"Pertes de paquets vers Internet ({loss:.0f} %)",
              "Les pertes apparaissent au-delà du réseau local.",
              "Coupures en visioconférence et téléphonie, téléchargements lents.",
              "Comparer avec les pertes vers la passerelle : si elles sont nulles, le problème est côté box / opérateur "
              "(ouvrir un ticket avec ces mesures).", ev)
    elif loss > 0:
        c.add("svc.inet.loss", SVC, MINOR, f"Pertes ponctuelles vers Internet ({loss:.0f} %)", "", "", "Surveiller.", ev)
    avg = best.get("avg") or 0
    if avg > 80:
        c.add("svc.inet.lat", SVC, MAJOR if avg > 150 else MINOR, f"Latence Internet élevée ({avg:.0f} ms)",
              "Une ligne fibre ou VDSL répond normalement en 5 à 30 ms ; une ligne 4G/5G ou satellite davantage.",
              "Visio et téléphonie dégradées, applications en ligne lentes.",
              "Vérifier la saturation de la ligne (sauvegardes, mises à jour), le type d'accès, le routage chez l'opérateur.", ev)
    if up and loss == 0 and avg <= 80 and https_ok:
        c.ok("svc.inet", SVC, f"Accès Internet correct ({avg:.0f} ms, sans perte)", "; ".join(ev[:2]))
    pub = c.connect.get("public") or {}
    if pub.get("ok"):
        c.add("svc.inet.pub", SVC, INFO, f"Adresse IP publique : {pub['ip']}" + (f" ({pub['isp']})" if pub.get("isp") else ""),
              f"Nom inverse : {pub.get('ptr') or '—'}")
    nc = c.connect.get("ncsi") or {}
    if nc and not nc.get("ok") and https_ok:
        c.add("svc.inet.portal", SVC, MINOR, "Test de connectivité Windows perturbé (portail captif ou proxy)",
              f"Réponse inattendue au test NCSI de Windows : {nc.get('body') or nc.get('error')}",
              "Windows peut afficher « Aucun accès à Internet » et certaines applications Microsoft s'en servent.",
              "Autoriser www.msftconnecttest.com sans authentification ni réécriture.")
    for h, r in https.items():
        if r.get("tls_intercept"):
            cert = r.get("cert") or {}
            c.add("svc.inet.tlsinspect", SVC, INFO, "Les connexions HTTPS sont interceptées (inspection TLS)",
                  f"Le certificat reçu pour {h} est émis par « {cert.get('issuer', '?')} », non reconnu par ce poste.",
                  "Normal si un pare-feu inspecte le trafic : son certificat racine doit alors être déployé sur TOUS les postes, "
                  "sinon erreurs de certificat.", "Vérifier le déploiement du certificat d'inspection (GPO, MDM).")
            break


@rule
def mtu(c: Ctx):
    m = c.connect.get("mtu")
    if not m or not m.get("ok"):
        return
    mt = m.get("mtu")
    if mt is None:
        c.add("svc.mtu", SVC, MAJOR, "MTU vers Internet très faible (moins de 1 228 octets)",
              "Les paquets de taille normale ne passent pas sans fragmentation.",
              "Sites qui ne chargent qu'à moitié, VPN instables, transferts bloqués.",
              "Vérifier la MTU de la box/routeur (PPPoE 1492), des tunnels VPN et le filtrage ICMP « fragmentation nécessaire ».")
    elif mt >= 1500:
        c.ok("svc.mtu", SVC, "MTU de 1 500 octets jusqu'à Internet")
    elif mt >= 1492:
        c.add("svc.mtu", SVC, INFO, f"MTU de {mt} octets jusqu'à Internet", "Valeur habituelle d'un accès PPPoE ou d'un tunnel léger.")
    else:
        c.add("svc.mtu", SVC, MINOR, f"MTU réduite à {mt} octets jusqu'à Internet",
              "Un tunnel, une box ou un lien opérateur réduit la taille des paquets.",
              "Si la découverte de MTU est filtrée quelque part, certains sites ou VPN se bloquent.",
              "Vérifier la MTU configurée sur le routeur et que l'ICMP « fragmentation nécessaire » n'est pas bloqué.",
              [f"plus grand ping sans fragmentation : {m.get('payload')} octets de données vers {m.get('target')}"])


@rule
def dns(c: Ctx):
    res = c.connect.get("dns") or {}
    if not res:
        c.add("svc.dns.none", SVC, MAJOR, "Aucun serveur DNS configuré sur le poste d'audit",
              "Le réseau ne fournit pas de serveur DNS (DHCP ou configuration fixe).",
              "Sans DNS, aucun nom (sites web, serveurs) ne peut être résolu.", "Distribuer des serveurs DNS par DHCP.")
        return
    dead = [s for s, r in res.items() if not r.get("ok")]
    alive = [s for s, r in res.items() if r.get("ok")]
    ev = [f"{s} : {'répond en ' + str(r.get('avg_ms')) + ' ms' if r.get('ok') else 'ne répond pas'}"
          + (f", {r.get('failed')} échec(s) sur {len(r.get('queries') or [])}" if r.get('failed') else "") for s, r in res.items()]
    if dead and not alive:
        c.add("svc.dns.down", SVC, CRIT, "Aucun serveur DNS ne répond", ", ".join(dead),
              "Plus aucun nom n'est résolu : Internet et les serveurs internes semblent « en panne ».",
              "Vérifier le service DNS (contrôleur de domaine, box, pare-feu) et la configuration distribuée par DHCP.", ev)
    elif dead:
        c.add("svc.dns.partial", SVC, MAJOR, f"Serveur DNS configuré mais muet : {', '.join(dead)}",
              "Windows bascule sur le serveur suivant après un délai : chaque résolution peut prendre plusieurs secondes.",
              "Lenteurs aléatoires à l'ouverture des sites, des partages et des applications.",
              "Retirer ce serveur de la configuration (DHCP ou IP fixe) ou le remettre en service.", ev, True)
    slow = [s for s in alive if (res[s].get("avg_ms") or 0) > 150]
    if slow:
        c.add("svc.dns.slow", SVC, MINOR, f"Résolution DNS lente ({', '.join(slow)})",
              "Temps de réponse moyen supérieur à 150 ms.", "Chaque nouvelle connexion est ralentie.",
              "Vérifier la charge du serveur DNS et ses redirecteurs (forwarders).", ev)
    redirect = [s for s in alive if res[s].get("nxdomain") == "OK" and res[s].get("nx_answers")]
    if redirect:
        c.add("svc.dns.nxhijack", SVC, MINOR, "Le DNS renvoie une adresse pour des noms inexistants",
              f"{', '.join(redirect)} répond par une adresse au lieu de « nom inexistant ».",
              "Pratique de certains opérateurs ou filtres : fausse les diagnostics et certaines applications.",
              "Désactiver cette « assistance » sur la box ou utiliser d'autres redirecteurs.",
              [f"réponse : {', '.join(res[s].get('nx_answers') or [])}" for s in redirect])
    if len(res) == 1 and alive:
        c.add("svc.dns.single", SVC, MINOR, "Un seul serveur DNS configuré",
              f"Seul {alive[0]} est distribué aux postes.", "Si ce serveur s'arrête, plus rien ne fonctionne.",
              "Ajouter un second serveur DNS (2e contrôleur de domaine, ou 2e résolveur) dans la configuration DHCP.", ev, True)
    # domaine Active Directory
    dom = c.snap.get("dns_domain") or ""
    host = (c.snap.get("local") or {}).get("host") or {}
    if dom and host.get("part_of_domain"):
        bad = [s for s in alive if not (res[s].get("internal") or {}).get("has_soa")]
        public = [s for s in res if not ipaddress.ip_address(s).is_private]
        if public:
            c.add("svc.dns.ad_public", SVC, MAJOR, "DNS public configuré dans un domaine Active Directory",
                  f"{', '.join(public)} ne connaît pas le domaine « {dom} ».",
                  "Ouvertures de session lentes, stratégies de groupe non appliquées, partages introuvables par intermittence.",
                  "Ne distribuer que les contrôleurs de domaine comme DNS ; mettre les DNS publics en redirecteurs sur les DC.")
        elif bad:
            c.add("svc.dns.ad_zone", SVC, MAJOR, f"Le domaine « {dom} » n'est pas résolu par tous les DNS",
                  f"Zone introuvable sur : {', '.join(bad)}.", "Même effet qu'un DNS public dans un domaine.",
                  "Corriger la liste des serveurs DNS distribués.", ev)
        else:
            dcs = sorted({d for s in alive for d in (res[s].get("ad_dc") or [])})
            c.ok("svc.dns.ad", SVC, f"Le domaine « {dom} » est résolu par les DNS configurés",
                 f"Contrôleurs annoncés : {', '.join(dcs) or '—'}")
    if alive and not dead and not slow:
        c.ok("svc.dns", SVC, f"{len(alive)} serveur(s) DNS fonctionnel(s)", "; ".join(ev))
    if (c.connect.get("direct_dns") or {}).get("ok"):
        c.add("svc.dns.egress", SVC, INFO, "Les postes peuvent interroger des DNS publics directement",
              "Une requête DNS vers 8.8.8.8 depuis le poste d'audit aboutit.",
              "Le filtrage DNS éventuel (sécurité, contrôle parental) peut être contourné par un poste.",
              "Si un filtrage DNS est en place, bloquer le port 53 sortant sauf depuis les serveurs DNS internes.")


@rule
def dhcp(c: Ctx):
    res = c.snap.get("dhcp")
    nets_dhcp = [n for n in c.networks if n.get("dhcp")]
    if res is None:
        c.nc("svc.dhcp.test", SVC, "Serveurs DHCP (détection des serveurs pirates)",
             "Test réalisé seulement en mode approfondi (requête DHCP diffusée sur le réseau).")
        return
    for net, r in res.items():
        if not r.get("ok"):
            c.nc(f"svc.dhcp.{net}", SVC, f"Test DHCP sur {net}", r.get("error") or "échec")
            continue
        offers = r.get("offers") or []
        servers = {}
        for o in offers:
            servers.setdefault(o.get("server_id") or o.get("source"), o)
        ev = [f"{sid} : propose {o.get('offered_ip')}, passerelle {', '.join(o.get('router') or []) or '—'}, DNS "
              f"{', '.join(o.get('dns') or []) or '—'}, bail {round((o.get('lease') or 0) / 3600, 1)} h" for sid, o in servers.items()]
        if not servers:
            sev = MAJOR if nets_dhcp else INFO
            c.add(f"svc.dhcp.none.{net}", SVC, sev, f"Aucun serveur DHCP ne répond sur {net}",
                  "Une demande DHCP diffusée n'a reçu aucune offre.",
                  "Les appareils configurés en automatique (DHCP) n'obtiendront pas d'adresse." if nets_dhcp else
                  "Normal si toutes les adresses de ce réseau sont fixes.",
                  "Vérifier le service DHCP (serveur, routeur) et le relais DHCP du VLAN.")
            continue
        if len(servers) > 1:
            c.add(f"svc.dhcp.multi.{net}", SVC, CRIT, f"{len(servers)} serveurs DHCP répondent sur {net}",
                  "Plusieurs serveurs distribuent des adresses sur le même réseau.",
                  "Des postes reçoivent une mauvaise passerelle ou un mauvais DNS : coupures aléatoires, « réseau non identifié ». "
                  "Souvent une box opérateur ou un routeur Wi-Fi branché par erreur, parfois un serveur pirate.",
                  "Identifier l'appareil de chaque adresse ci-dessous et désactiver le DHCP indésirable ; activer « DHCP snooping » "
                  "sur les switchs qui le permettent.", ev, True)
        else:
            c.ok(f"svc.dhcp.{net}", SVC, "Un seul serveur DHCP sur le réseau", ev[0])
        for sid, o in servers.items():
            lease = o.get("lease") or 0
            if lease and lease < 3600:
                c.add(f"svc.dhcp.lease.{sid}", SVC, MINOR, f"Bail DHCP très court ({lease // 60} min) sur {sid}",
                      "Les appareils renouvellent leur adresse très souvent.",
                      "Charge inutile et risque de perte d'adresse si le serveur est indisponible quelques minutes.",
                      "Allonger le bail (8 h à 8 jours selon le réseau ; plus court seulement pour un réseau invités très fréquenté).")
            gw_offer = (o.get("router") or [None])[0]
            known_gw = next((n.get("gateway") for n in c.networks if n.get("gateway")), None)
            if gw_offer and known_gw and gw_offer != known_gw and len(servers) == 1:
                c.add(f"svc.dhcp.gw.{sid}", SVC, INFO, f"Le DHCP distribue la passerelle {gw_offer}",
                      f"Le poste d'audit utilise {known_gw} (configuration fixe ?).")


@rule
def ntp(c: Ctx):
    ntp_ = c.connect.get("ntp") or {}
    offs = [r["offset_s"] for r in ntp_.values() if r.get("ok")]
    if not offs:
        if ntp_:
            c.add("svc.ntp.blocked", SVC, MINOR, "Les serveurs de temps Internet ne répondent pas (NTP)",
                  "Les requêtes NTP (UDP 123) vers Internet n'aboutissent pas.",
                  "Les horloges dérivent si aucun serveur de temps interne n'est disponible (authentification Kerberos, journaux, certificats).",
                  "Autoriser NTP sortant depuis le serveur de temps interne (contrôleur de domaine ou routeur).")
        return
    off = abs(sorted(offs)[len(offs) // 2])
    if off > 300:
        c.add("svc.ntp.skew", SVC, CRIT, f"Horloge du poste d'audit décalée de {off:.0f} s",
              "Plus de 5 minutes d'écart avec l'heure Internet.",
              "Au-delà de 5 minutes, l'authentification Kerberos (domaine Windows) échoue ; certificats et journaux faussés.",
              "Vérifier la source de temps du domaine (PDC) ou du réseau et la synchronisation des postes.", predictive=True)
    elif off > 5:
        c.add("svc.ntp.skew", SVC, MINOR, f"Horloge du poste d'audit décalée de {off:.0f} s",
              "L'heure n'est pas synchronisée précisément.", "Journaux difficiles à corréler ; risque d'échec Kerberos si l'écart grandit.",
              "Vérifier la synchronisation de l'heure (w32tm /query /status).", predictive=True)
    else:
        c.ok("svc.ntp", SVC, f"Heure synchronisée (écart {off:.2f} s)")


@rule
def addressing(c: Ctx):
    for n in c.networks:
        if n.get("span") or not n.get("scanned"):
            continue
        net = ipaddress.IPv4Network(n["network"])
        used = sum(1 for h in c.hosts.values() if h.get("network") == n["network"])
        size = max(1, net.num_addresses - 2)
        pct = 100 * used / size
        if n.get("note"):
            c.add(f"svc.addr.big.{n['network']}", SVC, INFO, f"Réseau {n['network']} analysé partiellement", n["note"])
        if pct >= 85:
            c.add(f"svc.addr.full.{n['network']}", SVC, MAJOR if pct >= 95 else MINOR,
                  f"Réseau {n['network']} presque plein ({used} adresses utilisées sur {size})",
                  f"{pct:.0f} % des adresses du sous-réseau sont occupées (appareils actifs ou vus récemment).",
                  "Les nouveaux appareils (et les téléphones à MAC aléatoire) risquent de ne plus obtenir d'adresse.",
                  "Agrandir le sous-réseau, raccourcir le bail DHCP du Wi-Fi invités, ou séparer les usages en VLAN.", predictive=True)
        elif size >= 500 and used > 400:
            c.add(f"svc.addr.flat.{n['network']}", SVC, MINOR, f"Plus de 400 appareils dans un même réseau ({n['network']})",
                  "Un domaine de diffusion très peuplé augmente le trafic de broadcast et l'impact d'une boucle.",
                  "Performances dégradées pour tous, panne qui touche tout le monde.", "Segmenter en VLAN par usage.")
    other = c.snap.get("other_networks") or {}
    if other:
        c.add("svc.addr.other", SVC, INFO, f"{len(other)} autre(s) réseau(x) connu(s) du routeur, non analysé(s)",
              "Le routeur échange avec ces réseaux (table ARP) : VLAN, réseau invités, téléphonie, caméras…",
              "", "Pour les inclure, ajouter ces plages dans « Plages supplémentaires » et relancer le diagnostic.",
              [f"{k} : {v} adresse(s) vue(s)" for k, v in other.items()])


RULES = R
