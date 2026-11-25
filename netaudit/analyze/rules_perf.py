"""Règles « Performances et stabilité » : lien du poste d'audit, broadcast /
multicast reçus (tempête, boucle), erreurs de la carte du poste, gigue."""
from __future__ import annotations

from .context import Ctx
from .model import CRIT, INFO, MAJOR, MINOR, PERF

R = []


def rule(fn):
    R.append(fn)
    return fn


def _rates(c: Ctx) -> dict:
    a, b = c.snap.get("ifstats_a") or {}, c.snap.get("ifstats_b") or {}
    out = {}
    for idx, rb in b.items():
        ra = a.get(idx) or a.get(str(idx))
        if not ra:
            continue
        dt = max(0.001, rb["t"] - ra["t"])
        out[idx] = {"rb": rb, "dt": dt, **{k: max(0, rb[k] - ra[k]) / dt for k in rb if isinstance(rb.get(k), int) and k in ra}}
    return out


@rule
def audit_link(c: Ctx):
    ads = (c.snap.get("local") or {}).get("adapters") or []
    if isinstance(ads, dict):
        ads = [ads]
    used = {n.get("ifindex") for n in c.networks if n.get("source") == "local"}
    for a in ads:
        if a.get("index") not in used:
            continue
        sp = (a.get("speed") or 0) / 1e6
        wifi = "802.11" in (a.get("media") or "") or "wi-fi" in (a.get("desc") or "").lower() or "wireless" in (a.get("desc") or "").lower()
        if wifi:
            c.add("perf.audit.wifi", PERF, INFO, "Diagnostic réalisé en Wi-Fi",
                  f"Carte {a.get('desc')} ({sp:.0f} Mb/s).",
                  "Pertes et latences mesurées incluent la qualité du Wi-Fi à cet endroit.",
                  "Pour isoler les problèmes du réseau filaire, refaire le diagnostic branché sur une prise réseau.")
            continue
        if a.get("full_duplex") is False:
            c.add("perf.audit.half", PERF, MAJOR, "La prise réseau du poste d'audit fonctionne en half-duplex",
                  f"Carte {a.get('desc')} : {sp:.0f} Mb/s half-duplex.", "Désaccord de duplex probable avec le switch : débit effondré.",
                  "Laisser carte et port du switch en négociation automatique ; tester le câble.")
        if 0 < sp < 1000:
            c.add("perf.audit.speed", PERF, MINOR if sp >= 100 else MAJOR, f"Lien du poste d'audit à {sp:.0f} Mb/s",
                  f"La prise utilisée pour le diagnostic n'est pas en gigabit ({a.get('desc')}).",
                  "Switch ancien (100 Mb/s), câble ou prise défectueuse (2 paires), ou port limité.",
                  "Vérifier le câblage de cette prise et le port du switch ; les postes en 100 Mb/s sont 10× plus lents pour les transferts.")
        elif sp >= 1000:
            c.ok("perf.audit.speed", PERF, f"Lien du poste d'audit à {sp / 1000:.0f} Gb/s full-duplex")


@rule
def broadcast(c: Ctx):
    rates = _rates(c)
    for idx, r in rates.items():
        bc = r.get("InBroadcastOctets", 0)
        mc = r.get("InMulticastOctets", 0)
        nu = r.get("InNUcastPkts", 0)
        ev = [f"broadcast reçu : {bc / 1024:.1f} Ko/s, multicast : {mc / 1024:.1f} Ko/s" + (f", {nu:.0f} paquets/s non unicast" if nu else "")
              + f" (mesure sur {r['dt']:.0f} s, carte {r['rb'].get('alias')})"]
        if bc > 1_000_000 or nu > 2000:
            c.add("perf.bcast.storm", PERF, CRIT, "Tempête de broadcast en cours",
                  "Le poste reçoit un volume énorme de trafic diffusé.",
                  "Typique d'une boucle réseau : tous les appareils sont saturés, le réseau devient inutilisable.",
                  "Rechercher immédiatement une boucle (câble branché entre deux prises, switch de bureau en double) ; activer "
                  "loop-protect / storm-control sur les switchs.", ev)
        elif bc > 150_000 or nu > 500:
            c.add("perf.bcast.high", PERF, MAJOR, "Trafic de broadcast élevé",
                  "Le trafic diffusé à tous les appareils est anormalement élevé.",
                  "Chaque appareil doit traiter ces paquets : lenteurs, batteries vidées, Wi-Fi saturé (le broadcast part au débit le plus bas).",
                  "Identifier la source (capture réseau) ; segmenter en VLAN ; vérifier les boucles et les appareils bavards.", ev, True)
        elif bc > 30_000:
            c.add("perf.bcast.mid", PERF, MINOR, "Trafic de broadcast un peu élevé", "", "Grand réseau à plat ou appareil bavard.",
                  "Segmenter si le réseau compte beaucoup d'appareils.", ev)
        else:
            c.ok("perf.bcast", PERF, "Trafic de broadcast normal", ev[0])
        if mc > 2_000_000:
            c.add("perf.mcast", PERF, MAJOR, "Flux multicast important reçu par tous les postes",
                  "Un flux multicast (vidéo, IPTV, clonage de postes) inonde le réseau.",
                  "Le multicast non maîtrisé se comporte comme du broadcast : saturation, Wi-Fi dégradé.",
                  "Activer l'IGMP snooping (et un « querier ») sur les switchs.", ev)
        err = r.get("InErrors", 0) + r.get("OutErrors", 0)
        if err > 0:
            c.add("perf.audit.err", PERF, MAJOR, "Erreurs sur la carte réseau du poste d'audit",
                  f"{err * r['dt']:.0f} erreur(s) pendant la mesure.", "Câble, prise ou port défectueux à cet endroit.",
                  "Changer de cordon et de prise pour confirmer.", ev)


@rule
def jitter(c: Ctx):
    pings = (c.connect.get("pings") or {}).values()
    js = [p.get("jitter") for p in pings if p.get("jitter") is not None]
    g = c.connect.get("gateway_ping") or {}
    if js and min(js) > 15:
        c.add("perf.jitter", PERF, MINOR, f"Gigue élevée vers Internet ({min(js):.0f} ms)",
              "La latence varie fortement d'un paquet à l'autre.", "Voix et visio hachées.",
              "Vérifier la saturation de la ligne (QoS) ; comparer avec la gigue vers la passerelle.",
              [f"gigue passerelle : {g.get('jitter')} ms"])


RULES = R
