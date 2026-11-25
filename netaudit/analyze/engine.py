"""Moteur d'analyse : applique toutes les règles à un instantané, calcule les
notes et la fiche du site."""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field

from . import rules_lan, rules_perf, rules_sec, rules_svc
from .context import Ctx
from .model import CRIT, DOMAINS, INFO, MAJOR, MINOR, NOT_CHECKED, OK, SVC, Finding

log = logging.getLogger(__name__)
ALL_RULES = rules_svc.RULES + rules_lan.RULES + rules_sec.RULES + rules_perf.RULES


@dataclass
class Analysis:
    findings: list[Finding]
    scores: dict[str, int]
    site: dict                      # fiche du site (réseaux, passerelle, compte des appareils…)
    hosts: dict = field(default_factory=dict)   # appareils classés (pour l'inventaire et le rapport)
    rule_errors: list[str] = field(default_factory=list)

    @property
    def machine(self) -> dict:      # compatibilité avec l'interface commune (nom affiché)
        return self.site

    @property
    def problems(self) -> list[Finding]:
        return sorted((f for f in self.findings if f.severity >= MINOR), key=lambda f: (-f.severity, f.domain, f.title))

    @property
    def risks(self) -> list[Finding]:
        return [f for f in self.problems if f.predictive]

    def counts(self) -> dict[int, int]:
        out = {CRIT: 0, MAJOR: 0, MINOR: 0, INFO: 0, OK: 0, NOT_CHECKED: 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings], "scores": self.scores, "site": self.site,
                "hosts": self.hosts, "rule_errors": self.rule_errors}

    @staticmethod
    def from_dict(d: dict) -> "Analysis":
        return Analysis([Finding.from_dict(x) for x in d.get("findings", [])], d.get("scores", {}), d.get("site", {}),
                        d.get("hosts", {}), d.get("rule_errors", []))


def score(findings: list[Finding]) -> int:
    n = {s: sum(1 for f in findings if f.severity == s) for s in (CRIT, MAJOR, MINOR)}
    pen = min(60, 25 * n[CRIT]) + min(30, 8 * n[MAJOR]) + min(12, 2 * n[MINOR])
    return max(0, 100 - pen)


def global_score(findings: list[Finding], scores: dict[str, int]) -> int:
    """Moyenne des domaines contrôlés, plafonnée par le problème le plus grave
    (critique → 49 au plus, majeur → 84 au plus)."""
    used = [scores[d] for d in DOMAINS if any(f.domain == d for f in findings)]
    sc = round(sum(used) / len(used)) if used else 100
    if any(f.severity == CRIT for f in findings):
        sc = min(sc, 49)
    elif any(f.severity == MAJOR for f in findings):
        sc = min(sc, 84)
    return sc


def site_info(c: Ctx) -> dict:
    kinds: dict[str, int] = {}
    for h in c.hosts.values():
        if h.get("kind") != "honeypot":
            kinds[h.get("kind_label")] = kinds.get(h.get("kind_label"), 0) + 1
    nets = [n["network"] for n in c.networks]
    gw = c.snap.get("default_gateway")
    pub = (c.connect.get("public") or {})
    return {
        "name": nets[0] if len(nets) == 1 else (next((n["network"] for n in c.networks if n.get("gateway")), nets[0] if nets else "?")),
        "networks": c.networks, "gateway": gw, "gateway_label": c.label(gw) if gw else "",
        "dns": sorted((c.connect.get("dns") or {}).keys()), "domain": c.snap.get("dns_domain") or "",
        "public_ip": pub.get("ip") or "", "isp": pub.get("isp") or "",
        "devices": sum(1 for h in c.hosts.values() if h.get("kind") != "honeypot"),
        "active": len(c.active()), "kinds": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
        "snmp_devices": len(c.snmp), "ssh_devices": sum(1 for r in c.ssh.values() if r.get("ok")),
        "audit_pc": c.snap.get("host_name") or "", "deep": c.deep,
        "duration_s": round((c.snap.get("finished") or 0) - (c.snap.get("started") or 0)),
        "key": "|".join(sorted(n["network"] for n in c.networks)),
    }


def analyze(snapshot: dict, prev_snapshot: dict | None = None) -> Analysis:
    c = Ctx(snapshot, prev_snapshot)
    errors = []
    for rule in ALL_RULES:
        try:
            rule(c)
        except Exception as exc:
            log.error("Règle %s : %s\n%s", rule.__name__, exc, traceback.format_exc())
            errors.append(f"{rule.__module__.rsplit('.', 1)[-1]}.{rule.__name__} : {exc}")
    for e in snapshot.get("errors") or []:
        c.nc(f"nc.scan.{abs(hash(e)) % 10**8}", SVC, "Étape du diagnostic incomplète", e)
    best: dict[str, Finding] = {}
    for f in c.findings:
        if f.id not in best or f.severity > best[f.id].severity:
            best[f.id] = f
    findings = list(best.values())
    scores = {d: score([f for f in findings if f.domain == d]) for d in DOMAINS}
    scores["global"] = global_score(findings, scores)
    slim = {}
    for ip, h in c.hosts.items():
        slim[ip] = {k: h.get(k) for k in ("ip", "mac", "vendor", "random_mac", "kind", "kind_label", "name", "model", "os",
                                          "confidence", "evidence", "ports", "network", "local_net", "inactive", "seen_by",
                                          "ttl", "rtt", "network_gear")}
        slim[ip]["snmp"] = bool(h.get("snmp"))
    return Analysis(findings, scores, site_info(c), slim, errors)
