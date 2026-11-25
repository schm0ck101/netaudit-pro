"""Connexion SSH en LECTURE SEULE aux équipements réseau (optionnelle).

Seules des commandes d'affichage (« show », « get », « print », « cat »…)
définies ci-dessous sont envoyées : aucune commande de configuration n'existe
dans ce module. Les journaux relevés sont ensuite analysés (boucles, MAC qui
« sautent » de port, ports désactivés pour erreur, duplex, flapping…).
"""
from __future__ import annotations

import logging
import re
import socket
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)      # erreurs gérées et rapportées par ce module

# profil -> (commandes de mise en forme, commandes d'audit)
PROFILES: dict[str, tuple[list[str], list[str]]] = {
    "procurve": (["no page"], ["show system", "show version", "show interfaces brief", "show lldp info remote-device",
                               "show spanning-tree", "show loop-protect", "show power-over-ethernet brief",
                               "show logging -r -s", "show logging -r"]),
    "aruba-cx": (["no page"], ["show system", "show version", "show interface brief", "show lldp neighbor-info",
                               "show spanning-tree", "show loop-protect", "show logging -r -n 300"]),
    "cisco-ios": (["terminal length 0", "terminal width 0"], ["show version", "show interfaces status",
                                                              "show interfaces counters errors", "show cdp neighbors",
                                                              "show lldp neighbors", "show spanning-tree summary",
                                                              "show interfaces status err-disabled", "show power inline",
                                                              "show logging"]),
    "cisco-sb": (["terminal datadump"], ["show version", "show system", "show interfaces status", "show lldp neighbors",
                                         "show spanning-tree", "show logging"]),
    "comware": (["screen-length disable"], ["display version", "display interface brief", "display lldp neighbor-information list",
                                            "display stp brief", "display logbuffer"]),
    "mikrotik": ([], ["/system resource print", "/system routerboard print", "/interface print stats without-paging",
                      "/interface ethernet print without-paging", "/log print without-paging where topics~\"error|critical|warning\""]),
    "fortigate": ([], ["get system status", "get system performance status", "get system interface physical",
                       "execute log filter category 0", "execute log display"]),
    "linux": ([], ["uname -a", "uptime", "cat /proc/loadavg", "ip -s link", "df -h", "dmesg 2>/dev/null | tail -n 120",
                   "cat /etc/os-release 2>/dev/null | head -n 5"]),
}

PROFILE_LABELS = {"procurve": "HP ProCurve / Aruba OS", "aruba-cx": "Aruba AOS-CX", "cisco-ios": "Cisco IOS",
                  "cisco-sb": "Cisco Small Business", "comware": "HPE / H3C Comware", "mikrotik": "MikroTik RouterOS",
                  "fortigate": "Fortinet FortiGate", "linux": "Linux (générique)"}

# toute commande envoyée doit commencer par l'un de ces mots (garde-fou supplémentaire)
SAFE_PREFIX = ("show ", "display ", "get ", "/system ", "/interface ", "/log ", "uname", "uptime", "cat ", "ip -s",
               "df ", "dmesg", "no page", "terminal ", "screen-length", "execute log filter", "execute log display")


def guess_profile(sys_descr: str = "", banner: str = "", sys_oid: str = "") -> str | None:
    d = f"{sys_descr} {banner}".lower()
    if "aruba" in d and ("cx" in d or "aos-cx" in d or "arubaos-cx" in d):
        return "aruba-cx"
    if "procurve" in d or "arubaos-switch" in d or re.search(r"\bhp (j\d{4}|.*switch)", d) or "aruba" in d and "switch" in d:
        return "procurve"
    if "comware" in d or "h3c" in d:
        return "comware"
    if "cisco" in d and ("sg" in d or "cbs" in d or "small business" in d):
        return "cisco-sb"
    if "cisco" in d or "ios" in d and "cisco" in d:
        return "cisco-ios"
    if "routeros" in d or "mikrotik" in d:
        return "mikrotik"
    if "fortigate" in d or "fortios" in d:
        return "fortigate"
    if "linux" in d or "openssh" in d or "dropbear" in d or "unifi" in d or "freebsd" in d:
        return "linux"
    return None


@dataclass
class SshCred:
    user: str
    password: str = ""
    key_file: str = ""

    def label(self) -> str:
        return f"{self.user}" + (" (clé)" if self.key_file else "")


def _clean(txt: str) -> str:
    txt = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", txt)       # séquences d'échappement VT100
    txt = re.sub(r"\x1bE", "\n", txt)
    txt = txt.replace("\r\n", "\n").replace("\r", "")
    txt = re.sub(r"-- ?MORE ?--.*?\n|--More--|<--- More --->", "", txt, flags=re.I)
    return txt


def run(ip: str, cred: SshCred, profile: str, timeout: float = 10.0, budget: float = 90.0) -> dict:
    """Exécute les commandes d'audit du profil ; {ok, profile, outputs{cmd: texte}, host_key, error}."""
    try:
        import paramiko
    except ImportError:
        return {"ok": False, "error": "module SSH absent"}
    if profile not in PROFILES:
        return {"ok": False, "error": f"profil inconnu : {profile}"}
    setup, cmds = PROFILES[profile]
    for c in setup + cmds:
        if not c.startswith(SAFE_PREFIX):
            return {"ok": False, "error": f"commande refusée : {c}"}
    out: dict = {"ok": False, "profile": profile, "outputs": {}, "host_key": ""}
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    t_end = time.monotonic() + budget
    try:
        cli.connect(ip, username=cred.user, password=cred.password or None, key_filename=cred.key_file or None,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False,
                    allow_agent=False)
        tr = cli.get_transport()
        if tr:
            k = tr.get_remote_server_key()
            out["host_key"] = f"{k.get_name()} {k.get_fingerprint().hex(':')}"
            out["server"] = tr.remote_version
        if profile in ("linux", "mikrotik", "fortigate"):
            for c in cmds:
                if time.monotonic() > t_end:
                    break
                try:
                    _i, so, se = cli.exec_command(c, timeout=timeout)
                    txt = so.read(200_000).decode("utf-8", "replace") + se.read(20_000).decode("utf-8", "replace")
                    out["outputs"][c] = _clean(txt)[:120_000]
                except (paramiko.SSHException, socket.timeout, OSError) as exc:
                    out["outputs"][c] = f"(erreur : {exc})"
        else:
            ch = cli.invoke_shell(width=250, height=1000)
            ch.settimeout(1.0)
            _read_until_quiet(ch, 3.0, first_key=True)       # bannière, « Press any key to continue »
            for c in setup:
                ch.send(c + "\n")
                _read_until_quiet(ch, 1.5)
            for c in cmds:
                if time.monotonic() > t_end:
                    break
                ch.send(c + "\n")
                txt = _read_until_quiet(ch, 2.5, max_total=min(40.0, max(3.0, t_end - time.monotonic())))
                out["outputs"][c] = _clean(txt)[:120_000]
            try:
                ch.send("exit\n")
            except OSError:
                pass
        out["ok"] = True
    except paramiko.AuthenticationException:
        out["error"] = "authentification refusée"
    except (paramiko.SSHException, socket.timeout, OSError, EOFError) as exc:
        out["error"] = str(exc)[:200] or exc.__class__.__name__
    finally:
        cli.close()
    return out


def _read_until_quiet(ch, quiet: float, max_total: float = 20.0, first_key: bool = False) -> str:
    buf, last, t0 = [], time.monotonic(), time.monotonic()
    while time.monotonic() - t0 < max_total:
        if ch.recv_ready():
            data = ch.recv(65535).decode("utf-8", "replace")
            buf.append(data)
            last = time.monotonic()
            low = data.lower()
            if first_key and "press any key" in low:
                ch.send(" ")
            if "-- more --" in low or "--more--" in low or "<--- more --->" in low:
                ch.send(" ")
        else:
            if time.monotonic() - last > quiet:
                break
            time.sleep(0.05)
    return "".join(buf)


# ------------------------------------------------------- analyse des journaux
# (motif, catégorie, gravité) — catégories reprises par les règles
LOG_PATTERNS = [
    (r"loop[- ]?protect|loop detected|loop_back_detected|loopback detected|boucle", "loop", 4),
    (r"macflap|mac.?flap|mac address .* (is )?moving|host .* is flapping between port", "mac_flap", 4),
    (r"broadcast storm|storm[- ]control|excessive broadcasts?", "storm", 3),
    (r"err-?disable|errdisable|disabled due to", "err_disabled", 3),
    (r"duplex mismatch|duplex_mismatch", "duplex", 3),
    (r"excessive crc|crc/alignment|alignment errors?|fcs error", "crc", 3),
    (r"high collision|late collision|excessive collision", "collision", 3),
    (r"topology change|tcn|spantree|root bridge changed|new root", "stp", 2),
    # (« entered disabled state » des ponts Linux n'est qu'une conséquence d'un « link down » : non compté)
    (r"is now off-line|changed state to down|\blink (is )?down\b|nic link is down|went down|link status (is )?down|carrier lost",
     "link_down", 1),
    (r"poe.{0,30}(fault|overload|denied|exceed)|power (budget|limit) exceeded|insufficient power", "poe", 2),
    (r"(over ?temp|temperature (is )?(high|critical)|fan (fail|fault))", "hw_temp", 3),
    (r"power supply.{0,20}(fail|fault)|psu.{0,10}(fail|fault)", "hw_psu", 3),
    (r"ip (address )?conflict|duplicate (ip|address)", "ip_conflict", 3),
    (r"authentication fail|login fail|invalid (user|password)", "auth_fail", 1),
]


def scan_logs(outputs: dict[str, str]) -> dict[str, dict]:
    """Compte les événements par catégorie dans les journaux relevés : {cat: {n, sev, samples}}."""
    res: dict[str, dict] = {}
    for cmd, txt in outputs.items():
        if not any(k in cmd for k in ("logging", "logbuffer", "/log", "dmesg", "log display")):
            continue
        for line in txt.splitlines():
            ll = line.lower()
            for pat, cat, sev in LOG_PATTERNS:
                if re.search(pat, ll):
                    e = res.setdefault(cat, {"n": 0, "sev": sev, "samples": []})
                    e["n"] += 1
                    if len(e["samples"]) < 5:
                        e["samples"].append(line.strip()[:200])
                    break
    return res
