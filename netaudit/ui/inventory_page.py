"""Page « Appareils » : inventaire du site et données relevées, par onglet."""
from __future__ import annotations

import ipaddress

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QHBoxLayout, QLineEdit, QPlainTextEdit, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout,
                               QWidget)

from ..analyze.context import PHYS_TYPES, VIRTUAL_NAME
from ..net.ports import SERVICES
from . import theme
from .common import fill_table, make_table, muted, page_title


def _ipkey(ip: str):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0


def _dur(s) -> str:
    if not isinstance(s, (int, float)):
        return ""
    d = int(s // 86400)
    return f"{d} j" if d else f"{s / 3600:.1f} h"


def _ports_txt(ps) -> str:
    return ", ".join(f"{p} {SERVICES.get(p, '')}".strip() for p in (ps or []))


class InventoryPage(QWidget):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 14)
        top = QHBoxLayout()
        top.addWidget(page_title("Appareils et équipements"), 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtrer le tableau affiché…")
        self.search.setFixedWidth(320)
        self.search.textChanged.connect(self._filter)
        top.addWidget(self.search)
        root.addLayout(top)
        self.sub = muted("")
        root.addWidget(self.sub)
        self.tabs = QTabWidget()
        self.tables = {}
        spec = {
            "Appareils": ["Adresse", "Nom", "Type", "Certitude", "Fabricant", "MAC", "Modèle / description", "Système", "Ports ouverts",
                          "Vu par", "Réseau"],
            "Équipements": ["Équipement", "Adresse", "Constructeur", "Description", "Allumé depuis", "Ports actifs", "LLDP", "MAC connues",
                            "Accès", "Emplacement"],
            "Ports des switchs": ["Équipement", "Port", "Description", "État", "Vitesse", "Duplex", "Erreurs entrée", "Erreurs sortie",
                                  "Rejets", "FCS", "Voisin (LLDP)"],
            "Voisins LLDP / CDP": ["Équipement", "Port local", "Voisin", "Port du voisin", "Adresse", "Rôle", "Description"],
            "Où est branché ?": ["Appareil", "Adresse", "MAC", "Switch", "Port", "VLAN"],
            "Services": ["Test", "Cible", "Résultat", "Détail"],
        }
        for name, headers in spec.items():
            t = make_table(headers)
            self.tables[name] = t
            if name == "Appareils":
                split = QSplitter(Qt.Horizontal)
                split.addWidget(t)
                self.detail = QTextBrowser()
                split.addWidget(self.detail)
                split.setSizes([1000, 340])
                t.itemSelectionChanged.connect(self._host_detail)
                self.tabs.addTab(split, name)
            else:
                self.tabs.addTab(t, name)
        self.ssh_txt = QPlainTextEdit()
        self.ssh_txt.setReadOnly(True)
        self.ssh_txt.setStyleSheet("font-family: Consolas; font-size: 9pt;")
        self.tabs.addTab(self.ssh_txt, "Journaux SSH")
        root.addWidget(self.tabs, 1)
        self.tabs.currentChanged.connect(lambda _i: self._filter(self.search.text()))
        ctx.current_changed.connect(self.load)
        self.load()

    def apply_theme(self):
        self.load()

    # ---------------------------------------------------------------------
    def load(self):
        for t in self.tables.values():
            t.setRowCount(0)
        self.detail.clear()
        self.ssh_txt.clear()
        rec, a = self.ctx.rec, self.ctx.analysis
        if not rec or not a:
            self.sub.setText("Aucun diagnostic ouvert.")
            return
        snap = self.ctx.snap
        hosts = a.hosts or {}
        raw = snap.get("hosts") or {}
        self.sub.setText(f"{len(hosts)} appareil(s) · {len(snap.get('snmp') or {})} équipement(s) interrogé(s) en SNMP · "
                         f"{sum(1 for r in (snap.get('ssh') or {}).values() if r.get('ok'))} en SSH")
        # appareils
        rows = []
        self._host_ips = []
        for ip in sorted(hosts, key=_ipkey):
            h = hosts[ip]
            self._host_ips.append(ip)
            rows.append([ip + (" ◌" if h.get("inactive") else ""), h.get("name") or "", h.get("kind_label") or "", h.get("confidence") or "",
                         h.get("vendor") or "", h.get("mac") or "", h.get("model") or "", h.get("os") or "",
                         _ports_txt(h.get("ports")), ", ".join(h.get("seen_by") or []), h.get("network") or ""])
        fill_table(self.tables["Appareils"], rows, sortable=False)
        t = self.tables["Appareils"]
        grey = QColor(theme.palette().muted)
        for r, ip in enumerate(self._host_ips):
            if hosts[ip].get("inactive"):
                for col in range(t.columnCount()):
                    it = t.item(r, col)
                    if it:
                        it.setForeground(grey)
        # équipements
        snmpd = snap.get("snmp") or {}
        eq, pr, nb, where = [], [], [], []
        mac_name = {h.get("mac"): (h.get("name") or ip, ip) for ip, h in hosts.items() if h.get("mac")}
        for ip in sorted(snmpd, key=_ipkey):
            d = snmpd[ip]
            sy = d.get("sys") or {}
            ifs = d.get("interfaces") or []
            phys = [i for i in ifs if i.get("type") in PHYS_TYPES and not VIRTUAL_NAME.match(i.get("name") or i.get("descr") or "")]
            name = sy.get("name") or (hosts.get(ip) or {}).get("name") or ip
            eq.append([name, ip, sy.get("vendor") or "", (sy.get("descr") or "")[:120], _dur(sy.get("uptime_s")),
                       f"{sum(1 for i in phys if i.get('oper') == 1)} / {len(phys)}", str(len(d.get("lldp") or [])),
                       str(len(d.get("fdb") or [])), d.get("credential") or "", sy.get("location") or ""])
            nbr = {n.get("local_port"): n for n in d.get("lldp") or []}
            for i in phys:
                n = nbr.get(i.get("name")) or nbr.get(i.get("descr")) or nbr.get(str(i.get("index")))
                pr.append([name, i.get("name") or i.get("descr") or str(i.get("index")), i.get("alias") or "",
                           {1: "actif", 2: "inactif", 7: "absent"}.get(i.get("oper"), str(i.get("oper") or "")),
                           f"{i.get('mbps')} Mb/s" if i.get("mbps") else "", i.get("duplex") or "",
                           (str(i.get("in_err") or 0), i.get("in_err") or 0), (str(i.get("out_err") or 0), i.get("out_err") or 0),
                           (str((i.get("in_disc") or 0) + (i.get("out_disc") or 0)), (i.get("in_disc") or 0) + (i.get("out_disc") or 0)),
                           (str(i.get("fcs") or ""), i.get("fcs") or 0),
                           (n.get("sys_name") or n.get("chassis") or "") + (f" / {n.get('port')}" if n and n.get("port") else "") if n else ""])
            for n in d.get("lldp") or []:
                nb.append([name, n.get("local_port") or "", n.get("sys_name") or n.get("chassis") or "", n.get("port_desc") or n.get("port") or "",
                           n.get("mgmt_ip") or "", ", ".join(n.get("caps") or []), (n.get("sys_desc") or "")[:100]])
            for n in d.get("cdp") or []:
                nb.append([name, n.get("local_if") or "", n.get("device_id") or "", n.get("port") or "", n.get("address") or "",
                           "CDP", n.get("platform") or ""])
            # appareils par port (table MAC) : seulement les ports d'accès (une seule MAC apprise ou pas de voisin LLDP)
            bp = d.get("bridge_ports") or {}
            ifname = {str(i.get("index")): (i.get("name") or i.get("descr")) for i in ifs}
            per_port: dict = {}
            for e in d.get("fdb") or []:
                per_port.setdefault(str(e.get("bridge_port")), []).append(e)
            for port, lst in per_port.items():
                if len(lst) > 3:            # lien vers un autre switch / une borne : beaucoup de MAC
                    continue
                for e in lst:
                    who = mac_name.get(e["mac"])
                    if who and who[1] != ip:
                        where.append([who[0], who[1], e["mac"], name, ifname.get(str(bp.get(port, port)), f"port {port}"), e.get("vlan") or ""])
        fill_table(self.tables["Équipements"], eq)
        fill_table(self.tables["Ports des switchs"], pr, numeric={6, 7, 8, 9})
        fill_table(self.tables["Voisins LLDP / CDP"], nb)
        fill_table(self.tables["Où est branché ?"], sorted(where, key=lambda r: _ipkey(r[1])))
        # services
        con = snap.get("connect") or {}
        sv = []
        g = con.get("gateway_ping") or {}
        if g:
            sv.append(["Ping passerelle", g.get("target"), f"{g.get('received')}/{g.get('sent')} réponses",
                       f"moy {g.get('avg')} ms · max {g.get('max')} ms · gigue {g.get('jitter')} ms"])
        for tg, r in (con.get("pings") or {}).items():
            sv.append(["Ping Internet", tg, f"{r.get('received')}/{r.get('sent')} réponses", f"moy {r.get('avg')} ms · gigue {r.get('jitter')} ms"])
        for hname, r in (con.get("https") or {}).items():
            sv.append(["HTTPS", hname, "OK" if r.get("ok") else "échec",
                       r.get("error") or f"DNS {r.get('dns_ms')} ms · TLS {r.get('tls_ms')} ms · {r.get('issuer')}"])
        for srv, r in (con.get("dns") or {}).items():
            sv.append(["Serveur DNS", srv, "OK" if r.get("ok") else "muet",
                       f"moy {r.get('avg_ms')} ms · {r.get('failed')} échec(s) · nom inexistant → {r.get('nxdomain')}"])
        m = con.get("mtu") or {}
        if m:
            sv.append(["MTU", m.get("target"), f"{m.get('mtu') or '—'} octets", ""])
        for s_, r in (con.get("ntp") or {}).items():
            sv.append(["Heure (NTP)", s_, f"écart {r.get('offset_s')} s" if r.get("ok") else "pas de réponse", r.get("error") or ""])
        pub = con.get("public") or {}
        if pub.get("ok"):
            sv.append(["IP publique", pub.get("ip"), pub.get("isp") or "", pub.get("ptr") or ""])
        for net, r in (snap.get("dhcp") or {}).items():
            offers = r.get("offers") or []
            sv.append(["DHCP", net, f"{len(offers)} offre(s)", "; ".join(
                f"{o.get('server_id') or o.get('source')} → {o.get('offered_ip')} (passerelle {', '.join(o.get('router') or [])})" for o in offers)
                or r.get("error") or ""])
        fill_table(self.tables["Services"], sv)
        # journaux SSH
        out = []
        for ip, r in (snap.get("ssh") or {}).items():
            out.append(f"===== {ip} — {r.get('profile', '')} — {'OK' if r.get('ok') else r.get('error')}")
            for cmd, txt in (r.get("outputs") or {}).items():
                out.append(f"\n$ {cmd}\n{txt.strip()}")
            out.append("\n")
        self.ssh_txt.setPlainText("\n".join(out) or "Aucun équipement interrogé en SSH.")
        self._filter(self.search.text())

    def _host_detail(self):
        rows = self.tables["Appareils"].selectionModel().selectedRows()
        a = self.ctx.analysis
        if not rows or not a or rows[0].row() >= len(self._host_ips):
            return
        ip = self._host_ips[rows[0].row()]
        h = (a.hosts or {}).get(ip, {})
        raw = (self.ctx.snap.get("hosts") or {}).get(ip, {})
        import html
        e = html.escape
        p = [f"<h3>{e(h.get('name') or ip)}</h3><p><b>{e(h.get('kind_label') or '')}</b> (certitude {e(h.get('confidence') or '—')})</p>"]
        p.append("<p>" + "<br>".join(e(x) for x in (f"Adresse : {ip}", f"MAC : {h.get('mac') or '—'} {h.get('vendor') or ''}",
                                                      f"Modèle : {h.get('model') or '—'}", f"Système : {h.get('os') or '—'}",
                                                      f"TTL : {h.get('ttl') or '—'} · temps de réponse : {h.get('rtt') or '—'} ms")) + "</p>")
        if h.get("evidence"):
            p.append("<p><b>Indices</b><br>" + "<br>".join(e(x) for x in h["evidence"]) + "</p>")
        n = raw.get("names") or {}
        if n:
            lines = []
            if n.get("dns"):
                lines.append(f"DNS : {n['dns']}")
            if n.get("netbios"):
                nb = n["netbios"]
                lines.append(f"NetBIOS : {nb.get('name')} ({nb.get('workgroup') or ''})")
            if n.get("mdns"):
                md = n["mdns"]
                lines.append(f"mDNS : {', '.join(md.get('names') or [])} · services {', '.join(md.get('services') or [])}")
            if n.get("ssdp"):
                ss = n["ssdp"]
                lines.append(f"UPnP : {ss.get('friendly') or ''} {ss.get('manufacturer') or ''} {ss.get('model') or ''} · {ss.get('server') or ''}")
            p.append("<p><b>Noms annoncés</b><br>" + "<br>".join(e(x) for x in lines) + "</p>")
        if raw.get("ports"):
            p.append("<p><b>Ports ouverts</b><br>" + e(_ports_txt(raw["ports"])) + "</p>")
        for w in raw.get("web") or []:
            if w and not w.get("error"):
                cert = w.get("cert") or {}
                p.append(f"<p>Web {w.get('port')} : {w.get('status')} « {e(w.get('title') or '')} » {e(w.get('server') or '')}"
                         + (f"<br>certificat {e(cert.get('subject') or '')} jusqu'au {e((cert.get('not_after') or '')[:10])}" if cert else "") + "</p>")
        for port, b in (raw.get("banners") or {}).items():
            p.append(f"<p>Bannière {port} : <code>{e(b)}</code></p>")
        self.detail.setHtml("".join(p))

    def _filter(self, txt: str):
        txt = (txt or "").lower().strip()
        w = self.tabs.currentWidget()
        if isinstance(w, QSplitter):
            w = w.widget(0)
        if w is self.ssh_txt or w is None:
            return
        for r in range(w.rowCount()):
            show = not txt or any(txt in (w.item(r, c).text().lower() if w.item(r, c) else "") for c in range(w.columnCount()))
            w.setRowHidden(r, not show)
