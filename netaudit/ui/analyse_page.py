"""Page « Diagnostic » : intervention, options, identifiants (facultatifs),
lancement en arrière-plan et suivi étape par étape."""
from __future__ import annotations

import logging
import threading
import time

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGridLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
                               QProgressBar, QPushButton, QRadioButton, QScrollArea, QVBoxLayout, QWidget)

from .. import secrets
from ..analyze.engine import analyze
from ..net import local
from ..net.snmp import Credential
from ..net.ssh import SshCred
from ..scan import runner
from . import theme
from .common import muted, page_title, panel

log = logging.getLogger(__name__)


# ------------------------------------------------------------------ dialogues
class SnmpDialog(QDialog):
    def __init__(self, parent=None, v3: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Identifiant SNMPv3" if v3 else "Communauté SNMP v1 / v2c")
        self.v3 = v3
        f = QFormLayout(self)
        if v3:
            self.user = QLineEdit()
            self.auth = QComboBox()
            self.auth.addItems(["SHA", "SHA256", "MD5", "(aucune)"])
            self.apass = QLineEdit()
            self.apass.setEchoMode(QLineEdit.Password)
            self.priv = QComboBox()
            self.priv.addItems(["AES", "(aucun)"])
            self.ppass = QLineEdit()
            self.ppass.setEchoMode(QLineEdit.Password)
            f.addRow("Utilisateur", self.user)
            f.addRow("Authentification", self.auth)
            f.addRow("Mot de passe d'authentification", self.apass)
            f.addRow("Chiffrement", self.priv)
            f.addRow("Mot de passe de chiffrement", self.ppass)
            f.addRow(muted("AES-128 uniquement (DES, AES-192/256 non pris en charge)."))
        else:
            self.ver = QComboBox()
            self.ver.addItems(["2c", "1"])
            self.comm = QLineEdit()
            self.comm.setEchoMode(QLineEdit.Password)
            f.addRow("Version", self.ver)
            f.addRow("Communauté", self.comm)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def credential(self) -> Credential | None:
        if self.v3:
            if not self.user.text().strip():
                return None
            auth = "" if self.auth.currentText().startswith("(") else self.auth.currentText()
            priv = "" if (self.priv.currentText().startswith("(") or not auth) else self.priv.currentText()
            return Credential("3", "", self.user.text().strip(), auth, self.apass.text(), priv, self.ppass.text())
        if not self.comm.text():
            return None
        return Credential(self.ver.currentText(), self.comm.text())


class SshDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Identifiant SSH (lecture seule)")
        f = QFormLayout(self)
        self.user = QLineEdit()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        self.key = QLineEdit()
        self.key.setPlaceholderText("(facultatif) fichier de clé privée")
        b = QPushButton("…")
        b.clicked.connect(lambda: self.key.setText(QFileDialog.getOpenFileName(self, "Clé privée")[0] or self.key.text()))
        rl.addWidget(self.key, 1)
        rl.addWidget(b)
        f.addRow("Utilisateur", self.user)
        f.addRow("Mot de passe", self.pw)
        f.addRow("Clé", row)
        f.addRow(muted("Seules des commandes d'affichage (show / display / get…) sont envoyées."))
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def credential(self) -> SshCred | None:
        if not self.user.text().strip():
            return None
        return SshCred(self.user.text().strip(), self.pw.text(), self.key.text().strip())


# ---------------------------------------------------------------- travailleurs
class Worker(QObject):
    progress = Signal(str, str, str, str)
    finished = Signal(object, object)
    failed = Signal(str)

    def __init__(self, opts: runner.Options, prev_snap: dict | None):
        super().__init__()
        self.opts = opts
        self.prev_snap = prev_snap
        self.cancel = threading.Event()

    def run(self):
        try:
            snap = runner.collect(self.opts, progress=lambda *a: self.progress.emit(*a), cancel=self.cancel)
            if self.cancel.is_set():
                self.failed.emit("Diagnostic annulé.")
                return
            self.finished.emit(snap, analyze(snap, self.prev_snap))
        except runner.Cancelled:
            self.failed.emit("Diagnostic annulé.")
        except Exception as exc:
            log.exception("Diagnostic")
            self.failed.emit(str(exc))


class NetProbe(QObject):
    done = Signal(object)

    def run(self):
        try:
            loc = local.collect()
            self.done.emit({"networks": local.networks(loc), "gateway": local.default_gateway(loc),
                            "host": (loc.get("host") or {})})
        except Exception as exc:
            log.exception("Réseaux du poste")
            self.done.emit({"error": str(exc)})


def _split(txt: str) -> list[str]:
    return [x.strip() for x in txt.replace(";", ",").replace("\n", ",").split(",") if x.strip()]


# --------------------------------------------------------------------- page
class AnalysePage(QWidget):
    done = Signal(int)

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.thread: QThread | None = None
        self.worker: Worker | None = None
        self.snmp_creds: list[Credential] = []
        self.ssh_creds: list[SshCred] = []
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        root = QVBoxLayout(body)
        root.setContentsMargins(28, 22, 28, 18)
        root.setSpacing(12)
        root.addWidget(page_title("Diagnostic du réseau"))
        root.addWidget(muted("Branchez ce PC sur le réseau à diagnostiquer (de préférence en filaire). Lecture seule : aucune "
                             "configuration n'est modifiée, aucun mot de passe n'est essayé. Durée : 1 à 5 minutes selon la taille."))

        # réseaux détectés
        box, bl = panel()
        self.nets_lbl = QLabel("Recherche des réseaux du poste…")
        self.nets_lbl.setWordWrap(True)
        self.nets_lbl.setTextFormat(Qt.RichText)
        bl.addWidget(self.nets_lbl)
        root.addWidget(box)

        # intervention
        box, bl = panel()
        bl.addWidget(QLabel("<b>Intervention</b>"))
        form = QFormLayout()
        self.client = QComboBox()
        self.client.setEditable(True)
        self.client.setInsertPolicy(QComboBox.NoInsert)
        self.client.lineEdit().setPlaceholderText("Nom du client (facultatif)")
        self.site = QLineEdit()
        self.site.setPlaceholderText("Site, bâtiment ou réseau (ex. « Siège — réseau bureautique »)")
        self.notes = QLineEdit()
        self.notes.setPlaceholderText("Motif de l'intervention, remarques…")
        form.addRow("Client", self.client)
        form.addRow("Site", self.site)
        form.addRow("Notes", self.notes)
        bl.addLayout(form)
        root.addWidget(box)

        # options
        box, bl = panel()
        bl.addWidget(QLabel("<b>Étendue et intensité</b>"))
        mode = QHBoxLayout()
        self.r_quick = QRadioButton("Discret")
        self.r_deep = QRadioButton("Approfondi")
        mode.addWidget(self.r_quick)
        mode.addWidget(self.r_deep)
        mode.addStretch(1)
        bl.addLayout(mode)
        bl.addWidget(muted("Discret : ~30 ports courants, une seule tentative, pas de requête DHCP. "
                           "Approfondi : ~130 ports, test des serveurs DHCP (détection d'un DHCP pirate), sondes répétées — "
                           "plus long et plus visible pour une sonde de détection d'intrusion."))
        f2 = QFormLayout()
        self.ranges = QLineEdit()
        self.ranges.setPlaceholderText("ex. 10.0.20.0/24, 10.0.30.1-10.0.30.80 (autres VLAN routés)")
        self.exclude = QLineEdit()
        self.exclude.setPlaceholderText("ex. 192.168.1.50, 192.168.1.200-192.168.1.220 (appareils sensibles à ne pas sonder)")
        f2.addRow("Plages supplémentaires", self.ranges)
        f2.addRow("Adresses exclues", self.exclude)
        bl.addLayout(f2)
        root.addWidget(box)

        # identifiants
        box, bl = panel()
        bl.addWidget(QLabel("<b>Accès aux équipements (facultatif)</b>"))
        bl.addWidget(muted("SNMP (lecture) permet de contrôler les ports des switchs : erreurs, duplex, voisins, spanning tree, PoE. "
                           "SSH permet de lire leurs journaux (boucles, ports désactivés…). Sans identifiant, le diagnostic "
                           "se limite à ce qui est visible depuis le réseau."))
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        self.snmp_list = QListWidget()
        self.snmp_list.setMaximumHeight(90)
        self.ssh_list = QListWidget()
        self.ssh_list.setMaximumHeight(90)
        grid.addWidget(QLabel("SNMP"), 0, 0)
        grid.addWidget(QLabel("SSH"), 0, 1)
        grid.addWidget(self.snmp_list, 1, 0)
        grid.addWidget(self.ssh_list, 1, 1)
        sb = QHBoxLayout()
        for label, fn in (("+ v1/v2c", lambda: self.add_snmp(False)), ("+ v3", lambda: self.add_snmp(True)),
                          ("Retirer", self.del_snmp)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            sb.addWidget(b)
        sb.addStretch(1)
        hb = QHBoxLayout()
        for label, fn in (("+ identifiant", self.add_ssh), ("Retirer", self.del_ssh)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            hb.addWidget(b)
        hb.addStretch(1)
        grid.addLayout(sb, 2, 0)
        grid.addLayout(hb, 2, 1)
        self.try_public = QCheckBox("Essayer aussi la communauté par défaut « public » (détecte une faille courante)")
        self.ssh_targets = QLineEdit()
        self.ssh_targets.setPlaceholderText("IP supplémentaires à interroger en SSH (par défaut : switchs/routeurs détectés)")
        grid.addWidget(self.try_public, 3, 0)
        grid.addWidget(self.ssh_targets, 3, 1)
        bl.addLayout(grid)
        self.remember = QCheckBox("Mémoriser ces identifiants sur ce PC (chiffrés par Windows, pour mon compte uniquement)")
        bl.addWidget(self.remember)
        root.addWidget(box)

        # lancement
        row = QHBoxLayout()
        self.go = QPushButton("  Lancer le diagnostic")
        self.go.setObjectName("Primary")
        self.go.setMinimumHeight(42)
        self.go.setMinimumWidth(240)
        self.go.clicked.connect(self.start)
        self.stop_btn = QPushButton("Annuler")
        self.stop_btn.clicked.connect(self.stop)
        self.stop_btn.hide()
        row.addWidget(self.go)
        row.addWidget(self.stop_btn)
        self.status = QLabel("")
        self.status.setObjectName("Muted")
        row.addWidget(self.status, 1)
        root.addLayout(row)
        self.bar = QProgressBar()
        self.bar.setRange(0, len(runner.STEPS))
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.bar.hide()
        root.addWidget(self.bar)
        self.steps_box, sl = panel()
        g = QGridLayout()
        g.setHorizontalSpacing(18)
        self.rows: dict[str, tuple[QLabel, QLabel, QLabel]] = {}
        for i, (key, label) in enumerate(runner.STEPS):
            dot, lab, st = QLabel("○"), QLabel(label), QLabel("en attente")
            st.setObjectName("Muted")
            st.setWordWrap(True)
            g.addWidget(dot, i, 0)
            g.addWidget(lab, i, 1)
            g.addWidget(st, i, 2)
            self.rows[key] = (dot, lab, st)
        g.setColumnStretch(2, 1)
        sl.addLayout(g)
        self.steps_box.hide()
        root.addWidget(self.steps_box)
        root.addStretch(1)
        self.t0 = 0.0
        self.timer = QTimer(self, interval=500, timeout=self._tick)
        self.reload()
        self._probe_networks()

    # ---------------------------------------------------------------- réseaux
    def _probe_networks(self):
        self._pt = QThread(self)
        self._pw = NetProbe()
        self._pw.moveToThread(self._pt)
        self._pt.started.connect(self._pw.run)
        self._pw.done.connect(self._nets_ready)
        self._pw.done.connect(self._pt.quit)
        self._pt.start()

    def _nets_ready(self, d: dict):
        p = theme.palette()
        if d.get("error"):
            self.nets_lbl.setText(f"<span style='color:{p.crit}'>Réseaux du poste illisibles : {d['error']}</span>")
            return
        nets = d.get("networks") or []
        if not nets:
            self.nets_lbl.setText(f"<b style='color:{p.crit}'>Aucun réseau IPv4 actif sur ce PC.</b> Branchez-le au réseau du client.")
            return
        lines = [f"<b>{n['network']}</b> — adresse {n['local_ip']} sur « {n.get('adapter')} »"
                 + (f", passerelle {n['gateway']}" if n.get("gateway") else "") + (" (DHCP)" if n.get("dhcp") else " (IP fixe)")
                 for n in nets]
        h = d.get("host") or {}
        dom = f" · domaine {h.get('domain')}" if h.get("part_of_domain") else ""
        self.nets_lbl.setText(f"<b>Réseaux qui seront analysés</b> (poste {h.get('name', '')}{dom}) :<br>" + "<br>".join(lines))

    # ----------------------------------------------------------- identifiants
    def add_snmp(self, v3: bool):
        dlg = SnmpDialog(self, v3)
        if dlg.exec() and (c := dlg.credential()):
            self.snmp_creds.append(c)
            self._fill_creds()

    def del_snmp(self):
        r = self.snmp_list.currentRow()
        if r >= 0:
            del self.snmp_creds[r]
            self._fill_creds()

    def add_ssh(self):
        dlg = SshDialog(self)
        if dlg.exec() and (c := dlg.credential()):
            self.ssh_creds.append(c)
            self._fill_creds()

    def del_ssh(self):
        r = self.ssh_list.currentRow()
        if r >= 0:
            del self.ssh_creds[r]
            self._fill_creds()

    def _fill_creds(self):
        self.snmp_list.clear()
        for c in self.snmp_creds:
            self.snmp_list.addItem(QListWidgetItem(c.label()))
        self.ssh_list.clear()
        for c in self.ssh_creds:
            self.ssh_list.addItem(QListWidgetItem(c.label()))

    # ------------------------------------------------------------------ état
    def reload(self):
        s = self.ctx.settings
        cur = self.client.currentText()
        self.client.clear()
        self.client.addItems(self.ctx.store.clients())
        self.client.setCurrentText(cur or s.get("last.client", ""))
        if not self.site.text():
            self.site.setText(s.get("last.site", ""))
        deep = bool(s.get("scan.deep", False))
        self.r_deep.setChecked(deep)
        self.r_quick.setChecked(not deep)
        self.ranges.setText(s.get("scan.extra_ranges", "") or "")
        self.exclude.setText(s.get("scan.exclude", "") or "")
        self.try_public.setChecked(bool(s.get("scan.snmp_default_public", True)))
        self.remember.setChecked(bool(s.get("scan.remember_creds", False)))
        if self.remember.isChecked() and not self.snmp_creds and not self.ssh_creds:
            self.snmp_creds, self.ssh_creds = secrets.load(s)
            self._fill_creds()
        self.apply_theme()

    def apply_theme(self):
        self.go.setIcon(theme.glyph_icon(theme.G_PLAY, theme.palette().accent_text))

    def start(self):
        if self.thread:
            return
        s = self.ctx.settings
        s.set("last.client", self.client.currentText().strip())
        s.set("last.site", self.site.text().strip())
        s.set("scan.deep", self.r_deep.isChecked())
        s.set("scan.extra_ranges", self.ranges.text().strip())
        s.set("scan.exclude", self.exclude.text().strip())
        s.set("scan.snmp_default_public", self.try_public.isChecked())
        s.set("scan.remember_creds", self.remember.isChecked())
        try:
            if self.remember.isChecked():
                secrets.save(s, self.snmp_creds, self.ssh_creds)
            else:
                secrets.forget(s)
            s.save()
        except OSError:
            pass
        bad = runner.parse_ranges(_split(self.ranges.text()) + _split(self.exclude.text()))[2]
        if bad:
            QMessageBox.warning(self, "Plages", "Format non reconnu : " + ", ".join(bad)
                                + "\n\nFormats acceptés : 10.0.20.0/24 · 10.0.20.15 · 10.0.20.10-10.0.20.50 · 10.0.20.10-50")
            return
        opts = runner.Options(deep=self.r_deep.isChecked(), extra_ranges=_split(self.ranges.text()),
                              exclude=_split(self.exclude.text()), snmp_creds=list(self.snmp_creds),
                              snmp_try_public=self.try_public.isChecked(), ssh_creds=list(self.ssh_creds),
                              ssh_targets=_split(self.ssh_targets.text()))
        prev = None
        try:
            key_prefix = f"{self.client.currentText().strip()}|"
            for r in self.ctx.store.list(self.client.currentText().strip() or None):
                if (r.get("machine_key") or "").startswith(key_prefix) and (r.get("site") or "") == self.site.text().strip():
                    prev = (self.ctx.store.get(r["id"]) or {}).get("snapshot")
                    break
        except Exception:
            log.exception("diagnostic précédent")
        for dot, _lab, st in self.rows.values():
            dot.setText("○")
            dot.setStyleSheet("")
            st.setText("en attente")
        self.done_n = 0
        self.bar.setValue(0)
        self.bar.show()
        self.steps_box.show()
        QTimer.singleShot(50, lambda: self.scroll.ensureWidgetVisible(self.steps_box))
        self.go.setEnabled(False)
        self.stop_btn.show()
        self.t0 = time.monotonic()
        self.timer.start()
        self.thread = QThread(self)
        self.worker = Worker(opts, prev)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.thread.start()

    def stop(self):
        if self.worker:
            self.worker.cancel.set()
            self.status.setText("Annulation…")

    def _tick(self):
        self.status.setText(f"Diagnostic en cours… {time.monotonic() - self.t0:.0f} s")

    def _progress(self, key, _label, state, detail):
        p = theme.palette()
        if key not in self.rows:
            return
        dot, _lab, st = self.rows[key]
        if state == "start":
            dot.setText("●")
            dot.setStyleSheet(f"color:{p.accent}")
            st.setText("en cours…")
        elif state == "info":
            st.setText(f"en cours… {detail}")
        else:
            self.done_n += 1
            self.bar.setValue(self.done_n)
            if state == "error":
                dot.setText("✖")
                dot.setStyleSheet(f"color:{p.crit}")
            elif state == "skip":
                dot.setText("–")
                dot.setStyleSheet(f"color:{p.muted}")
            else:
                dot.setText("✓")
                dot.setStyleSheet(f"color:{p.ok}")
            st.setText(detail[:220])

    def _cleanup(self):
        self.timer.stop()
        if self.thread:
            self.thread.quit()
            self.thread.wait(5000)
        self.thread = self.worker = None
        self.go.setEnabled(True)
        self.stop_btn.hide()

    def _finished(self, snap, analysis):
        dur = time.monotonic() - self.t0
        self._cleanup()
        s = self.ctx.settings
        aid = self.ctx.store.save(client=self.client.currentText().strip(), site=self.site.text().strip(),
                                  notes=self.notes.text().strip(), auditor=s.get("report.auditor", ""),
                                  analysis=analysis, snapshot=snap)
        self.status.setText(f"Diagnostic terminé en {dur:.0f} s — note {analysis.scores.get('global')} / 100")
        self.notes.clear()
        self.reload()
        self.ctx.history_changed.emit()
        self.done.emit(aid)

    def _failed(self, msg):
        self._cleanup()
        self.status.setText(msg)
        if msg != "Diagnostic annulé.":
            QMessageBox.warning(self, "Diagnostic", f"Le diagnostic a échoué :\n{msg}")
