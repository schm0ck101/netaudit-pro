"""Point d'entrée de NetAudit Pro."""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import sys
import threading
import traceback

from .config import APP_NAME, APP_VERSION, Settings, data_dir, setup_logging

log = logging.getLogger("netaudit")


def _compat_old_windows() -> None:
    """Windows 10 < 1809 / Server 2016 : le moteur de polices DirectWrite de Qt 6.8+
    (IDWriteFactory5, 1703+) n'y affiche que des carrés. On force le moteur GDI de
    Windows, avant toute création de QApplication. Sans effet sur les versions récentes."""
    try:
        if sys.platform == "win32" and sys.getwindowsversion().build < 17763:
            os.environ.setdefault("QT_QPA_PLATFORM", "windows:fontengine=gdi")
    except Exception:
        pass


_compat_old_windows()


def _excepthook(t, e, tb):
    log.error("Exception non gérée :\n%s", "".join(traceback.format_exception(t, e, tb)))
    from PySide6.QtWidgets import QApplication, QMessageBox
    if QApplication.instance() and threading.current_thread() is threading.main_thread():
        # emplacement précis (3 derniers appels) : suffit au support à partir d'une capture d'écran
        where = " ← ".join(f"{fr.filename.replace(chr(92), '/').rsplit('/', 1)[-1]}:{fr.lineno} {fr.name}"
                           for fr in reversed(traceback.extract_tb(tb)[-3:]))
        QMessageBox.warning(None, APP_NAME, f"Erreur inattendue (version {APP_VERSION}) :\n{e}\n\nEmplacement : {where}"
                                            f"\n\nDétails : {data_dir() / 'netaudit.log'}")


def cli_collect(out: str | None, pdf: str | None = None, client: str = "", site: str = "", deep: bool = False,
                ranges: str = "", exclude: str = "", communities: str = "", ssh_user: str = "", ssh_key: str = "",
                ssh_targets: str = "") -> int:
    """Mode ligne de commande (sans interface) : diagnostic -> JSON et/ou PDF.
    Le mot de passe SSH éventuel est lu dans la variable d'environnement NETAUDIT_SSH_PASSWORD
    (jamais en argument : il resterait visible dans la liste des processus)."""
    import os

    from .analyze.engine import analyze
    from .net.snmp import Credential
    from .net.ssh import SshCred
    from .scan import runner
    split = lambda t: [x.strip() for x in (t or "").split(",") if x.strip()]  # noqa: E731
    ssh_creds = [SshCred(ssh_user, os.environ.get("NETAUDIT_SSH_PASSWORD", ""), ssh_key)] if ssh_user else []
    opts = runner.Options(deep=deep, extra_ranges=split(ranges), exclude=split(exclude),
                          snmp_creds=[Credential("2c", c) for c in split(communities)], ssh_creds=ssh_creds,
                          ssh_targets=split(ssh_targets))
    snap = runner.collect(opts, progress=lambda k, label, st, d: print(f"[{st}] {label} {d}", flush=True) if st != "info" else None)
    a = analyze(snap)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"analysis": a.to_dict(), "snapshot": snap}, f, ensure_ascii=False, indent=1, default=str)
    if pdf:
        from PySide6.QtGui import QGuiApplication
        app = QGuiApplication.instance() or QGuiApplication(["NetAuditPro"])  # noqa: F841
        from . import report
        rec = {"client": client, "site": site, "ts": snap.get("started"), "snapshot_options": snap.get("options", {})}
        report.export_pdf(pdf, rec, a, Settings())
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="NetAuditPro")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--collect", metavar="FICHIER.json", help="diagnostic sans interface, résultat en JSON")
    ap.add_argument("--pdf", metavar="FICHIER.pdf", help="diagnostic sans interface, rapport PDF")
    ap.add_argument("--deep", action="store_true", help="mode approfondi")
    ap.add_argument("--ranges", default="", help="plages supplémentaires (séparées par des virgules)")
    ap.add_argument("--exclude", default="", help="adresses exclues")
    ap.add_argument("--community", default="", help="communautés SNMP v2c (séparées par des virgules)")
    ap.add_argument("--ssh-user", default="", help="utilisateur SSH (lecture seule) ; mot de passe : variable NETAUDIT_SSH_PASSWORD")
    ap.add_argument("--ssh-key", default="", help="fichier de clé privée SSH")
    ap.add_argument("--ssh-targets", default="", help="IP à interroger en SSH en plus des équipements réseau détectés")
    ap.add_argument("--client", default="")
    ap.add_argument("--site", default="")
    args, _rest = ap.parse_known_args(argv)
    setup_logging(args.debug)
    log.info("Démarrage %s %s", APP_NAME, APP_VERSION)
    if args.collect or args.pdf:
        try:
            return cli_collect(args.collect, args.pdf, args.client, args.site, args.deep, args.ranges, args.exclude, args.community,
                               args.ssh_user, args.ssh_key, args.ssh_targets)
        except Exception:
            log.exception("Mode ligne de commande")
            return 1
    sys.excepthook = _excepthook
    threading.excepthook = lambda a: log.error("Exception dans %s", a.thread.name,
                                               exc_info=(a.exc_type, a.exc_value, a.exc_traceback))
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SCHMOCK.NetAuditPro")
    except Exception:
        pass
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import QApplication

    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    from .store import Store
    from .ui import theme
    from .ui.context import AppContext
    from .ui.main_window import MainWindow

    settings = Settings()
    theme.apply_theme(settings.get("ui.theme", "dark"))
    app.setWindowIcon(QIcon(theme.app_icon_pixmap(256)))
    store = Store()
    ctx = AppContext(settings, store)
    win = MainWindow(ctx)
    win.show()
    code = app.exec()
    store.close()
    return code
