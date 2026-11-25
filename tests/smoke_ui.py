"""Test de bout en bout de l'interface : VRAI diagnostic du réseau courant,
captures de chaque page (thèmes sombre et clair), rapport PDF et export JSON.
Usage : python tests/smoke_ui.py <dossier de sortie> [--deep]"""
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("NETAUDIT_DATA_DIR", str(OUT / "data"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtGui import QFont  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from netaudit import report  # noqa: E402
from netaudit.config import Settings  # noqa: E402
from netaudit.store import Store  # noqa: E402
from netaudit.ui import theme  # noqa: E402
from netaudit.ui.context import AppContext  # noqa: E402
from netaudit.ui.main_window import MainWindow  # noqa: E402

app = QApplication([])
app.setStyle("Fusion")
app.setFont(QFont("Segoe UI", 10))
settings = Settings()
theme.apply_theme("dark")
store = Store()
ctx = AppContext(settings, store)
win = MainWindow(ctx)
win.resize(1500, 950)
win.show()


def wait(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def shot(name):
    wait(300)
    win.grab().save(str(OUT / f"{name}.png"))


wait(5000)        # réseaux du poste (PowerShell)
shot("01_diagnostic")
win.analyse.client.setCurrentText("Client Test")
win.analyse.site.setText("Siège")
win.analyse.notes.setText("Test de recette")
win.analyse.r_deep.setChecked("--deep" in sys.argv)
done = []
win.analyse.done.connect(lambda aid: done.append(aid))
t0 = time.time()
win.analyse.start()
wait(12000)
shot("02_en_cours")
while not done and time.time() - t0 < 600:
    wait(500)
print("diagnostic terminé en", round(time.time() - t0), "s, id", done)
assert done, "diagnostic non terminé"
shot("03_resultats")
a = ctx.analysis
print("notes", a.scores, "constats", len(a.findings), "erreurs de règles", a.rule_errors)
win.results.f_kind.setCurrentIndex(2)
shot("04_resultats_tous")
win.show_page(2)
for i in range(win.inventory.tabs.count()):
    win.inventory.tabs.setCurrentIndex(i)
    shot(f"05_appareils_{i}")
win.show_page(3)
shot("07_historique")
win.show_page(4)
shot("08_parametres")
settings.set("ui.theme", "light")
win.apply_settings()
win.show_page(1)
shot("09_resultats_clair")
win.show_page(2)
win.inventory.tabs.setCurrentIndex(0)
shot("10_appareils_clair")
pdf = OUT / "rapport.pdf"
report.export_pdf(pdf, ctx.rec, ctx.analysis, settings, ctx.prev)
report.export_json(OUT / "export.json", ctx.rec)
print("PDF", pdf.stat().st_size, "octets")
store.close()
