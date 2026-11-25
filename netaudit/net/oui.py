"""Fabricant d'une carte réseau d'après son adresse MAC (registres IEEE
embarqués : assets/oui.txt.gz, généré par tools/make_oui.py)."""
from __future__ import annotations

import gzip
import threading

_db: dict[str, str] | None = None
_lock = threading.Lock()


def _load() -> dict[str, str]:
    global _db
    with _lock:
        if _db is None:
            from ..config import asset_path
            d = {}
            try:
                with gzip.open(asset_path("oui.txt.gz"), "rt", encoding="utf-8") as f:
                    for line in f:
                        k, _sep, v = line.rstrip("\n").partition("\t")
                        d[k] = v
            except OSError:
                pass
            _db = d
    return _db


def is_random(mac: str) -> bool:
    """Adresse « administrée localement » (bit U/L) : MAC aléatoire des téléphones
    et PC récents (confidentialité Wi-Fi), ou adresse de machine virtuelle."""
    try:
        return bool(int(mac.replace(":", "").replace("-", "")[:2], 16) & 0x02)
    except ValueError:
        return False


def vendor(mac: str | None) -> str:
    if not mac:
        return ""
    h = mac.replace(":", "").replace("-", "").upper()
    if len(h) < 6:
        return ""
    db = _load()
    for n in (9, 7, 6):
        v = db.get(h[:n])
        if v:
            return v
    return "Adresse aléatoire (privée)" if is_random(mac) else ""
