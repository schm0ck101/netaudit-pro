"""Construit assets/oui.txt.gz (préfixe hexadécimal<TAB>fabricant) à partir des
registres IEEE (MA-L 24 bits, MA-M 28 bits, MA-S 36 bits), téléchargés dans
dev/oui/ :
  https://standards-oui.ieee.org/oui/oui.csv
  https://standards-oui.ieee.org/oui28/mam.csv
  https://standards-oui.ieee.org/oui36/oui36.csv
Les noms sont raccourcis (« Co., Ltd », « Inc. »… retirés) pour l'affichage."""
import csv
import gzip
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "dev" / "oui"
SUFFIX = re.compile(r"[,.]?\s+(co\.?,?\s*ltd\.?|corporation|corp\.?|inc\.?|incorporated|limited|ltd\.?|gmbh|s\.?a\.?s?\.?|"
                    r"s\.?r\.?l\.?|b\.?v\.?|ag|llc|l\.?l\.?c\.?|co\.?|company|technologies|technology|electronics|"
                    r"international|holdings?|group|pte|pty|plc|oy|ab|as|a/s|kg|spa|s\.p\.a\.)\b\.?", re.I)


def short(name: str) -> str:
    n = " ".join(name.replace('"', "").split())
    for _ in range(3):
        n2 = SUFFIX.sub("", n).strip(" ,.")
        if n2 == n or len(n2) < 3:
            break
        n = n2
    return n[:40]


def main():
    rows = {}
    for f in ("oui.csv", "mam.csv", "oui36.csv"):
        p = SRC / f
        if not p.exists():
            print("absent :", p)
            continue
        with p.open(encoding="utf-8", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                a = (r.get("Assignment") or "").strip().upper()
                org = short(r.get("Organization Name") or "")
                if a and org and org.upper() != "PRIVATE":
                    rows[a] = org
    out = ROOT / "assets" / "oui.txt.gz"
    with gzip.open(out, "wt", encoding="utf-8", compresslevel=9) as g:
        for k in sorted(rows):
            g.write(f"{k}\t{rows[k]}\n")
    print(len(rows), "préfixes ->", out, out.stat().st_size, "octets")


if __name__ == "__main__":
    main()
