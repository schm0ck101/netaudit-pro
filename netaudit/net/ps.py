"""Exécution de Windows PowerShell 5.1 sans fenêtre (repris de SysAudit Pro).

Le script est transmis par l'entrée standard : aucun fichier .ps1 écrit dans
%TEMP%, pas de contournement de la stratégie d'exécution (moins « suspect »
pour les antivirus comportementaux).
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)
CREATE_NO_WINDOW = 0x08000000


def powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    # processus 32 bits sur Windows 64 bits : passer par Sysnative pour voir le vrai système
    for sub in ("Sysnative", "System32"):
        p = Path(root) / sub / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if p.exists():
            return str(p)
    return "powershell.exe"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relance l'application avec élévation (invite UAC). True si lancée."""
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe = sys.executable.replace("python.exe", "pythonw.exe")
        params = " ".join(f'"{a}"' for a in [os.path.abspath(sys.argv[0])] + sys.argv[1:])
    try:
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(r) > 32
    except Exception:
        log.exception("Élévation impossible")
        return False


def parse_output(txt: str) -> tuple[dict, str, bool]:
    """Lignes « @@{json} » (une section chacune), « @@>nom » (section en cours),
    « @@END ». Renvoie (données, dernière section commencée, fin atteinte)."""
    data: dict = {}
    current, ended = "", False
    for line in txt.splitlines():
        line = line.strip()
        if line == "@@END":
            ended = True
        elif line.startswith("@@>"):
            current = line[3:]
        elif line.startswith("@@{"):
            try:
                data.update(json.loads(line[2:]))
            except json.JSONDecodeError:
                log.warning("Section illisible : %s", line[:120])
    errs = data.get("_errors")
    if errs is not None and not isinstance(errs, list):
        data["_errors"] = [errs]
    return data, current, ended


# Le script est transmis en mémoire par l'entrée standard puis exécuté comme bloc de script :
# aucun fichier écrit sur le disque, et pas de « -ExecutionPolicy Bypass » (la stratégie
# d'exécution ne concerne que les fichiers .ps1). Le contenu reste analysé par l'antivirus (AMSI).
STDIN_RUNNER = "$s = [Console]::In.ReadToEnd(); & ([scriptblock]::Create($s))"


def to_ascii_script(text: str) -> bytes:
    """Retire les lignes de commentaire (seules à contenir des accents) : l'entrée standard de
    PowerShell 5.1 est lue dans la page de code de la console, l'ASCII est sûr partout."""
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def run_script(text: str, timeout: int, cancel: threading.Event | None = None) -> tuple[dict | None, str]:
    """Exécute un script et renvoie (objet JSON, erreur)."""
    payload = to_ascii_script(text)
    cmd = [powershell_exe(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", STDIN_RUNNER]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                             creationflags=CREATE_NO_WINDOW)
        t0 = time.monotonic()
        out = err = b""
        stopped = ""
        first = True
        while True:
            try:
                out, err = p.communicate(input=payload if first else None, timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                first = False
                if (cancel and cancel.is_set()) or time.monotonic() - t0 > timeout:
                    p.kill()
                    out, err = p.communicate()      # ce qui a déjà été écrit est conservé
                    stopped = "annulé" if cancel and cancel.is_set() else f"délai dépassé ({timeout} s)"
                    break
        data, current, ended = parse_output(out.decode("utf-8", "replace"))
        if stopped:
            if current and not ended:
                stopped += f" pendant « {current} »"
                data.setdefault("_errors", []).append(f"{current}: {stopped}")
            return (data or None), stopped
        if not data:
            return None, (err.decode("utf-8", "replace") or out.decode("utf-8", "replace") or "aucune donnée").strip()[:800]
        return data, ""
    except OSError as exc:
        return None, f"PowerShell introuvable ou bloqué : {exc}"




PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$R = [ordered]@{}
$script:E = New-Object System.Collections.ArrayList
function D($d) { if ($null -eq $d -or "$d" -eq '') { return $null }; try { return ([datetime]$d).ToString('o') } catch { return $null } }
# Chaque section est écrite dès qu'elle est prête (une ligne « @@{json} ») :
# si le script dépasse son délai, les sections déjà collectées sont conservées
# et « @@>nom » indique celle qui était en cours.
function Emit([string]$k, $v) {
  $h = @{}; $h[$k] = $v
  # JSON en ASCII pur (accents en \uXXXX) : indépendant de la page de code de la console
  $j = [regex]::Replace((ConvertTo-Json -InputObject $h -Depth 7 -Compress), '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
  [Console]::Out.WriteLine('@@' + $j); [Console]::Out.Flush()
}
function T([string]$k, [scriptblock]$b) {
  [Console]::Out.WriteLine("@@>$k"); [Console]::Out.Flush()
  try { $v = & $b; $R[$k] = $v; Emit $k $v } catch { [void]$script:E.Add("${k}: $($_.Exception.Message)") }
}
# TL : section de type liste (PowerShell « déroule » un tableau d'un seul élément)
function TL([string]$k, [scriptblock]$b) {
  [Console]::Out.WriteLine("@@>$k"); [Console]::Out.Flush()
  try { $v = @(& $b | Where-Object { $null -ne $_ }); $R[$k] = $v; Emit $k $v } catch { [void]$script:E.Add("${k}: $($_.Exception.Message)") }
}
"""


def run(body: str, timeout: int = 60, cancel: threading.Event | None = None) -> tuple[dict, str]:
    """PRELUDE + corps ; renvoie (sections, erreur)."""
    tail = "\nEmit '_errors' @($script:E)\n[Console]::Out.WriteLine('@@END')\n"
    data, err = run_script(PRELUDE + "\n" + body + tail, timeout, cancel)
    return data or {}, err
