"""Mémorisation facultative des identifiants SNMP / SSH, chiffrés par Windows
(DPAPI, propre à l'utilisateur et au PC) : illisibles sur un autre poste,
même en copiant la clé USB. Jamais écrits dans les rapports ni l'historique."""
from __future__ import annotations

import base64
import ctypes
import json
import logging
from ctypes import wintypes

from .net.snmp import Credential
from .net.ssh import SshCred

log = logging.getLogger(__name__)


class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    b = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    b._buf = buf          # garder le tampon en vie
    return b


def protect(data: bytes) -> bytes:
    out = _BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(_blob(data)), "NetAuditPro", None, None, None, 0x1, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def unprotect(data: bytes) -> bytes:
    out = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(_blob(data)), None, None, None, None, 0x1, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def save(settings, snmp_creds: list[Credential], ssh_creds: list[SshCred]):
    d = {"snmp": [c.__dict__ for c in snmp_creds], "ssh": [c.__dict__ for c in ssh_creds]}
    settings.set("secrets.blob", base64.b64encode(protect(json.dumps(d).encode("utf-8"))).decode("ascii"))
    settings.save()


def load(settings) -> tuple[list[Credential], list[SshCred]]:
    raw = settings.get("secrets.blob", "")
    if not raw:
        return [], []
    try:
        d = json.loads(unprotect(base64.b64decode(raw)).decode("utf-8"))
        return [Credential(**x) for x in d.get("snmp", [])], [SshCred(**x) for x in d.get("ssh", [])]
    except Exception as exc:      # autre PC / autre utilisateur : illisible, on ignore
        log.info("Identifiants mémorisés illisibles (%s)", exc)
        return [], []


def forget(settings):
    settings.set("secrets.blob", "")
    settings.save()
