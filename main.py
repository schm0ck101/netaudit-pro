"""Lanceur de NetAudit Pro (utilisé aussi par PyInstaller)."""
import sys

from netaudit.app import main

if __name__ == "__main__":
    sys.exit(main())
