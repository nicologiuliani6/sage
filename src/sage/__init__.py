"""SAGE: SSVC-Aware Guarded Engine."""

import os

# Nelle immagini delle release la CI imposta SAGE_VERSION dal tag; in sviluppo vale questa.
__version__ = os.environ.get("SAGE_VERSION") or "0.2.2"
