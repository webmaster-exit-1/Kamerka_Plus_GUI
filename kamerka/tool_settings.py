"""
tool_settings.py – Configurable paths for external security tools.

All paths default to the tool name only (i.e. the executable is resolved
via the system ``$PATH``), which is the correct behaviour when naabu and
nuclei have been installed with ``go install`` or a package manager.

Customisation options (choose one)
------------------------------------
1. **Environment variables** (recommended for CI / containers)::

       export KAMERKA_NAABU_BIN=/opt/tools/naabu
       export KAMERKA_NUCLEI_BIN=/opt/tools/nuclei

2. **Direct edit** – change the ``*_DEFAULT`` constants below to hardcoded
   absolute paths if you prefer not to use environment variables::

       NAABU_DEFAULT  = "/home/user/go/bin/naabu"
       NUCLEI_DEFAULT = "/home/user/go/bin/nuclei"

These settings are imported into ``kamerka/settings.py`` and exposed as
``settings.NAABU_BIN`` / ``settings.NUCLEI_BIN`` so every part of the
application (Celery tasks, verification pipeline, GUI launcher) reads from
a single authoritative source.

Scan-behaviour tuning
---------------------
``NAABU_DEFAULT_PORTS``   Port spec passed to Naabu when the caller does not
                          supply one.  Accepts any value naabu's ``-p`` flag
                          understands (comma list, range, or preset name).
``NUCLEI_DEFAULT_TIMEOUT``  Maximum seconds a single Nuclei scan may run.
``NAABU_DEFAULT_TIMEOUT``   Maximum seconds a single Naabu scan may run.
"""

import os

# ---------------------------------------------------------------------------
# Naabu
# ---------------------------------------------------------------------------

#: Default Naabu binary name / path.  Override via ``KAMERKA_NAABU_BIN`` env
#: var or edit this constant directly.
NAABU_DEFAULT: str = "naabu"

NAABU_BIN: str = os.environ.get("KAMERKA_NAABU_BIN", NAABU_DEFAULT)

#: Default port specification for :func:`verification.naabu_scanner.run_naabu`.
NAABU_DEFAULT_PORTS: str = os.environ.get("KAMERKA_NAABU_PORTS", "top-100")

#: Naabu subprocess timeout in seconds.
NAABU_DEFAULT_TIMEOUT: int = int(os.environ.get("KAMERKA_NAABU_TIMEOUT", "60"))

# ---------------------------------------------------------------------------
# Naabu – on-demand device port discovery
# ---------------------------------------------------------------------------
# When a Device has no port data, scan tasks call _resolve_open_ports() which
# runs a full Naabu scan to discover open ports before further testing.
# Override via env vars or edit below.

#: Port range used for device port discovery (when device.port is empty).
#: "1-65535" scans every TCP port; tune to "top-1000" for faster results.
NAABU_DISCOVERY_PORTS: str = os.environ.get("KAMERKA_NAABU_DISCOVERY_PORTS", "1-65535")

#: Timeout in seconds for a discovery scan (full range needs more time).
NAABU_DISCOVERY_TIMEOUT: int = int(os.environ.get("KAMERKA_NAABU_DISCOVERY_TIMEOUT", "120"))

# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------

#: Default Nuclei binary name / path.  Override via ``KAMERKA_NUCLEI_BIN``
#: env var or edit this constant directly.
NUCLEI_DEFAULT: str = "nuclei"

NUCLEI_BIN: str = os.environ.get("KAMERKA_NUCLEI_BIN", NUCLEI_DEFAULT)

#: Nuclei subprocess timeout in seconds.
NUCLEI_DEFAULT_TIMEOUT: int = int(os.environ.get("KAMERKA_NUCLEI_TIMEOUT", "300"))
