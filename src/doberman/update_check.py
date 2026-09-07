"""Best-effort "a newer Doberman is on PyPI" notice — CLI-only and fail-open.

This module is never imported by the hook or proxy hot paths, and every public
operation is best-effort: any error (network, parse, disk) is swallowed and the
CLI proceeds silently. It never blocks a tool call and never raises.

PyPI is queried at most once per :data:`DEFAULT_INTERVAL`; the result is cached
under the user's ``.doberman`` dir. Between checks the cached latest version
drives the notice with no network at all, so the common path is a cheap file
read. The passive notice (``doberman status``) refreshes in the background and
shows on the *next* run — it never waits on the network; the explicit
``doberman update`` command does one synchronous, timeout-bounded check.

Respecting ``DO_NOT_TRACK`` / ``CI`` is politeness, not privacy-critical: the
check sends nothing but a normal PyPI GET (the same request ``pip`` makes). It is
on by default; ``DOBERMAN_UPDATE_CHECK=off`` turns it off.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from doberman import __version__
from doberman.storage.device_metrics import HOME_ENV

logger = logging.getLogger("doberman.update_check")

#: PyPI's JSON metadata endpoint for the distribution.
PYPI_JSON_URL = "https://pypi.org/pypi/doberman-core/json"
#: One-line upgrade instruction shown to the user (we never run pip for them).
UPGRADE_HINT = "pip install -U doberman-core"

_CACHE_NAME = "update-check.json"
#: How stale the cached "latest" may get before we hit PyPI again.
DEFAULT_INTERVAL = timedelta(hours=24)
_TIMEOUT_S = 2.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def disabled_reason() -> str | None:
    """Why the update check is off right now, or ``None`` if it may run."""
    do_not_track = os.environ.get("DO_NOT_TRACK", "")
    if do_not_track and do_not_track != "0":
        return "DO_NOT_TRACK is set"
    if os.environ.get("DOBERMAN_UPDATE_CHECK", "").lower() in {"0", "false", "off", "no"}:
        return "DOBERMAN_UPDATE_CHECK disables the update check"
    if os.environ.get("CI", ""):
        return "CI is set"
    return None


def _cache_path(home: Path | None = None) -> Path:
    base = home if home is not None else Path(os.environ.get(HOME_ENV) or Path.home())
    return base / ".doberman" / _CACHE_NAME


def _read_cache(home: Path | None = None) -> dict:
    try:
        return json.loads(_cache_path(home).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a missing/corrupt cache is just "unknown"
        return {}


def _write_cache(latest: str, home: Path | None = None) -> None:
    """Atomically replace the cache file (mkstemp + os.replace) so a crash or
    concurrent read never observes a half-written cache; mirrors
    ``auth/totp.py``'s ``_save_lockout``. Best-effort — never raises."""
    try:
        path = _cache_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = _now().isoformat().replace("+00:00", "Z")
        payload = json.dumps({"checked_at": stamp, "latest": latest})
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".update-check-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_name, path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except Exception:  # noqa: BLE001 — caching is best-effort; never break the CLI
        logger.debug("could not write update-check cache", exc_info=True)


#: Pre-release phases in PEP 440 order, lowest first, in the normalized spelling
#: PyPI and installed metadata use. A final release ranks above every phase, so
#: ``1.3.0`` beats ``1.3.0rc9`` and ``1.3.0rc1`` beats ``1.3.0b2``.
_PRE_RANK: dict[str, int] = {"dev": 0, "a": 1, "b": 2, "rc": 3}
_FINAL_RANK = len(_PRE_RANK)
#: Splits ``1.2.0rc1`` into the numeric release ``1.2.0`` and the rest ``rc1``.
_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)(.*)\Z", re.ASCII | re.DOTALL)
#: A whole pre-release suffix: optional separator, phase, optional separator,
#: optional number. Anchored, so a suffix of any other shape (``.post1``,
#: ``+local``, garbage) keeps ranking as a final release, exactly as before.
_PRE_RE = re.compile(r"^[._-]?(dev|a|b|rc)[._-]?(\d*)\Z", re.ASCII | re.IGNORECASE)


def _parse(version: object) -> tuple[int, ...]:
    """Leading numeric ``X.Y.Z`` parts as a tuple; ``()`` on anything unparseable.

    Only the release prefix — a suffix such as ``rc1`` or ``.dev3`` is dropped
    here and ordered by :func:`_key` instead. Never raises: any input that
    cannot be read as digits yields ``()``.
    """
    try:
        out: list[int] = []
        for part in str(version).split("."):
            digits = ""
            for ch in part:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if not digits:
                break
            out.append(int(digits))
        return tuple(out)
    except Exception:  # noqa: BLE001 — e.g. Unicode digits int() rejects; fail open
        return ()


def _key(version: object) -> tuple[tuple[int, ...], int, int]:
    """Ordering key ``(release, phase_rank, phase_number)`` for :func:`is_newer`.

    Suffix-aware without ``packaging``: a pre-release of version *N* sorts below
    the final *N* and above everything that precedes *N*, so an installed rc is
    nagged toward its final and a final is never nagged toward an rc.

    ponytail: understands only the normalized ``dev``/``a``/``b``/``rc`` family
    — no epochs, post-releases, or local ``+tags``; any other suffix ranks as a
    final release, as the whole string did before. Swap in ``packaging.version``
    if full PEP 440 ordering ever matters. Unparseable stays ``()``.
    """
    release = _parse(version)
    if not release:
        return ((), 0, 0)
    split = _RELEASE_RE.match(str(version))
    pre = _PRE_RE.match(split.group(2)) if split else None
    if pre is None:
        return (release, _FINAL_RANK, 0)
    phase, number = pre.groups()
    try:
        phase_number = int(number or 0)
    except (ValueError, OverflowError):
        return ((), 0, 0)
    return (release, _PRE_RANK[phase.lower()], phase_number)


def _is_unknown_version(version: object) -> bool:
    """True for a version we can't meaningfully compare: an all-zero parse (the
    ``0.0.0`` fallback) or one carrying an "unknown" marker (the local dev
    fallback ``0.0.0+unknown`` when package metadata is absent)."""
    if "unknown" in str(version).lower():
        return True
    parts = _parse(version)
    return not any(parts)


def is_newer(latest: object, current: object) -> bool:
    """True only if ``latest`` orders strictly above ``current`` (see :func:`_key`).

    Never nags when ``current`` is unknown (see :func:`_is_unknown_version`) —
    there's nothing to compare against. Never nags from a final release toward
    a pre-release of a *later* version either: ``1.3.0rc1`` is not "newer" than
    an installed ``1.2.0`` for the purposes of ``pip install -U``, which would
    not install it.
    """
    if _is_unknown_version(current):
        return False
    latest_key = _key(latest)
    current_key = _key(current)
    if not latest_key[0] or not current_key[0]:
        return False
    if latest_key[1] != _FINAL_RANK and current_key[1] == _FINAL_RANK:
        return False  # installed a final; the newer thing on PyPI is a pre-release
    return latest_key > current_key


def fetch_latest() -> str | None:
    """GET the latest version string from PyPI, or ``None`` on any failure."""
    try:
        with urllib.request.urlopen(  # noqa: S310 — constant https URL, not user input
            PYPI_JSON_URL, timeout=_TIMEOUT_S
        ) as resp:
            data = json.loads(resp.read(65536).decode("utf-8"))
        latest = data.get("info", {}).get("version")
        return latest if isinstance(latest, str) and latest else None
    except Exception:  # noqa: BLE001 — fail open: an unreachable PyPI is not an error
        logger.debug("PyPI update check failed", exc_info=True)
        return None


def _cache_fresh(cache: dict, now: datetime) -> bool:
    stamp = cache.get("checked_at")
    try:
        checked_at = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    return now - checked_at < DEFAULT_INTERVAL


def refresh(home: Path | None = None, *, force: bool = False) -> str | None:
    """Return the latest version, hitting PyPI only if due (or ``force``). Synchronous.

    Returns the cached value when the cache is still fresh, the fetched value when
    a fetch succeeds (and caches it), or the stale cached value if the fetch fails.
    Returns ``None`` when the check is disabled or nothing is known.
    """
    if disabled_reason():
        return None
    cache = _read_cache(home)
    if not force and _cache_fresh(cache, _now()):
        return cache.get("latest")
    latest = fetch_latest()
    if latest:
        _write_cache(latest, home)
        return latest
    return cache.get("latest")


_REFRESH_THREADS: list[threading.Thread] = []


def _join_refresh_threads(timeout: float = 1.0) -> None:
    """Join outstanding refresh threads within one shared wall-clock budget.

    Without this, a bare ``daemon=True`` thread can be killed by the
    interpreter mid DNS+TLS round trip and never write its cache. Mirrors
    ``telemetry._join_sender_threads``. Never raises — shutdown must never
    delay or break CLI exit.
    """
    try:
        deadline = time.monotonic() + timeout
        for thread in list(_REFRESH_THREADS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(remaining)
    except Exception:  # noqa: BLE001 — shutdown must never delay or break CLI exit
        return


atexit.register(_join_refresh_threads)


def refresh_async(home: Path | None = None) -> None:
    """Kick a background refresh in a daemon thread. Never blocks or raises.

    A no-op when disabled or when the cache is still fresh (so the common case
    starts no thread and touches no network)."""
    if disabled_reason():
        return
    if _cache_fresh(_read_cache(home), _now()):
        return
    thread = threading.Thread(target=lambda: refresh(home), daemon=True)
    _REFRESH_THREADS.append(thread)
    thread.start()


def pending_notice(home: Path | None = None) -> str | None:
    """A one-line upgrade notice if the cached latest beats the installed version.

    Reads only the cache — no network — so it is safe to call on any human CLI
    command. ``None`` when disabled, unknown, or already current.
    """
    if disabled_reason():
        return None
    latest = _read_cache(home).get("latest")
    if isinstance(latest, str) and is_newer(latest, __version__):
        return (
            f"A new Doberman is available: {latest} (you have {__version__}). "
            f"Upgrade with: {UPGRADE_HINT}"
        )
    return None
