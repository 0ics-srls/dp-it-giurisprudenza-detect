"""Detect of the case-law Sources: validates the config, emits catalog items, never uses the network.

One pipeline serves three Source types (P79-03/04); the kind of an item is its ``meta.kind``:

* ``cc``: one item per selected Corte costituzionale dump (``cc:pronunce_2001_oggi``);
* ``cassazione``: one item per partition ``(kind, anno, mese)`` (``cass:snciv:2025:03``; month 13 is the residual partition);
* ``cgt``: one item per calendar-month window between ``from`` and ``to`` (``cgt:2024-12-01:2024-12-31``).

Item key = ``<itemId>|v<version>``. The version is ``1``; a non-blank ``refreshToken`` makes it ``1-<hash8>`` so changing the token re-emits every
item. The existence of a dump, partition or window is checked by grab.
"""
from __future__ import annotations

import calendar
import hashlib
import re
from datetime import date
from typing import Any, TypeGuard
from urllib.parse import urlencode

from v11 import ProcErrorCode

CORPORA = ("cc", "cassazione", "cgt")
CASS_KINDS = ("snciv", "snpen")
MIN_CASS_YEAR, MAX_YEAR = 2021, 2100
MIN_CGT_DATE, MAX_CGT_DATE = date(2022, 1, 1), date(2100, 12, 31)
MAX_CGT_WINDOWS = 600
SEEN_LIMIT = 2000
BASE_VERSION = "1"
DATE_PATTERN = "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
RESIDUAL_MONTH = 13

CC_BASE = "https://dati.cortecostituzionale.it/opendata"
CC_DUMPS: dict[str, str] = {
    "pronunce_1956_1980": f"{CC_BASE}/distribuzione/CC_OpenPronunce_1956_1980.zip",
    "pronunce_1981_2000": f"{CC_BASE}/distribuzione/CC_OpenPronunce_1981_2000.zip",
    "pronunce_2001_oggi": f"{CC_BASE}/distribuzione/CC_OpenPronunce_2001_oggi.zip",
    "massime_1956_1980": f"{CC_BASE}/distribuzione/CC_OpenMassime_1956_1980.zip",
    "massime_1981_2000": f"{CC_BASE}/distribuzione/CC_OpenMassime_1981_2000.zip",
    "massime_2001_oggi": f"{CC_BASE}/distribuzione/CC_OpenMassime_2001_oggi.zip",
    "norme_ordinanze": f"{CC_BASE}/Norme_impugnate/Cc_Opendata_NormeImpugnate_RegistroOrdinanze_json.zip",
    "norme_ricorsi": f"{CC_BASE}/Norme_impugnate/Cc_Opendata_NormeImpugnate_RegistroRicorsi_json.zip",
    "norme_conflitti_enti": f"{CC_BASE}/Norme_impugnate/Cc_Opendata_NormeImpugnate_RegistroConflittiEnti_json.zip",
    "norme_conflitti_poteri": f"{CC_BASE}/Norme_impugnate/Cc_Opendata_NormeImpugnate_RegistroConflittiPoteri_json.zip",
}
CASS_URL = "https://www.italgiure.giustizia.it/sncass/"
CGT_URL = "https://def.finanze.it/DocTribFrontend/executeAdvancedGiurisprudenzaSearch.do"

_DATE = re.compile(DATE_PATTERN)


class DetectError(Exception):
    """A protocol error: ``code`` is one of the three v1.1 codes."""

    def __init__(self, code: ProcErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def _config_error(message: str) -> DetectError:
    return DetectError(ProcErrorCode.CONFIG_ERROR, message)


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _shapes(params: dict[str, Any]) -> set[str]:
    shapes: set[str] = set()
    if "bundles" in params:
        shapes.add("cc")
    if "anno" in params or params.get("kind") in CASS_KINDS or "kindCass" in params:
        shapes.add("cassazione")
    if "from" in params or "to" in params:
        shapes.add("cgt")
    return shapes


def resolve_corpus(params: dict[str, Any]) -> str:
    """The explicit kind (``cc``, ``cassazione``, ``cgt``), else inferred from the shape of the config (the Host has no Source-type template to pass it)."""
    kind = params.get("kind")
    if kind in CORPORA:
        return str(kind)
    if kind is not None and kind not in (*CASS_KINDS, "both"):
        msg = f"kind must be one of {[*CORPORA, *CASS_KINDS]}, got {kind!r}"
        raise _config_error(msg)
    shapes = _shapes(params)
    if len(shapes) != 1:
        msg = "the corpus cannot be inferred: give bundles (cc), kind + anno (cassazione) or from + to (cgt), one shape only"
        raise _config_error(msg)
    return shapes.pop()


def validate_refresh_token(token: Any) -> str | None:
    if token is None or token == "":
        return None
    if not isinstance(token, str):
        raise _config_error("refreshToken must be a string")
    return token


def validate_state(state: Any) -> dict[str, Any] | None:
    if state is None:
        return None
    seen = state.get("seen") if isinstance(state, dict) else None
    if not isinstance(state, dict) or (seen is not None and not (isinstance(seen, list) and all(isinstance(s, str) for s in seen))):
        raise _config_error("state must be an object {seen: [string]}")
    return state


def version_of(refresh_token: str | None) -> str:
    if not refresh_token:
        return BASE_VERSION
    return f"{BASE_VERSION}-{hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()[:8]}"


def _with_refresh(url: str, version: str, refresh_token: str | None) -> str:
    if not refresh_token:
        return url
    return url + ("&" if "?" in url or "#" in url else "?") + urlencode({"refresh": version})


def _cc_items(params: dict[str, Any], version: str, token: str | None) -> list[dict[str, Any]]:
    bundles = params.get("bundles")
    if not isinstance(bundles, list) or not bundles:
        raise _config_error("bundles must be a non-empty array")
    unknown = [b for b in bundles if b not in CC_DUMPS]
    if unknown:
        raise _config_error(f"unknown bundles {unknown!r}; expected a subset of {sorted(CC_DUMPS)}")
    anni = params.get("anni")
    if anni is not None and not (isinstance(anni, list) and all(_is_int(y) for y in anni)):
        raise _config_error("anni must be an array of integers")
    only = params.get("only")
    if only is not None and not (
        isinstance(only, list) and all(isinstance(o, dict) and _is_int(o.get("anno")) and _is_int(o.get("numero")) for o in only)
    ):
        raise _config_error("only must be an array of {anno, numero} integers")
    items = []
    for bundle in dict.fromkeys(bundles):
        item_id = f"cc:{bundle}"
        items.append({
            "key": f"{item_id}|v{version}",
            "url": _with_refresh(CC_DUMPS[bundle], version, token),
            "meta": {"kind": "cc", "itemId": item_id, "version": version, "bundle": bundle},
        })
    return items


def _cass_kinds(params: dict[str, Any]) -> list[str]:
    raw = params.get("kindCass") or (params.get("kind") if params.get("kind") not in CORPORA else None)
    if raw == "both":
        return list(CASS_KINDS)
    if raw not in CASS_KINDS:
        raise _config_error(f"kind must be one of {[*CASS_KINDS, 'both']}, got {raw!r}")
    return [str(raw)]


def _cassazione_items(params: dict[str, Any], version: str, token: str | None) -> list[dict[str, Any]]:
    kinds = _cass_kinds(params)
    anno = params.get("anno")
    if not _is_int(anno) or not MIN_CASS_YEAR <= anno <= MAX_YEAR:
        raise _config_error(f"anno must be an integer {MIN_CASS_YEAR}..{MAX_YEAR} (full text exists from {MIN_CASS_YEAR})")
    mese = params.get("mese")
    if mese is not None and (not _is_int(mese) or not 1 <= mese <= RESIDUAL_MONTH):
        raise _config_error(f"mese must be an integer 1..{RESIDUAL_MONTH} (13 = residual partition)")
    months = [mese] if mese is not None else list(range(1, RESIDUAL_MONTH + 1))
    items = []
    for kind in kinds:
        for month in months:
            item_id = f"cass:{kind}:{anno}:{month:02d}"
            items.append({
                "key": f"{item_id}|v{version}",
                "url": _with_refresh(f"{CASS_URL}#/ricerca?kind={kind}&anno={anno}&mese={month}", version, token),
                "meta": {"kind": "cassazione", "itemId": item_id, "version": version, "cassKind": kind, "anno": anno, "mese": month},
            })
    return items


def _parse_date(value: Any, name: str) -> date:
    if not isinstance(value, str) or not _DATE.match(value):
        raise _config_error(f"{name} must be a date YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise _config_error(f"{name} must be a real calendar date, got {value!r}") from None


def month_windows(start: date, end: date) -> list[tuple[date, date]]:
    """Calendar-month windows between two dates, clipped to them."""
    windows = []
    year, month = start.year, start.month
    while (year, month) <= (end.year, end.month):
        first = max(start, date(year, month, 1))
        last = min(end, date(year, month, calendar.monthrange(year, month)[1]))
        windows.append((first, last))
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)  # noqa: PLR2004
    return windows


def _cgt_items(params: dict[str, Any], version: str, token: str | None) -> list[dict[str, Any]]:
    if "from" not in params or "to" not in params:
        raise _config_error("from and to are both required")
    start, end = _parse_date(params["from"], "from"), _parse_date(params["to"], "to")
    if end < start:
        raise _config_error("to must not be before from")
    if start < MIN_CGT_DATE or end > MAX_CGT_DATE:
        raise _config_error(f"the window must lie within {MIN_CGT_DATE}..{MAX_CGT_DATE} (the Corti di giustizia tributaria exist from 2022)")
    windows = month_windows(start, end)
    if len(windows) > MAX_CGT_WINDOWS:
        raise _config_error(f"at most {MAX_CGT_WINDOWS} month windows per Source, got {len(windows)}")
    items = []
    for first, last in windows:
        item_id = f"cgt:{first.isoformat()}:{last.isoformat()}"
        items.append({
            "key": f"{item_id}|v{version}",
            "url": _with_refresh(f"{CGT_URL}?{urlencode({'from': first.isoformat(), 'to': last.isoformat()})}", version, token),
            "meta": {"kind": "cgt", "itemId": item_id, "version": version, "from": first.isoformat(), "to": last.isoformat()},
        })
    return items


def build_found(params: dict[str, Any], refresh_token: str | None) -> list[dict[str, Any]]:
    """Every item of the Source config, in config order (validates the whole config)."""
    corpus = resolve_corpus(params)
    version = version_of(refresh_token)
    if corpus == "cc":
        return _cc_items(params, version, refresh_token)
    if corpus == "cassazione":
        return _cassazione_items(params, version, refresh_token)
    return _cgt_items(params, version, refresh_token)


def build_run_result(found: list[dict[str, Any]], state_in: dict[str, Any] | None) -> dict[str, Any]:
    """Items = those whose key is not in state.seen; state keeps the newest SEEN_LIMIT keys."""
    seen = list((state_in or {}).get("seen") or [])
    known = set(seen)
    new = [item for item in found if item["key"] not in known]
    seen_out = (seen + [item["key"] for item in new])[-SEEN_LIMIT:]
    return {
        "items": new,
        "state": {"seen": seen_out},
        "metrics": {"items": len(found), "newItems": len(new)},
        "checks": [{"name": "items_found", "passed": len(found) > 0, "severity": "error"}],
    }


CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "kind": {"enum": [*CORPORA, *CASS_KINDS, "both"], "description": "corpus or Cassazione kind; inferred from the shape"},
        "bundles": {"type": "array", "minItems": 1, "items": {"enum": sorted(CC_DUMPS)}, "uniqueItems": True},
        "anni": {"type": "array", "items": {"type": "integer"}},
        "only": {"type": "array", "items": {"type": "object", "required": ["anno", "numero"],
                                            "properties": {"anno": {"type": "integer"}, "numero": {"type": "integer"}}}},
        "anno": {"type": "integer", "minimum": MIN_CASS_YEAR, "maximum": MAX_YEAR},
        "mese": {"type": "integer", "minimum": 1, "maximum": RESIDUAL_MONTH},
        "kindCass": {"enum": [*CASS_KINDS, "both"]},
        "from": {"type": "string", "pattern": DATE_PATTERN},
        "to": {"type": "string", "pattern": DATE_PATTERN},
        "refreshToken": {"type": ["string", "null"], "description": "change it to fetch every item again"},
        "state": {"type": ["object", "null"], "properties": {"seen": {"type": "array", "items": {"type": "string"}}}},
    },
    "additionalProperties": True,
}

OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["items", "state", "metrics", "checks"],
    "properties": {
        "items": {"type": "array", "items": {"type": "object", "required": ["key", "url", "meta"], "properties": {
            "key": {"type": "string", "minLength": 1}, "url": {"type": "string", "minLength": 1},
            "meta": {"type": "object", "required": ["kind", "itemId", "version"], "properties": {
                "kind": {"enum": list(CORPORA)}, "itemId": {"type": "string"}, "version": {"type": "string"}}}}}},
        "state": {"type": "object", "required": ["seen"], "properties": {"seen": {"type": "array", "items": {"type": "string"}}}},
        "metrics": {"type": "object", "properties": {"items": {"type": "integer"}, "newItems": {"type": "integer"}}},
        "checks": {"type": "array"},
    },
}
