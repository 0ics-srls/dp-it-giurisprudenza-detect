"""Proc-protocol v1.1 detect for the case-law Sources (Corte costituzionale dumps, Cassazione partitions, CGT month windows): no network."""
from __future__ import annotations

import io
import json
from collections.abc import Callable

import pytest
from jsonschema import Draft202012Validator

from conftest import Run, invoke_raw

Invoke = Callable[..., Run]


def keys(run: Run) -> list[str]:
    return [item["key"] for item in run.result["items"]]


def test_spec_declares_protocol_11_with_valid_schemas(invoke: Invoke) -> None:
    run = invoke("spec")

    assert run.result["protocol"] == "1.1"
    for name in ("configSchema", "outputSchema"):
        Draft202012Validator.check_schema(run.result[name])
    properties = run.result["configSchema"]["properties"]
    assert {"kind", "bundles", "anni", "only", "anno", "mese", "from", "to", "refreshToken", "state"} <= set(properties)


def test_cc_one_item_per_bundle_with_deterministic_keys(invoke: Invoke) -> None:
    run = invoke("run", bundles=["pronunce_2001_oggi", "norme_ordinanze"], state=None)

    assert keys(run) == ["cc:pronunce_2001_oggi|v1", "cc:norme_ordinanze|v1"]
    first = run.result["items"][0]
    assert first["meta"] == {"kind": "cc", "itemId": "cc:pronunce_2001_oggi", "version": "1", "bundle": "pronunce_2001_oggi"}
    assert first["url"] == "https://dati.cortecostituzionale.it/opendata/distribuzione/CC_OpenPronunce_2001_oggi.zip"
    assert run.result["items"][1]["url"].endswith("/Norme_impugnate/Cc_Opendata_NormeImpugnate_RegistroOrdinanze_json.zip")
    assert run.result["metrics"] == {"items": 2, "newItems": 2}
    assert run.result["checks"][0]["passed"] is True


def test_cc_duplicate_bundles_are_emitted_once(invoke: Invoke) -> None:
    run = invoke("run", bundles=["massime_2001_oggi", "massime_2001_oggi"])

    assert keys(run) == ["cc:massime_2001_oggi|v1"]


def test_cassazione_without_month_emits_the_twelve_months_and_the_residual(invoke: Invoke) -> None:
    run = invoke("run", kind="snciv", anno=2025)

    assert keys(run) == [f"cass:snciv:2025:{month:02d}|v1" for month in range(1, 14)]
    third = run.result["items"][2]
    assert third["meta"] == {"kind": "cassazione", "itemId": "cass:snciv:2025:03", "version": "1", "cassKind": "snciv", "anno": 2025, "mese": 3}
    assert run.result["items"][12]["meta"]["mese"] == 13  # the residual partition


def test_cassazione_one_month_and_both_kinds(invoke: Invoke) -> None:
    assert keys(invoke("run", kind="snpen", anno=2024, mese=13)) == ["cass:snpen:2024:13|v1"]
    both = invoke("run", kind="cassazione", kindCass="both", anno=2023, mese=1)
    assert keys(both) == ["cass:snciv:2023:01|v1", "cass:snpen:2023:01|v1"]


def test_cgt_one_item_per_calendar_month_window_clipped(invoke: Invoke) -> None:
    one = invoke("run", **{"from": "2024-12-01", "to": "2024-12-31"})
    assert keys(one) == ["cgt:2024-12-01:2024-12-31|v1"]
    assert one.result["items"][0]["meta"] == {
        "kind": "cgt", "itemId": "cgt:2024-12-01:2024-12-31", "version": "1", "from": "2024-12-01", "to": "2024-12-31",
    }

    three = invoke("run", **{"from": "2024-11-15", "to": "2025-01-10"})
    assert keys(three) == ["cgt:2024-11-15:2024-11-30|v1", "cgt:2024-12-01:2024-12-31|v1", "cgt:2025-01-01:2025-01-10|v1"]


def test_cgt_leap_february_and_single_day(invoke: Invoke) -> None:
    assert keys(invoke("run", **{"from": "2024-02-10", "to": "2024-03-01"})) == ["cgt:2024-02-10:2024-02-29|v1", "cgt:2024-03-01:2024-03-01|v1"]


def test_state_skips_a_known_key(invoke: Invoke) -> None:
    state = {"seen": ["cc:pronunce_2001_oggi|v1"]}

    run = invoke("run", bundles=["pronunce_2001_oggi", "massime_2001_oggi"], state=state)

    assert keys(run) == ["cc:massime_2001_oggi|v1"]
    assert run.result["state"]["seen"] == ["cc:pronunce_2001_oggi|v1", "cc:massime_2001_oggi|v1"]
    assert run.result["metrics"] == {"items": 2, "newItems": 1}


def test_refresh_token_re_emits_with_a_new_version(invoke: Invoke) -> None:
    seen = {"seen": ["cc:massime_2001_oggi|v1"]}

    run = invoke("run", bundles=["massime_2001_oggi"], state=seen, refreshToken="2026-11-12")

    version = run.result["items"][0]["meta"]["version"]
    assert version.startswith("1-")
    assert len(version) == 10
    assert keys(run) == [f"cc:massime_2001_oggi|v{version}"]
    assert "refresh" in run.result["items"][0]["url"]
    assert invoke("run", bundles=["massime_2001_oggi"], refreshToken="2026-11-12").result["items"][0]["meta"]["version"] == version  # deterministic


def test_execute_is_an_alias_of_run(invoke: Invoke) -> None:
    assert keys(invoke("execute", bundles=["massime_2001_oggi"])) == ["cc:massime_2001_oggi|v1"]


def test_check_validates_without_items(invoke: Invoke) -> None:
    run = invoke("check", bundles=["massime_2001_oggi"])

    assert run.result == {"ok": True}
    assert invoke("check", **{"from": "2024-12-02", "to": "2024-12-01"}).error["code"] == "config_error"


@pytest.mark.parametrize(
    "params",
    [
        {"bundles": ["nonexistent_dump"]},
        {"bundles": []},
        {"bundles": "pronunce_2001_oggi"},
        {"bundles": ["massime_2001_oggi"], "anni": ["2026"]},
        {"bundles": ["massime_2001_oggi"], "only": [{"anno": 2026}]},
        {"kind": "snciv", "anno": 2020},
        {"kind": "snciv", "anno": "2025"},
        {"kind": "snciv", "anno": 2025, "mese": 0},
        {"kind": "snciv", "anno": 2025, "mese": 14},
        {"kind": "snxyz", "anno": 2025},
        {"from": "2024-12-02", "to": "2024-12-01"},
        {"from": "2024-12-01"},
        {"from": "2024/12/01", "to": "2024-12-31"},
        {"from": "2024-02-30", "to": "2024-03-31"},
        {"from": "2020-01-01", "to": "2060-01-01"},
        {"bundles": ["massime_2001_oggi"], "anno": 2025, "kind": "snciv"},
        {"bundles": ["massime_2001_oggi"], "from": "2024-01-01", "to": "2024-02-01"},
        {},
    ],
)
def test_invalid_config_is_a_config_error(invoke: Invoke, params: dict[str, object]) -> None:
    run = invoke("run", **params)

    assert run.returncode == 1
    assert run.error["code"] == "config_error"


def test_explicit_kind_wins_over_shape(invoke: Invoke) -> None:
    run = invoke("run", kind="cc", bundles=["massime_2001_oggi"], anno=2025)

    assert keys(run) == ["cc:massime_2001_oggi|v1"]


def test_invalid_state_and_refresh_token_are_config_errors(invoke: Invoke) -> None:
    assert invoke("run", bundles=["massime_2001_oggi"], state={"seen": [1]}).error["code"] == "config_error"
    assert invoke("run", bundles=["massime_2001_oggi"], refreshToken=5).error["code"] == "config_error"


def test_protocol_loop_emits_one_error_line_for_a_bad_request() -> None:
    run = invoke_raw("not json\n")

    assert run.returncode == 1
    assert [line["type"] for line in run.lines] == ["error"]
    assert run.lines[0]["code"] == "config_error"


def test_protocol_loop_unknown_action_and_terminate() -> None:
    run = invoke_raw(json.dumps({"_action": "frobnicate", "_meta": {"executionId": "e"}}) + "\n" + json.dumps({"_action": "terminate", "_meta": {"executionId": "e"}}) + "\n")

    assert [line["type"] for line in run.lines] == ["error", "result"]
    assert run.lines[0]["code"] == "config_error"


def test_config_keys_the_host_resolves_to_null_count_as_absent(invoke: Invoke) -> None:
    # The Manifest passes every Source config key of the pipeline; the Host resolves the ones a Source type does not declare to null.
    nulls = {"kind": None, "bundles": None, "anni": None, "only": None, "anno": None, "mese": None, "from": None, "to": None, "refreshToken": None}

    cc = invoke("run", **{**nulls, "bundles": ["massime_2001_oggi"], "state": None})
    cass = invoke("run", **{**nulls, "kind": "snciv", "anno": 2025, "mese": 3})
    cgt = invoke("run", **{**nulls, "from": "2024-12-01", "to": "2024-12-31"})

    assert keys(cc) == ["cc:massime_2001_oggi|v1"]
    assert keys(cass) == ["cass:snciv:2025:03|v1"]
    assert keys(cgt) == ["cgt:2024-12-01:2024-12-31|v1"]
    assert invoke("run", **nulls).error["code"] == "config_error"  # nothing at all is still an error


def test_stdout_carries_protocol_events_only(invoke: Invoke) -> None:
    run = invoke("run", bundles=["massime_2001_oggi"])

    assert all(line.get("type") in {"progress", "result", "error"} for line in run.lines)
    assert io.StringIO(run.stdout).read().count("\n") == len(run.lines)
