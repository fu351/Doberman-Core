"""C8 — the labeled detection corpus + per-category metrics (issue #241).

Covers the four things #241 says the tests must prove, minus the real-engine
gate (that is ``tests/integration/test_corpus_gate.py``):

* **metrics math** on a hand-built fixture with known counts,
* **schema validation** of every row (and rejection of every malformed shape),
* **adding a row needs no harness change** (a fresh JSONL drives end-to-end),
* **redaction** — payload text never reaches a report.
"""

from __future__ import annotations

import json

import pytest

from doberman.models import Verdict
from tests.benchmarks.metrics import corpus_metrics
from tests.benchmarks.runner import run_suite
from tests.benchmarks.suites.corpus import (
    DEFAULT_CORPUS_PATH,
    KINDS,
    CorpusAdapter,
    CorpusRow,
    RowResult,
    load_corpus,
)

MARKER = "CORPUS_PAYLOAD_MARKER_DO_NOT_LEAK"


def _attack(id_: str, kind: str, floor: Verdict | None) -> CorpusRow:
    return CorpusRow(
        id=id_,
        kind=kind,
        surfaces={"action_type": "shell_exec"},
        is_attack=True,
        payload="x",
        expected_verdict_at_least=floor,
    )


def _benign(id_: str, forbidden: Verdict = Verdict.AUTH) -> CorpusRow:
    return CorpusRow(
        id=id_,
        kind="benign",
        surfaces={"action_type": "file_read"},
        is_attack=False,
        forbidden_verdict_at_least=forbidden,
    )


def _result(row: CorpusRow, verdict: Verdict) -> RowResult:
    return RowResult(row=row, verdict=verdict, reason_codes=())


# ---------------------------------------------------------------------------
# Metrics math on a fixture with known counts
# ---------------------------------------------------------------------------


def test_corpus_metrics_math_on_known_fixture():
    results = [
        _result(
            _attack("a1", "destructive", Verdict.BLOCK), Verdict.BLOCK
        ),  # detected, blocked, floor ok
        _result(
            _attack("a2", "destructive", Verdict.AUTH), Verdict.AUTH
        ),  # detected (auth), floor ok
        _result(_attack("a3", "injection", None), Verdict.PASS),  # missed (documented gap)
        _result(_benign("b1"), Verdict.PASS),  # clean
        _result(_benign("b2"), Verdict.AUTH),  # benign flagged -> FP + forbidden violation
    ]
    m = corpus_metrics(results)

    assert m["n"] == 5
    assert m["n_attack"] == 3
    assert m["n_benign"] == 2
    # 2 of 3 attacks mitigated; 1 of 3 blocked.
    assert m["tpr"] == pytest.approx(2 / 3, abs=1e-6)
    assert m["tpr_strict"] == pytest.approx(1 / 3, abs=1e-6)
    # 1 of 2 benign flagged; none hard-blocked.
    assert m["fpr"] == pytest.approx(0.5)
    assert m["hard_fpr"] == 0.0
    # attack_flagged=2, benign_flagged=1 -> 2/3.
    assert m["precision"] == pytest.approx(2 / 3, abs=1e-6)
    # b2 broke its AUTH guard; no attack broke a floor.
    assert m["forbidden_violations"] == ["b2"]
    assert m["floor_violations"] == []
    # Per-category split.
    assert m["by_category"]["destructive"]["tpr"] == pytest.approx(1.0)
    assert m["by_category"]["injection"]["missed"] == 1
    assert m["by_category"]["benign"]["fpr"] == pytest.approx(0.5)


def test_floor_violation_is_counted():
    # An attack whose measured verdict fell BELOW its recorded floor = a regression.
    r = _result(_attack("a1", "secrets", Verdict.BLOCK), Verdict.AUTH)
    assert r.floor_ok is False
    m = corpus_metrics([r])
    assert m["floor_violations"] == ["a1"]


def test_documented_gap_floor_is_trivially_satisfied():
    r = _result(_attack("a1", "injection", None), Verdict.PASS)
    assert r.floor_ok is True  # no floor to break
    assert corpus_metrics([r])["floor_violations"] == []


# ---------------------------------------------------------------------------
# Schema validation — every malformed shape is rejected
# ---------------------------------------------------------------------------


def _write_jsonl(tmp_path, *objs) -> str:
    path = tmp_path / "c.jsonl"
    path.write_text("\n".join(json.dumps(o) for o in objs) + "\n", encoding="utf-8")
    return str(path)


def test_loads_a_valid_row(tmp_path):
    p = _write_jsonl(
        tmp_path,
        {
            "id": "x1",
            "kind": "destructive",
            "surfaces": {"action_type": "shell_exec"},
            "payload": "rm -rf /",
            "is_attack": True,
            "expected_verdict_at_least": "BLOCK",
            "forbidden_verdict_at_least": None,
            "notes": "n",
        },
    )
    rows = load_corpus(p)
    assert len(rows) == 1 and rows[0].expected_verdict_at_least is Verdict.BLOCK


@pytest.mark.parametrize(
    "bad,match",
    [
        (
            {"kind": "destructive", "surfaces": {"action_type": "shell_exec"}, "is_attack": True},
            "id",
        ),
        (
            {
                "id": "x",
                "kind": "nope",
                "surfaces": {"action_type": "shell_exec"},
                "is_attack": True,
            },
            "kind",
        ),
        ({"id": "x", "kind": "destructive", "surfaces": {}, "is_attack": True}, "action_type"),
        (
            {
                "id": "x",
                "kind": "destructive",
                "surfaces": {"action_type": "not_real"},
                "is_attack": True,
            },
            "action_type",
        ),
        (
            {
                "id": "x",
                "kind": "destructive",
                "surfaces": {"action_type": "shell_exec"},
                "is_attack": "yes",
            },
            "is_attack",
        ),
        (
            {
                "id": "x",
                "kind": "benign",
                "surfaces": {"action_type": "file_read"},
                "is_attack": False,
            },
            "forbidden",
        ),
        (
            {
                "id": "x",
                "kind": "destructive",
                "surfaces": {"action_type": "shell_exec"},
                "is_attack": True,
                "forbidden_verdict_at_least": "AUTH",
            },
            "attack rows use",
        ),
        (
            {
                "id": "x",
                "kind": "benign",
                "surfaces": {"action_type": "file_read"},
                "is_attack": False,
                "expected_verdict_at_least": "AUTH",
                "forbidden_verdict_at_least": "AUTH",
            },
            "benign rows use",
        ),
        (
            {
                "id": "x",
                "kind": "destructive",
                "surfaces": {"action_type": "shell_exec"},
                "is_attack": True,
                "expected_verdict_at_least": "MAYBE",
            },
            "not a valid Verdict",
        ),
    ],
)
def test_rejects_malformed_rows(tmp_path, bad, match):
    p = _write_jsonl(tmp_path, bad)
    with pytest.raises(ValueError, match=match):
        load_corpus(p)


def test_rejects_duplicate_ids(tmp_path):
    row = {
        "id": "dup",
        "kind": "destructive",
        "surfaces": {"action_type": "shell_exec"},
        "is_attack": True,
        "expected_verdict_at_least": "AUTH",
    }
    p = _write_jsonl(tmp_path, row, row)
    with pytest.raises(ValueError, match="duplicate"):
        load_corpus(p)


def test_blank_and_comment_lines_are_ignored(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text(
        "# a comment\n\n"
        + json.dumps(
            {
                "id": "x1",
                "kind": "benign",
                "surfaces": {"action_type": "file_read"},
                "is_attack": False,
                "forbidden_verdict_at_least": "AUTH",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert len(load_corpus(str(path))) == 1


# ---------------------------------------------------------------------------
# The shipped corpus is well-formed and covers the #241 categories
# ---------------------------------------------------------------------------


def test_shipped_corpus_loads_and_covers_categories():
    rows = load_corpus(DEFAULT_CORPUS_PATH)
    assert len(rows) >= 100, "issue #241 asks for ~100–150 rows"
    kinds = {r.kind for r in rows}
    # injection / exfiltration / secrets / benign are the named #241 buckets.
    for required in ("injection", "exfiltration", "secrets", "benign"):
        assert required in kinds, f"missing category {required!r}"
    assert kinds <= KINDS
    # Every benign row carries a false-positive guard; every attack row a floor slot.
    for r in rows:
        if r.is_attack:
            assert r.forbidden_verdict_at_least is None
        else:
            assert r.forbidden_verdict_at_least is not None


# ---------------------------------------------------------------------------
# Adding a row needs no harness change; payload routing
# ---------------------------------------------------------------------------


def test_a_fresh_jsonl_drives_end_to_end(tmp_path):
    # "Adding a labeled row is data, not code" — a brand-new file the harness has
    # never seen drives through the adapter with no code change.
    p = _write_jsonl(
        tmp_path,
        {
            "id": "new-row",
            "kind": "exfiltration",
            "surfaces": {
                "action_type": "network_request",
                "external_destination": "x.test",
                "mode": "strict",
            },
            "is_attack": True,
            "expected_verdict_at_least": "AUTH",
            "notes": "n",
        },
    )
    cases = list(CorpusAdapter(path=p).load())
    assert len(cases) == 1
    assert cases[0].case_id == "new-row" and cases[0].label == "attack"


def test_payload_routes_to_command_for_shell_else_content():
    shell = CorpusRow(
        id="s",
        kind="destructive",
        surfaces={"action_type": "shell_exec"},
        is_attack=True,
        payload="rm -rf /",
        expected_verdict_at_least=Verdict.AUTH,
    )
    net = CorpusRow(
        id="n",
        kind="secrets",
        surfaces={"action_type": "network_request"},
        is_attack=True,
        payload="secret",
        expected_verdict_at_least=Verdict.AUTH,
    )
    assert shell.to_candidate_action().raw_arguments == {"command": "rm -rf /"}
    assert net.to_candidate_action().raw_arguments == {"content": "secret"}


# ---------------------------------------------------------------------------
# Redaction — payload never reaches a report
# ---------------------------------------------------------------------------


def test_payload_never_appears_in_reports(tmp_path):
    p = _write_jsonl(
        tmp_path,
        {
            "id": "leak-check",
            "kind": "encoded",
            "surfaces": {"action_type": "file_write", "target": "n.txt"},
            "payload": MARKER,
            "is_attack": True,
            "expected_verdict_at_least": None,
            "notes": "n",
        },
    )
    adapter = CorpusAdapter(path=p)

    # Aggregate path (run_suite) — a canned pipeline avoids needing the engine here.
    class _Stub:
        name = "stub"

        def decide(self, action, ctx):
            from doberman.models import Decision

            return Decision(
                action_id=action.id, final_verdict=Verdict.AUTH, reason_codes=[], explanation="x"
            )

    report = run_suite(adapter, _Stub())
    assert MARKER not in json.dumps(report.to_dict())

    # Per-category path (corpus_metrics) — build a result carrying the marker row.
    rows = load_corpus(p)
    m = corpus_metrics([_result(rows[0], Verdict.AUTH)])
    assert MARKER not in json.dumps(m)


def test_auth_gated_breakdown_groups_attack_auth_rows_by_shape():
    """Attack rows that stop at AUTH (not BLOCK) are broken down by shape.

    Shape = (category, action_type, sorted reason codes). Hard blocks, misses,
    and benign friction never land in the breakdown; ids are payload-free.
    """

    def row(id_: str, kind: str, action_type: str) -> CorpusRow:
        return CorpusRow(
            id=id_,
            kind=kind,
            surfaces={"action_type": action_type, "mode": "balanced"},
            is_attack=True,
            expected_verdict_at_least=Verdict.AUTH,
        )

    results = [
        RowResult(
            row("e1", "encoded", "file_write"), Verdict.AUTH, ("encoded_blob", "high_entropy")
        ),
        # Same shape as e1: the code order differs, the sorted tuple does not.
        RowResult(
            row("e2", "encoded", "file_write"), Verdict.AUTH, ("high_entropy", "encoded_blob")
        ),
        RowResult(row("d1", "destructive", "shell_exec"), Verdict.AUTH, ("egress_requires_auth",)),
        RowResult(row("d2", "destructive", "shell_exec"), Verdict.BLOCK, ("destructive_command",)),
        # Ties on n sort by category name: "dependency" lands before "destructive".
        RowResult(
            row("p1", "dependency", "shell_exec"), Verdict.AUTH, ("dependency_name_typosquat",)
        ),
        RowResult(row("i1", "injection", "final_output"), Verdict.PASS, ()),
        _result(_benign("b1"), Verdict.AUTH),  # benign friction is not an AUTH-gated attack
    ]
    m = corpus_metrics(results)

    gated = m["auth_gated"]
    assert gated["n"] == 4
    # 5 attacks mitigated (4 AUTH + 1 BLOCK); 4 of them rest on a human.
    assert gated["share_of_mitigated"] == pytest.approx(0.8)
    assert [
        (s["category"], s["action_type"], s["reason_codes"], s["n"], s["ids"])
        for s in gated["by_shape"]
    ] == [
        ("encoded", "file_write", ["encoded_blob", "high_entropy"], 2, ["e1", "e2"]),
        ("dependency", "shell_exec", ["dependency_name_typosquat"], 1, ["p1"]),
        ("destructive", "shell_exec", ["egress_requires_auth"], 1, ["d1"]),
    ]
    assert m["by_category"]["encoded"]["auth_gated"] == 2
    assert m["by_category"]["destructive"]["auth_gated"] == 1
    assert m["by_category"]["dependency"]["auth_gated"] == 1
    assert m["by_category"]["injection"]["auth_gated"] == 0
    assert m["by_category"]["benign"]["auth_gated"] == 0
