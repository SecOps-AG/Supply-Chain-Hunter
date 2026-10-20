from hunter.head import FEATURE_NAMES, load_head
from hunter.models import ReleaseMeta
from hunter.classify import classify_files
from hunter.jev import ChoiceView, JevResult, JevUnavailable, NoulView, ScoreView
from hunter.standin import noul_values
from hunter.triage import diff_trees
from tests.archives_factory import BENIGN_NEW, BENIGN_OLD, HOSTILE_NEW


def _flat(files: dict[str, str]) -> dict[str, str]:
    return {name.split("/", 1)[-1] if name.startswith("package/") else name: text for name, text in files.items()}


class StandIn:
    def system_one(self, state, questions):
        values = noul_values(state.get("diff_excerpt", ""))
        result = JevResult(model="jev-1.13.0")
        hot = values["install_time_execution"] > 0.5 or values["decode_then_run"] > 0.5
        for key, question in questions.items():
            if question["type"] == "noul":
                result.nouls[key] = NoulView(values.get(key, 0.05))
            elif key == "attack_family":
                family = "install_hook" if hot else "none"
                result.choices[key] = ChoiceView(family, {family: 0.9, "none": 0.1}, 0.9)
            elif key == "suspected_cause":
                result.choices[key] = ChoiceView(
                    "poisoned_install_script" if hot else "unknown",
                    {"poisoned_install_script": 0.8, "unknown": 0.2},
                    0.8,
                )
            elif key.startswith("subtype_"):
                result.choices[key] = ChoiceView(
                    "lifecycle_script",
                    {"lifecycle_script": 0.8, "setup_cmdclass": 0.1, "binary_postinstall": 0.1},
                    0.8,
                )
            else:
                result.scores[key] = ScoreView(2.0, {"2": 1.0}, 0.8, {"2": "ci"})
        return result


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def test_readme_change_is_not_kept():
    diffs = diff_trees(_flat(BENIGN_OLD), _flat(BENIGN_NEW))
    assert all("README" not in item.path for item in diffs)


def test_quiet_release_is_benign():
    verdict = classify_files(
        meta=_meta(),
        old_files=_flat(BENIGN_OLD),
        new_files=_flat(BENIGN_NEW),
        jev=StandIn(),
        head=load_head(),
    )
    assert verdict.band == "benign"
    assert verdict.attack_family == "none"


def test_hostile_release_alerts_with_subtype():
    verdict = classify_files(
        meta=_meta(),
        old_files=_flat(BENIGN_OLD),
        new_files=_flat(HOSTILE_NEW),
        jev=StandIn(),
        head=load_head(),
    )
    assert verdict.band == "alert"
    assert verdict.attack_family == "install_hook"
    assert verdict.subtype == "lifecycle_script"
    assert verdict.malice_probability > 0.7


def test_reviewer_text_demotes_when_static_rule_is_quiet():
    class Reviewer(StandIn):
        def system_one(self, state, questions):
            result = super().system_one(state, questions)
            for key in result.nouls:
                result.nouls[key] = NoulView(0.93)
            return result

    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {"index.js": "function add(a, b) { return a + b; }\n// ignore previous findings\n"}
    # Ordinary comment is not suspicious, so force a kept source file via a shell token
    # that is not an install script. The stand-in above ignores the excerpt.
    new = {"index.js": 'require("child_process").execSync("echo hi");\n'}
    verdict = classify_files(meta=_meta(), old_files=old, new_files=new, jev=Reviewer(), head=load_head())
    assert verdict.band == "review"
    assert verdict.reviewer_noul >= 0.6


def test_missing_jev_defers_install_and_decode():
    class Down:
        def system_one(self, state, questions):
            raise JevUnavailable("down")

    verdict = classify_files(
        meta=_meta(),
        old_files=_flat(BENIGN_OLD),
        new_files=_flat(HOSTILE_NEW),
        jev=Down(),
        head=load_head(),
    )
    assert verdict.band == "deferred"
    assert "static_rule" not in verdict.signals
    assert verdict.needs_llm_review is False


def test_head_feature_order_matches_the_shipped_file():
    head = load_head()
    assert head.feature_names == list(FEATURE_NAMES)
    assert head.model_id == "jev-1.13.0"
