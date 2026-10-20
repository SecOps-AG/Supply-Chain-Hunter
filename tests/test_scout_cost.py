"""Scout cost on large releases: the changed-file list is sent once, and a release cap."""

from hunter.classify import classify_files, riskiest_first
from hunter.head import load_head
from hunter.jev import CHANGED_FILES_SENT_NOTE, STATE_TOKEN_BUDGET, pack_chunks, slice_state
from hunter.jev_tokens import state_tokens
from hunter.models import FileDiff, ReleaseMeta
from hunter.questions import PASS_B_IDS
from hunter.triage import changed_file_manifest, diff_trees
from hunter.fake_jev import KeywordJev
from hunter.webhook import partial_read_reasons


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
        rank=4,
        registry_url="https://example.test/widget",
    )


def _big_release() -> tuple[dict[str, str], dict[str, str]]:
    body = "function add(a, b) {\n  return a + b;\n}\nmodule.exports = add;\n"
    old = {f"lib/mod_{index}.js": body for index in range(300)}
    new = {path: text + "module.exports.extra = 1;\n" for path, text in old.items()}
    hostile = "const data = Buffer.from(process.env.TOKEN).toString('base64');\n"
    for index in range(40):
        old[f"src/net_{index}.js"] = body
        new[f"src/net_{index}.js"] = body + hostile * 60
    return old, new


def test_a_long_changed_file_list_is_sent_once_not_on_every_chunk():
    old, new = _big_release()
    kept = diff_trees(old, new)
    manifest = changed_file_manifest(old, new)
    chunks = pack_chunks(kept, _meta(), budget=STATE_TOKEN_BUDGET, changed_files=manifest)
    full = [state for state in chunks if "lib/mod_299.js" in (state.get("changed_files") or "")]
    with_code = [state for state in chunks if "src/net_" in (state.get("diff_excerpt") or "")]
    assert full
    assert with_code
    for state in with_code:
        listed = state.get("changed_files") or ""
        assert CHANGED_FILES_SENT_NOTE in listed
        assert "lib/mod_0.js" not in listed
        assert listed.startswith("[changed_files]\ncounts:")
    for state in chunks:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET
    # Pass C and Pass D see the counts, not the whole list again.
    combined = slice_state(kept, _meta(), "combined", changed_files=manifest)
    assert CHANGED_FILES_SENT_NOTE in combined["changed_files"]


def test_a_short_changed_file_list_still_rides_on_every_chunk():
    body = "function add(a, b) {\n  return a + b;\n}\n"
    hostile = "const data = Buffer.from(process.env.TOKEN).toString('base64');\n"
    old = {"index.js": body, "lib/quiet.js": body}
    new = {"index.js": body + hostile * 900, "lib/quiet.js": body + "// note\n"}
    kept = diff_trees(old, new)
    manifest = changed_file_manifest(old, new)
    chunks = pack_chunks(kept, _meta(), budget=2_000, changed_files=manifest)
    assert len(chunks) > 1
    for state in chunks:
        assert state.get("changed_files") == manifest


def _pass_b_calls(jev: KeywordJev) -> list[dict]:
    return [call for call in jev.calls if set(PASS_B_IDS) <= set(call["questions"])]


def test_a_release_over_the_token_cap_goes_to_triage_unread_when_nothing_fits(monkeypatch):
    # Not even the first state fits in a 1,000-token cap, so there is no partial read.
    monkeypatch.setenv("HUNTER_SCOUT_RELEASE_TOKENS", "1000")
    old, new = _big_release()
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert not _pass_b_calls(jev)
    assert "release_budget" in result.signals
    assert result.band == "review"
    assert result.needs_llm_review is True


def test_the_token_cap_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_RELEASE_TOKENS", "0")
    old, new = _big_release()
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert _pass_b_calls(jev)
    assert "release_budget" not in result.signals


class _Quiet:
    """Every Noul is a clear no, or a clear yes when ``level`` is high."""

    def __init__(self, level: float = 0.04):
        self.level = level
        self.calls: list[dict] = []

    def system_one(self, state, questions):
        from hunter.jev import ChoiceView, JevResult, NoulView, ScoreView

        self.calls.append({"state": state, "questions": questions})
        result = JevResult(model="jev-1.13.0")
        for key, question in questions.items():
            if question["type"] == "noul":
                result.nouls[key] = NoulView(self.level)
            elif question["type"] == "choice":
                options = list(question["criteria"])
                result.choices[key] = ChoiceView(options[0], {options[0]: 1.0}, 0.5)
            else:
                result.scores[key] = ScoreView(0.0, {"0": 1.0}, 0.5, {"0": "local"})
        return result


def _scripted_big_release() -> tuple[dict[str, str], dict[str, str]]:
    old, new = _big_release()
    old["package.json"] = '{"name":"widget","version":"1.0.0"}\n'
    new["package.json"] = '{"name":"widget","version":"1.0.1","scripts":{"postinstall":"node setup.js"}}\n'
    return old, new


def _pass_b_states(jev) -> list[dict]:
    return [call["state"] for call in jev.calls if set(PASS_B_IDS) <= set(call["questions"])]


def test_an_over_cap_release_gets_a_risk_first_partial_read(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_RELEASE_TOKENS", "30000")
    monkeypatch.setenv("HUNTER_SCOUT_PARTIAL_TOKENS", "25000")
    old, new = _scripted_big_release()
    jev = _Quiet()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    states = _pass_b_states(jev)
    read = [path for state in states for path in state.get("file_paths") or []]
    assert states
    assert read[0] == "package.json"
    assert 0 < len(read) < 41
    assert "src/net_39.js" not in read
    assert "release_budget" in result.signals
    assert "release_budget_partial" in result.signals
    assert "jev_unreadable" not in result.signals
    assert partial_read_reasons(result.signals) == ["release_budget", "release_budget_partial"]
    # A quiet partial read with no other sign stays out of Triage, still marked partial.
    assert result.band == "benign"
    assert result.needs_llm_review is False


def test_an_over_cap_partial_read_that_finds_something_goes_to_triage(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_RELEASE_TOKENS", "30000")
    monkeypatch.setenv("HUNTER_SCOUT_PARTIAL_TOKENS", "25000")
    old, new = _scripted_big_release()
    jev = _Quiet(0.97)
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert _pass_b_states(jev)
    assert "release_budget_partial" in result.signals
    assert result.band in {"review", "alert"}
    assert result.needs_llm_review is True


def test_the_partial_read_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_RELEASE_TOKENS", "30000")
    monkeypatch.setenv("HUNTER_SCOUT_PARTIAL_TOKENS", "0")
    old, new = _scripted_big_release()
    jev = _Quiet()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert not _pass_b_states(jev)
    assert "release_budget" in result.signals
    assert "release_budget_partial" not in result.signals
    assert "jev_unreadable" in result.signals
    assert result.band == "review"
    assert result.needs_llm_review is True


def test_partial_reads_take_install_files_then_entry_points_then_suspicious_then_new_files():
    def diff(path: str, category: str, size: int) -> FileDiff:
        text = "x" * size
        return FileDiff(path=path, category=category, diff_text=text, added_text=text, old_text="", new_text=text)

    ordered = riskiest_first(
        [
            diff("docs/new.js", "new_file", 10),
            diff("lib/big.js", "suspicious_source", 500),
            diff("lib/small.js", "suspicious_source", 50),
            diff("bin/cli.js", "entry_points", 900),
            diff("art.png", "binary_media", 5),
            diff("package.json", "install_scripts", 2000),
            diff(".github/workflows/release.yml", "workflows", 100),
        ]
    )
    assert [item.path for item in ordered] == [
        ".github/workflows/release.yml",
        "package.json",
        "bin/cli.js",
        "lib/small.js",
        "lib/big.js",
        "docs/new.js",
    ]
