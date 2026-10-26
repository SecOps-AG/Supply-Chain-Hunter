"""MCP server.json checks. Synthetic documents, no network."""

from hunter.mcp_manifest import (
    is_unpinned,
    manifest_signals,
    normalize_repository,
    order_versions,
    select_versions,
    server_detail,
)

OFFICIAL = "io.modelcontextprotocol.registry/official"


def _server(**extra) -> dict:
    body = {
        "name": "io.example/demo",
        "version": "1.2.3",
        "repository": {"url": "https://github.com/a/b", "source": "github"},
        "packages": [
            {
                "registryType": "npm",
                "identifier": "@example/demo",
                "version": "1.2.3",
                "transport": {"type": "stdio"},
            }
        ],
    }
    body.update(extra)
    return body


def _entry(version: str, published: str, *, package_version: str | None = None, updated: str = "") -> dict:
    official = {"updatedAt": updated} if not published else {"publishedAt": published}
    if updated and published:
        official["updatedAt"] = updated
    return {
        "server": _server(
            version=version,
            packages=[
                {
                    "registryType": "npm",
                    "identifier": "@example/demo",
                    "version": package_version if package_version is not None else version,
                    "transport": {"type": "stdio"},
                }
            ],
        ),
        "_meta": {OFFICIAL: official},
    }


def test_pinned_versions_stay_quiet_and_ranges_do_not():
    assert is_unpinned("1.2.3") is False
    assert is_unpinned("1.2.3-beta.1") is False
    for bad in ("latest", "LATEST", "^1.2.3", "1.x", "1.*", "", None, "~1.2.0", ">=1.2.3", "1.2 || 2.0", ">=1.2.3, <2"):
        assert is_unpinned(bad) is True, bad

    assert manifest_signals(_server(version="1.2.3-beta.1"))[0] == []
    for bad in ("latest", "^1.2.3", "1.x"):
        signals, _detail = manifest_signals(_server(version="1.0.0", packages=[{
            "registryType": "npm",
            "identifier": "@example/demo",
            "version": bad,
            "transport": {"type": "stdio"},
        }]))
        assert signals == ["unpinned_version"], bad
    missing, _detail = manifest_signals(_server(packages=[{
        "registryType": "npm",
        "identifier": "@example/demo",
        "transport": {"type": "stdio"},
    }]))
    assert missing == ["unpinned_version"]
    assert manifest_signals(_server(version="latest"))[0] == ["unpinned_version"]


def test_cleartext_http_includes_loopback_and_https_does_not():
    https, _detail = manifest_signals(_server(remotes=[{"type": "streamable-http", "url": "https://example.com/mcp"}]))
    assert "http_remote" not in https

    signals, detail = manifest_signals(_server(remotes=[{"type": "streamable-http", "url": "http://example.com/mcp"}]))
    assert signals == ["http_remote"]
    assert detail["http_remote"]["hosts"] == ["example.com"]

    loop, detail = manifest_signals(_server(remotes=[{"type": "sse", "url": "http://127.0.0.1/mcp"}]))
    assert loop == ["http_remote"]
    assert detail["http_remote"]["hosts"] == ["127.0.0.1"]

    package, detail = manifest_signals(_server(packages=[{
        "registryType": "npm",
        "identifier": "@example/demo",
        "version": "1.2.3",
        "transport": {"type": "streamable-http", "url": "http://files.example/mcp"},
    }]))
    assert package == ["http_remote"]
    assert detail["http_remote"]["hosts"] == ["files.example"]


def test_secret_and_env_thresholds():
    def doc(count: int, *, secret: bool) -> dict:
        return _server(packages=[{
            "registryType": "npm",
            "identifier": "@example/demo",
            "version": "1.2.3",
            "transport": {"type": "stdio"},
            "environmentVariables": [
                {"name": f"K{index}", "isRequired": True, "isSecret": secret} for index in range(count)
            ],
        }])

    assert "many_required_secrets" not in manifest_signals(doc(4, secret=True))[0]
    assert manifest_signals(doc(5, secret=True))[0] == ["many_required_secrets"]
    assert "many_required_env" not in manifest_signals(doc(7, secret=False))[0]
    assert manifest_signals(doc(8, secret=False))[0] == ["many_required_env"]
    assert manifest_signals(doc(8, secret=True), secret_min=0, env_min=0)[0] == []


def test_repository_missing_and_normalized_change():
    missing, _detail = manifest_signals(_server(repository={"source": "github"}))
    assert missing == ["missing_repository"]
    assert manifest_signals(_server())[0] == []

    same = "https://github.com/a/b"
    variants = (
        "https://github.com/a/b/",
        "https://github.com/a/b.git",
        "https://www.github.com/a/b",
        "HTTPS://GitHub.com/a/b/",
    )
    for url in variants:
        assert normalize_repository(url) == normalize_repository(same)
        signals, _detail = manifest_signals(
            _server(repository={"url": url, "source": "github", "subfolder": "packages/demo"}),
            _server(repository={"url": same, "source": "github", "subfolder": "old"}),
        )
        assert signals == [], url

    moved, detail = manifest_signals(
        _server(repository={"url": "https://github.com/c/b", "source": "github"}),
        _server(repository={"url": "https://github.com/a/b", "source": "github"}),
    )
    assert moved == ["repository_changed"]
    assert detail["repository_changed"]["old"].endswith("/a/b")
    assert detail["repository_changed"]["new"].endswith("/c/b")

    scheme, _detail = manifest_signals(
        _server(repository={"url": "https://github.com/a/b", "source": "github"}),
        _server(repository={"url": "http://github.com/a/b", "source": "github"}),
    )
    assert scheme == ["repository_changed"]
    assert manifest_signals(_server(), None)[0] == []


def test_versions_follow_published_at_not_version_text():
    early = _entry("1.2.0", "2024-01-01T00:00:00Z")
    late = _entry("1.10.0", "2025-01-01T00:00:00Z")
    ordered = order_versions([late, early])
    assert [server_detail(item)["version"] for item in ordered] == ["1.2.0", "1.10.0"]
    assert sorted(["1.10.0", "1.2.0"]) == ["1.10.0", "1.2.0"]

    current, previous = select_versions([late, early], "npm", "@example/demo", "9.9.9")
    assert server_detail(current)["version"] == "1.10.0"
    assert server_detail(previous)["version"] == "1.2.0"

    matched, earlier = select_versions([late, early], "npm", "@example/demo", "1.2.0")
    assert server_detail(matched)["version"] == "1.2.0"
    assert earlier is None

    only, previous = select_versions([early], "npm", "@example/demo", "1.2.0")
    assert previous is None
    assert manifest_signals(server_detail(only), None)[0] == []


def test_updated_at_is_the_fallback_clock():
    older = _entry("1.2.0", "", updated="2024-05-01T00:00:00Z")
    newer = _entry("1.10.0", "", updated="2025-05-01T00:00:00Z")
    ordered = order_versions([newer, older])
    assert [server_detail(item)["version"] for item in ordered] == ["1.2.0", "1.10.0"]
