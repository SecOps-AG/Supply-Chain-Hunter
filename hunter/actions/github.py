"""Read-only GitHub access for the Actions watcher. Nothing is cloned or run.

Two ways to read a repository's tags:

* ``ls_refs``: the git smart-HTTP protocol (v2 ``ls-refs``), the same request
  ``git ls-remote`` makes. It needs no token, returns every tag with annotated
  tags peeled to their commit, and also names the default branch.
* ``tags_graphql``: one GraphQL query reads the newest 100 tags of up to
  ``GRAPHQL_BATCH`` repositories. It needs a token (any token; public data only).

REST calls (commit details, compare) work without a token at GitHub's low
anonymous limit and use the token when one is set.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import quote

from hunter.registry import FeedError, USER_AGENT

log = logging.getLogger("hunter.actions.github")

# (method, url, body, headers, timeout) -> (status, body). Errors with a status come back as a status.
Fetch = Callable[[str, str, bytes | None, dict[str, str], float], tuple[int, bytes]]

GRAPHQL_BATCH = 50
GRAPHQL_TAGS = 100
MAX_REF_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_RAW_BYTES = 512 * 1024


class RateLimited(FeedError):
    """GitHub refused the request for rate or abuse limits."""


def urllib_fetch(method: str, url: str, body: bytes | None, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read(MAX_REF_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(4096)
        except Exception:
            detail = b""
        return int(exc.code), detail
    except urllib.error.URLError as exc:
        raise FeedError(str(exc.reason)) from exc


@dataclass
class RefList:
    """Tags of one repository. ``complete`` is False when only the newest page was read."""

    tags: dict[str, str] = field(default_factory=dict)
    default_branch: str | None = None
    branches: dict[str, str] = field(default_factory=dict)
    complete: bool = True


def _pkt(text: str) -> bytes:
    data = text.encode("utf-8")
    return f"{len(data) + 4:04x}".encode("ascii") + data


def ls_refs_body(prefixes: list[str]) -> bytes:
    parts = [_pkt("command=ls-refs\n"), b"0001", _pkt("peel\n"), _pkt("symrefs\n")]
    parts.extend(_pkt(f"ref-prefix {prefix}\n") for prefix in prefixes)
    parts.append(b"0000")
    return b"".join(parts)


def parse_pkt_lines(blob: bytes) -> list[str]:
    """Data lines of a pkt-line stream, without the trailing newline."""
    lines: list[str] = []
    offset = 0
    while offset + 4 <= len(blob):
        try:
            size = int(blob[offset : offset + 4], 16)
        except ValueError as exc:
            raise FeedError("bad pkt-line length") from exc
        if size in (0, 1, 2):
            offset += 4
            continue
        if size < 4 or offset + size > len(blob):
            raise FeedError("truncated pkt-line stream")
        line = blob[offset + 4 : offset + size].decode("utf-8", "replace").rstrip("\n")
        if line.startswith("ERR "):
            raise FeedError(line[:200])
        lines.append(line)
        offset += size
    return lines


def parse_ls_refs(blob: bytes) -> RefList:
    refs = RefList()
    for line in parse_pkt_lines(blob):
        fields = line.split(" ")
        if len(fields) < 2:
            continue
        oid, ref = fields[0].lower(), fields[1]
        attrs = dict(item.split(":", 1) for item in fields[2:] if ":" in item)
        commit = attrs.get("peeled", oid).lower()
        if ref == "HEAD":
            target = attrs.get("symref-target", "")
            if target.startswith("refs/heads/"):
                refs.default_branch = target[len("refs/heads/") :]
        elif ref.startswith("refs/tags/"):
            refs.tags[ref[len("refs/tags/") :]] = commit
        elif ref.startswith("refs/heads/"):
            refs.branches[ref[len("refs/heads/") :]] = commit
    return refs


def _peel(target: dict | None) -> str:
    """Follow annotated tags (a tag of a tag is allowed) down to the commit sha."""
    for _depth in range(4):
        if not isinstance(target, dict):
            return ""
        if target.get("__typename") == "Tag" and isinstance(target.get("target"), dict):
            target = target["target"]
            continue
        return str(target.get("oid") or "").lower()
    return ""


def _graphql_string(value: str) -> str:
    return json.dumps(value)


TAG_FIELDS = (
    "nameWithOwner defaultBranchRef { name } "
    f"refs(refPrefix: \"refs/tags/\", first: {GRAPHQL_TAGS}, orderBy: {{field: TAG_COMMIT_DATE, direction: DESC}}) "
    "{ totalCount nodes { name target { __typename oid "
    "... on Tag { target { __typename oid ... on Tag { target { __typename oid } } } } } } }"
)


def tags_query(names: list[str]) -> str:
    parts = []
    for index, name in enumerate(names):
        owner, repo = name.split("/", 1)
        parts.append(
            f"r{index}: repository(owner: {_graphql_string(owner)}, name: {_graphql_string(repo)}) {{ {TAG_FIELDS} }}"
        )
    return "query { " + " ".join(parts) + " }"


WORKFLOW_FIELDS = (
    "workflows: object(expression: \"HEAD:.github/workflows\") "
    "{ ... on Tree { entries { name object { ... on Blob { text } } } } }"
)


def workflows_query(names: list[str]) -> str:
    parts = []
    for index, name in enumerate(names):
        owner, repo = name.split("/", 1)
        parts.append(
            f"r{index}: repository(owner: {_graphql_string(owner)}, name: {_graphql_string(repo)}) {{ {WORKFLOW_FIELDS} }}"
        )
    return "query { " + " ".join(parts) + " }"


class GitHubClient:
    def __init__(
        self,
        token: str = "",
        *,
        fetch: Fetch = urllib_fetch,
        api: str = "https://api.github.com",
        web: str = "https://github.com",
        raw: str = "https://raw.githubusercontent.com",
        codeload: str = "https://codeload.github.com",
        timeout: float = 30.0,
    ):
        self.token = (token or "").strip()
        self.fetch = fetch
        self.api = api.rstrip("/")
        self.web = web.rstrip("/")
        self.raw = raw.rstrip("/")
        self.codeload = codeload.rstrip("/")
        self.timeout = timeout

    @property
    def has_token(self) -> bool:
        return bool(self.token)

    def _api_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _json(self, status: int, body: bytes, what: str) -> dict | list | None:
        if status == 404:
            return None
        if status in (403, 429) and (b"rate limit" in body.lower() or b"abuse" in body.lower() or status == 429):
            raise RateLimited(f"{what}: GitHub rate limit")
        if status != 200:
            raise FeedError(f"{what}: HTTP {status}")
        if len(body) > MAX_JSON_BYTES:
            raise FeedError(f"{what}: response too large")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FeedError(f"{what}: bad JSON") from exc

    # --- tags -------------------------------------------------------------

    def ls_refs(self, name: str, prefixes: list[str] | None = None) -> RefList | None:
        """Every tag (and HEAD) of a public repository over git smart HTTP. None when it is gone or private."""
        url = f"{self.web}/{name}.git/git-upload-pack"
        headers = {
            "Content-Type": "application/x-git-upload-pack-request",
            "Accept": "application/x-git-upload-pack-result",
            "Git-Protocol": "version=2",
        }
        body = ls_refs_body(prefixes or ["refs/tags/", "HEAD"])
        status, data = self.fetch("POST", url, body, headers, self.timeout)
        if status in (401, 403, 404):
            if status == 403 and b"rate" in data.lower():
                raise RateLimited(f"{name}: git rate limit")
            return None
        if status == 429:
            raise RateLimited(f"{name}: git rate limit")
        if status != 200:
            raise FeedError(f"{name}: git ls-refs HTTP {status}")
        if len(data) > MAX_REF_BYTES:
            raise FeedError(f"{name}: ref list too large")
        return parse_ls_refs(data)

    def graphql(self, query: str) -> dict:
        if not self.token:
            raise FeedError("GitHub GraphQL needs a token")
        body = json.dumps({"query": query}).encode("utf-8")
        headers = {**self._api_headers(), "Content-Type": "application/json"}
        status, data = self.fetch("POST", f"{self.api}/graphql", body, headers, self.timeout)
        document = self._json(status, data, "graphql")
        if not isinstance(document, dict):
            raise FeedError("graphql: empty response")
        errors = document.get("errors") or []
        if any(str(item.get("type") or "") == "RATE_LIMITED" for item in errors if isinstance(item, dict)):
            raise RateLimited("graphql: GitHub rate limit")
        return document.get("data") or {}

    def tags_graphql(self, names: list[str]) -> dict[str, RefList | None]:
        """Newest tags of each repository, ``GRAPHQL_BATCH`` per query. None for a missing repository."""
        found: dict[str, RefList | None] = {}
        for start in range(0, len(names), GRAPHQL_BATCH):
            batch = names[start : start + GRAPHQL_BATCH]
            data = self.graphql(tags_query(batch))
            for index, name in enumerate(batch):
                repo = data.get(f"r{index}")
                if not isinstance(repo, dict):
                    found[name] = None
                    continue
                refs = RefList()
                branch = repo.get("defaultBranchRef") or {}
                refs.default_branch = branch.get("name") if isinstance(branch, dict) else None
                connection = repo.get("refs") or {}
                nodes = connection.get("nodes") or []
                for node in nodes:
                    if not isinstance(node, dict) or not node.get("name"):
                        continue
                    sha = _peel(node.get("target"))
                    if sha:
                        refs.tags[str(node["name"])] = sha
                refs.complete = int(connection.get("totalCount") or 0) <= len(nodes)
                found[name] = refs
        return found

    def workflow_uses(self, names: list[str], batch: int = 20) -> dict[str, list[str]]:
        """Text of every file in ``.github/workflows`` on the default branch, per repository."""
        found: dict[str, list[str]] = {}
        for start in range(0, len(names), batch):
            chunk = names[start : start + batch]
            data = self.graphql(workflows_query(chunk))
            for index, name in enumerate(chunk):
                repo = data.get(f"r{index}")
                tree = (repo or {}).get("workflows") if isinstance(repo, dict) else None
                texts: list[str] = []
                for entry in (tree or {}).get("entries") or []:
                    blob = (entry or {}).get("object") or {}
                    text = blob.get("text") if isinstance(blob, dict) else None
                    if isinstance(text, str):
                        texts.append(text)
                found[name] = texts
        return found

    # --- REST ---------------------------------------------------------------

    def commit(self, name: str, sha: str) -> dict | None:
        """Author, committer, date and signature state of one commit."""
        status, data = self.fetch("GET", f"{self.api}/repos/{name}/commits/{quote(sha)}", None, self._api_headers(), self.timeout)
        document = self._json(status, data, f"{name} commit")
        if not isinstance(document, dict):
            return None
        details = document.get("commit") or {}
        verification = details.get("verification") or {}
        committer = details.get("committer") or {}
        return {
            "sha": str(document.get("sha") or sha).lower(),
            "author_login": str((document.get("author") or {}).get("login") or ""),
            "committer_login": str((document.get("committer") or {}).get("login") or ""),
            "date": str(committer.get("date") or ""),
            "verified": bool(verification.get("verified")),
            "parents": [str(item.get("sha") or "") for item in document.get("parents") or [] if isinstance(item, dict)],
        }

    def compare(self, name: str, base: str, head: str) -> str | None:
        """GitHub's compare status: ahead, behind, identical or diverged. None when either side is unknown."""
        url = f"{self.api}/repos/{name}/compare/{quote(base, safe='')}...{quote(head, safe='')}?per_page=1"
        status, data = self.fetch("GET", url, None, self._api_headers(), self.timeout)
        document = self._json(status, data, f"{name} compare")
        if not isinstance(document, dict):
            return None
        value = str(document.get("status") or "")
        return value if value in {"ahead", "behind", "identical", "diverged"} else None

    def raw_file(self, name: str, ref: str, path: str) -> str | None:
        url = f"{self.raw}/{name}/{quote(ref, safe='')}/{quote(path)}"
        status, data = self.fetch("GET", url, None, {}, self.timeout)
        if status == 404:
            return None
        if status != 200:
            raise FeedError(f"{name}/{path}: HTTP {status}")
        return data[:MAX_RAW_BYTES].decode("utf-8", "replace")

    def tarball_url(self, name: str, sha: str) -> str:
        return f"{self.codeload}/{name}/tar.gz/{sha}"
