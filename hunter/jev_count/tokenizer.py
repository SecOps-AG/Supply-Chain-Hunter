"""Reconstruction of the Jev (TypeSafe System One) tokenizer.

Vendored from https://github.com/LabGuy94/jevtok at 698c53b778ce901be82c166d809e4b1f7948a465 (MIT).
The o200k vocabulary is read from vocab/o200k_base.tiktoken in this package.
That load is the one change from the pinned commit: tiktoken.get_encoding would download it.

Pipeline, as measured against the live API's ``usage.input_tokens``:

0. NFC-normalize the text (not NFKC: fullwidth forms and ligatures survive).
1. Pre-tokenize with a cl100k-style regex, except: every digit is its own
   pre-token, letter runs include combining marks, marks never join
   punctuation runs, and punctuation runs absorb trailing newlines.
2. If the whole pre-token is in the LOOKUP set (a subset of the o200k_base
   vocabulary), it is a single token.
3. Otherwise run byte-level BPE with o200k_base rank priority, allowing only
   merges whose result is in the FORMED set (another subset of o200k_base)
   or a single byte.

Token ids are o200k_base ranks.
"""
from __future__ import annotations

import unicodedata
from importlib import resources
from pathlib import Path

import regex
import tiktoken
from tiktoken.load import load_tiktoken_bpe

PRETOK = regex.compile(
    r"""(?i:'s|'t|'re|'ve|'m|'ll|'d)"""
    r"""|[^\r\n\p{L}\p{N}]?[\p{L}\p{M}]+"""
    r"""|\p{N}"""
    r"""| ?[^\s\p{L}\p{N}\p{M}]+[\r\n]*"""
    r"""|\s*[\r\n]+|\s+(?!\S)|\s+"""
)

_MAGIC = b"JEVTOK1\0"
_MODELS = {
    "jev-1.13": "jev-1.13.bin",
}
_ALIASES = {
    "jev-latest": "jev-1.13",
    "jev-1.13.0": "jev-1.13",
    "jev-1.13-20260917": "jev-1.13",
    "typesafe/jev-1.13": "jev-1.13",
    "typesafe/jev-latest": "jev-1.13",
}


def _load_bitmaps(path: Path) -> tuple[bytes, bytes, int]:
    raw = path.read_bytes()
    if raw[:8] != _MAGIC:
        raise ValueError(f"{path}: not a jevtok data file")
    n_vocab = int.from_bytes(raw[10:14], "little")
    size = (n_vocab + 7) // 8
    body = raw[14:]
    if len(body) != 2 * size:
        raise ValueError(f"{path}: truncated data file")
    return body[:size], body[size:], n_vocab


def _o200k_base() -> tiktoken.Encoding:
    """o200k ranks from the vendored file. The regex is tiktoken's o200k pattern."""
    path = Path(str(resources.files("hunter.jev_count").joinpath("vocab", "o200k_base.tiktoken")))
    ranks = load_tiktoken_bpe(str(path))
    pat_str = "|".join(
        [
            r"""[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?""",
            r"""[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?""",
            r"""\p{N}{1,3}""",
            r""" ?[^\s\p{L}\p{N}]+[\r\n/]*""",
            r"""\s*[\r\n]+""",
            r"""\s+(?!\S)""",
            r"""\s+""",
        ]
    )
    return tiktoken.Encoding(
        name="o200k_base",
        pat_str=pat_str,
        mergeable_ranks=ranks,
        special_tokens={"<|endoftext|>": 199999, "<|endofprompt|>": 200018},
    )


class Encoding:
    """tiktoken-style interface: ``encode``, ``decode``, ``n_vocab``, ``name``.

    ``count`` and ``encode_pieces`` are Jev-specific extras.
    """

    def __init__(self, name: str, data_path: Path):
        self.name = name
        self._base = _o200k_base()
        self.n_vocab = self._base.n_vocab
        lookup_bm, formed_bm, n = _load_bitmaps(data_path)
        self._lookup: set[bytes] = set()
        self._formed: set[bytes] = set()
        self._ranks: dict[bytes, int] = {}
        for i in range(n):
            try:
                tok = self._base.decode_single_token_bytes(i)
            except Exception:  # special tokens have no bytes
                continue
            self._ranks[tok] = i
            if lookup_bm[i >> 3] >> (i & 7) & 1:
                self._lookup.add(tok)
            if formed_bm[i >> 3] >> (i & 7) & 1:
                self._formed.add(tok)

    # -- core -------------------------------------------------------------

    def _encode_pretoken(self, b: bytes) -> list[bytes]:
        if b in self._lookup:
            return [b]
        parts = [b[i:i + 1] for i in range(len(b))]
        ranks, formed = self._ranks, self._formed
        while len(parts) > 1:
            best_rank = None
            best_i = -1
            for i in range(len(parts) - 1):
                cand = parts[i] + parts[i + 1]
                r = ranks.get(cand)
                if r is not None and cand in formed and (best_rank is None or r < best_rank):
                    best_rank, best_i = r, i
            if best_i < 0:
                break
            parts[best_i:best_i + 2] = [parts[best_i] + parts[best_i + 1]]
        return parts

    def encode_pieces(self, text: str) -> list[bytes]:
        """Token byte strings, in order."""
        out: list[bytes] = []
        for chunk in PRETOK.findall(unicodedata.normalize("NFC", text)):
            out.extend(self._encode_pretoken(chunk.encode("utf-8")))
        return out

    def encode(self, text: str) -> list[int]:
        """Token ids (o200k_base ranks)."""
        ranks = self._ranks
        return [ranks[p] for p in self.encode_pieces(text)]

    def decode(self, ids: list[int]) -> str:
        return self._base.decode(ids)

    def decode_bytes(self, ids: list[int]) -> bytes:
        return self._base.decode_bytes(ids)

    def count(self, text: str) -> int:
        """Number of tokens; equals ``len(encode(text))`` but skips id lookup."""
        text = unicodedata.normalize("NFC", text)
        return sum(len(self._encode_pretoken(c.encode("utf-8"))) for c in PRETOK.findall(text))

    def __repr__(self) -> str:
        return f"<jevtok.Encoding {self.name!r}>"


_cache: dict[str, Encoding] = {}


def list_encoding_names() -> list[str]:
    return sorted(_MODELS)


def get_encoding(name: str = "jev-1.13") -> Encoding:
    """Return the Encoding for a Jev model version (default: latest known)."""
    name = _ALIASES.get(name, name)
    if name not in _MODELS:
        raise ValueError(f"unknown encoding {name!r}; known: {list_encoding_names()}")
    if name not in _cache:
        path = Path(str(resources.files("hunter.jev_count").joinpath("vocab", _MODELS[name])))
        _cache[name] = Encoding(name, path)
    return _cache[name]


def encoding_for_model(model: str) -> Encoding:
    """tiktoken-style alias: accepts model ids such as ``jev-latest``."""
    return get_encoding(model)
