"""jevtok: exact token counting for TypeSafe's Jev decision model.

    >>> import jevtok
    >>> enc = jevtok.get_encoding("jev-1.13")
    >>> enc.count("The tokenization of evidence")
    7
    >>> jevtok.estimate_request_tokens("hello world")
    269
"""
from .request import (
    BASE_OVERHEAD,
    CONTEXT_LIMIT,
    ContextLimitExceeded,
    estimate_request_tokens,
    question_cost,
    state_cost,
)
from .tokenizer import Encoding, encoding_for_model, get_encoding, list_encoding_names

__version__ = "0.1.0"
__all__ = [
    "BASE_OVERHEAD",
    "CONTEXT_LIMIT",
    "ContextLimitExceeded",
    "Encoding",
    "encoding_for_model",
    "estimate_request_tokens",
    "get_encoding",
    "list_encoding_names",
    "question_cost",
    "state_cost",
    "__version__",
]
