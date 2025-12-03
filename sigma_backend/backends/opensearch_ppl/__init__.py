"""
OpenSearch PPL backend for Sigma rules.
"""
from .opensearch_ppl import OpenSearchPPLBackend
from .opensearch_ppl_textquery import OpenSearchPPLBackend as OpenSearchPPLTextQueryBackend

__all__ = [
    "OpenSearchPPLBackend",
    "OpenSearchPPLTextQueryBackend"
]

