"""
OpenSearch PPL backend for Sigma rules.

This backend supports both regular Sigma detection rules and correlation rules.
"""
from .opensearch_ppl import OpenSearchPPLBackend

__all__ = [
    "OpenSearchPPLBackend"
]
