"""
OpenSearch PPL backend for Sigma rules.

This backend supports both regular Sigma detection rules and correlation rules.
"""
from .opensearch_ppl import OpenSearchPPLBackend, register_custom_modifiers

# Register custom modifiers when the backend is imported
register_custom_modifiers()

__all__ = [
    "OpenSearchPPLBackend",
    "register_custom_modifiers"
]
