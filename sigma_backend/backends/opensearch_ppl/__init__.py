"""
OpenSearch PPL backend for Sigma rules.
"""
from .opensearch_ppl_textquery import OpenSearchPPLBackend
from .opensearch_ppl_correlations import OpenSearchPPLCorrelationBackend
from .modifiers import register_custom_modifiers

# Register custom modifiers when the backend is imported
register_custom_modifiers()

__all__ = [
    "OpenSearchPPLBackend",
    "OpenSearchPPLCorrelationBackend",
    "register_custom_modifiers"
]

