"""
ECS (Elastic Common Schema) Field Mapping for Sigma Rules

This package provides YAML-based field mapping pipelines to convert Sigma field names
to ECS-compliant field names for use with OpenSearch.

The pipeline uses the standard Sigma YAML pipeline format for simplicity and maintainability.
"""

from .yaml_loader import load_ecs_pipeline_from_yaml, create_ecs_pipeline_from_yaml

__all__ = [
    'load_ecs_pipeline_from_yaml',
    'create_ecs_pipeline_from_yaml'
]
