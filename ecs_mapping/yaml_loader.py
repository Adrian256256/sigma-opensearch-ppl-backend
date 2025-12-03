"""
Simple YAML-based ECS Field Mapping for Sigma

This module provides a simpler way to load ECS field mappings from a YAML file,
following the Sigma pipeline standard.
"""

from pathlib import Path
from sigma.processing.pipeline import ProcessingPipeline


def load_ecs_pipeline_from_yaml(yaml_path: str = None) -> ProcessingPipeline:
    """
    Load ECS field mapping pipeline from a YAML file.
    
    This is a simpler alternative to the Python-based ECSFieldMappingPipeline.
    It uses Sigma's standard YAML pipeline format.
    
    Args:
        yaml_path: Path to the YAML pipeline file. If None, uses the default
                  ecs_mapping.yml in the same directory.
    
    Returns:
        ProcessingPipeline configured from YAML
    
    Example:
        >>> from ecs_mapping.yaml_loader import load_ecs_pipeline_from_yaml
        >>> from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
        >>> 
        >>> # Use default ECS mapping YAML
        >>> pipeline = load_ecs_pipeline_from_yaml()
        >>> backend = OpenSearchPPLBackend(processing_pipeline=pipeline)
        >>> 
        >>> # Use custom YAML file
        >>> pipeline = load_ecs_pipeline_from_yaml("my_custom_ecs.yml")
        >>> backend = OpenSearchPPLBackend(processing_pipeline=pipeline)
    """
    if yaml_path is None:
        # Use default YAML file in the same directory
        yaml_path = Path(__file__).parent / "ecs_mapping.yml"
    else:
        yaml_path = Path(yaml_path)
    
    if not yaml_path.exists():
        raise FileNotFoundError(f"ECS mapping YAML file not found: {yaml_path}")
    
    # Load pipeline from YAML using pySigma's built-in loader
    # Open and read the YAML file
    with open(yaml_path, 'r') as f:
        pipeline = ProcessingPipeline.from_yaml(f)
    
    return pipeline


def create_ecs_pipeline_from_yaml(yaml_path: str = None) -> ProcessingPipeline:
    """
    Alias for load_ecs_pipeline_from_yaml for consistency with the Python API.
    
    Args:
        yaml_path: Path to the YAML pipeline file
    
    Returns:
        ProcessingPipeline configured from YAML
    """
    return load_ecs_pipeline_from_yaml(yaml_path)
