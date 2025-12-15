# Tables

This directory contains CSV files documenting all features, modifiers, and operations that have been implemented and verified in the Sigma to OpenSearch PPL backend.

## Contents

- **`custom_modifiers.csv`** - Custom field modifiers and transformations
- **`detection_rules.csv`** - Detection rule implementations
- **`logical_operations.csv`** - Logical operations (AND, OR, NOT, etc.)
- **`modifiers_testing.csv`** - Field modifiers testing coverage
- **`special_features.csv`** - Special features and edge cases

## Verification

All features and implementations documented in these tables are automatically verified by the test suite located in:
- `tests/automatic_tests/`

The automated tests ensure that each documented feature works correctly and maintains compatibility with the Sigma rule format and OpenSearch PPL query language.
