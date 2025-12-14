# ECS Field Verification Results

## Overview

This directory contains the results of verifying Sigma rule fields against the official Elastic Common Schema (ECS) field definitions.

## Files

### `ecs_verification_results.csv`

This file contains the verification results for all Sigma fields found in the rule collection. It maps each Sigma field to its corresponding ECS field(s) or indicates if no official ECS equivalent exists.

#### Columns

- **`sigma_field`**: The original field name as used in Sigma rules
- **`match_type`**: The type of match found in the official ECS specification
  - `exact`: Direct 1:1 match with an official ECS field name
  - `partial`: Similar field name found in ECS, but requires manual verification to confirm correct mapping
  - `none`: No official ECS equivalent found
- **`ecs_field`**: The corresponding ECS field name(s). For partial matches, multiple potential fields may be listed
- **`notes`**: Additional information about the mapping
  - "Official ECS field" for exact matches
  - "Similar name, verify manually" for partial matches
  - "No official ECS equivalent found" when no match exists

#### Match Types Explained

**Exact Match (`exact`)**
- The Sigma field name exists as-is in the official ECS specification
- These fields can be used directly without modification
- Example: `Message` → `message`

**Partial Match (`partial`)**
- The field name is similar to one or more ECS fields
- Manual verification is needed to ensure correct semantic mapping
- Multiple potential ECS fields may be suggested
- Example: `Action` could map to `event.action`
- Example: `Address` could map to `client.address`, `destination.address`, or `email.bcc.address` depending on context

**No Match (`none`)**
- No official ECS field exists for this Sigma field
- These fields may be:
  - Windows-specific event data fields (should use `winlog.event_data.*` namespace)
  - Custom/vendor-specific fields
  - Legacy or deprecated field names
  - Arguments/parameters that need contextual mapping
- Examples: `AccessMask`, `GrantedAccess`, `a0-a7` (syscall arguments)

### `sigma_fields.csv`

This file contains all Sigma fields extracted from the official [Sigma GitHub repository](https://github.com/SigmaHQ/sigma) using the `checker.py` script.

#### Columns

- **`sigma_field`**: The original field name as used in Sigma rules
- **`ecs_field`**: The recommended ECS field mapping based on semantic analysis and ECS best practices

These mappings follow ECS best practices and include:
- Standard ECS fields for common security events
- Windows-specific fields under `winlog.event_data.*`
- Process, file, network, user, and registry fields
- Cloud provider-specific mappings

## Usage

These files are used to:
1. **Validate Sigma rule fields** against official ECS specifications
2. **Guide field mapping** when converting Sigma rules to OpenSearch PPL queries
3. **Identify missing fields** that need custom handling or namespacing
4. **Ensure compatibility** with ECS-compliant SIEM platforms

## Notes

- Fields with `none` match type may still have valid mappings in extended ECS namespaces (e.g., `winlog.*`, `powershell.*`)
- Partial matches require context-aware mapping based on the specific Sigma rule's detection logic
- Some Sigma fields represent the same concept but use different naming conventions (case sensitivity, abbreviations)
- Windows Event Log fields often don't have direct ECS equivalents and should use the `winlog.event_data.*` namespace

## References

- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
- [ECS GitHub Repository](https://github.com/elastic/ecs)
- [ECS Field CSV](https://github.com/elastic/ecs/blob/master/generated/csv/fields.csv)
