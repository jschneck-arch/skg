"""Canonical SKG reasoning layer (SKG-R)."""

from skg_reasoning.contracts import (
    DELEGATION_REASONING_REQUIRED_WICKETS,
    DELEGATION_REASONING_SCHEMA,
    DELEGATION_REASONING_SLICE,
    is_delegation_reasoning_output,
    validate_delegation_reasoning_output,
)
from skg_reasoning.delegation_engine import evaluate_delegation_reasoning

__all__ = [
    "DELEGATION_REASONING_REQUIRED_WICKETS",
    "DELEGATION_REASONING_SCHEMA",
    "DELEGATION_REASONING_SLICE",
    "evaluate_delegation_reasoning",
    "is_delegation_reasoning_output",
    "validate_delegation_reasoning_output",
]
