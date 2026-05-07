"""
Shared state schema — legacy shim.

The canonical state model is `src.core.orchestrator.GrondState`.
This module is retained for backward-compatibility with existing agent
definition files.  New code should import GrondState directly.
"""
from __future__ import annotations

# Re-export the canonical state so imports of `src.core.state.OsintState`
# continue to work.
from src.core.orchestrator import GrondState as OsintState

# Evidence replaces the old Finding model.
from src.models.evidence import Evidence as Finding

__all__ = ["OsintState", "Finding"]
