"""Tests for ``run_pipeline`` end state and HTTP-oriented error mapping."""

import pytest

from src.core.exceptions import ActiveScanApprovalRequiredError, PipelineInputError
from src.core.orchestrator import run_pipeline


@pytest.mark.asyncio
async def test_run_pipeline_run_nmap_raises_without_hitl_resume() -> None:
    with pytest.raises(ActiveScanApprovalRequiredError):
        await run_pipeline(
            target="abcexpress.id",
            goal="Company intel",
            analyst_id="analyst-test",
            run_nmap=True,
        )


@pytest.mark.asyncio
async def test_run_pipeline_empty_target_is_pipeline_input_error() -> None:
    with pytest.raises(PipelineInputError, match="target is required"):
        await run_pipeline(
            target="",
            goal="Company intel",
            analyst_id="analyst-test",
            run_nmap=False,
        )
