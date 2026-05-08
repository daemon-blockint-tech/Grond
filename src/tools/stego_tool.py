"""
Steganography analysis adapters.

- **stegoVeritas** (`stegoveritas`): comprehensive multi-method CLI — LSB extraction,
  color map analysis, image transforms, trailing data, StegHide, EXIF, XMP, carving.
  ( https://github.com/bannsec/stegoVeritas )
- **LSB fallback**: pure-Python LSB bit-plane extraction via Pillow — no external
  CLI required. Detects anomalies in least-significant-bit planes.

Both adapters receive an analyst-uploaded file and produce Evidence with
``ClaimType.STEGANOGRAPHY`` (detection) or ``ClaimType.STEGO_EMBEDDED`` (extracted payload).

**Passive:** analyst must only upload material they are authorized to analyze.
Flag extracted content via ``requires_review`` — hidden data may contain illicit material.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import struct
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.audit import AuditLogger
from src.core.config import get_settings
from src.core.exceptions import ToolExecutionError
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTier, SourceTool
from src.tools.base import ToolAdapter

STEGOVERITAS_ENDPOINT = "local:stegoveritas"
LSB_ENDPOINT = "local:stego-lsb"


class StegoInput(BaseModel):
    target: str = Field(..., min_length=1, description="Investigation / case label")
    analyst_id: str
    session_id: str
    query: str = Field(default="", description="Audit label")
    file_path: str = Field(..., min_length=1, description="Absolute path to file to analyze")
    original_filename: str = Field(default="upload", description="Original client filename")
    engine: str = Field(
        default="auto",
        pattern="^(stegoveritas|lsb|auto)$",
        description="Engine: stegoveritas, lsb, or auto",
    )
    password: str = Field(default="", description="Password for encrypted stego (steghide etc.)")


class StegoOutput(BaseModel):
    evidence: list[Evidence]
    error: str | None = None


def _suffix(name: str) -> str:
    p = Path(name)
    s = p.suffix
    if s and len(s) <= 16:
        return s
    return ""


def _stegoveritas_available() -> bool:
    return shutil.which(get_settings().stegoveritas_bin) is not None


def _pillow_available() -> bool:
    try:
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def _stego_evidence(
    *,
    inp: StegoInput,
    source_tool: SourceTool,
    api_endpoint: str,
    extractor: str,
    claim: str,
    claim_type: ClaimType,
    value: dict[str, Any],
    raw_response: dict[str, Any],
    weight: float,
    requires_review: bool = True,
    review_reason: str = "steganography_analysis_may_contain_illicit_hidden_content",
) -> Evidence:
    collected_at = datetime.now(UTC)
    prov = Provenance(
        source_tool=source_tool,
        source_tier=SourceTier.COMMUNITY,
        collection_query=inp.query.strip() or Path(inp.original_filename).name,
        api_endpoint=api_endpoint,
        collected_at=collected_at,
        analyst_id=inp.analyst_id,
        session_id=inp.session_id,
        source_url=f"artifact://{inp.original_filename}",
        raw_snippet=claim[:800],
        extractor=extractor,
        raw_response=raw_response,
    )
    return Evidence(
        target=inp.target,
        claim=claim,
        claim_type=claim_type,
        value=value,
        provenance=prov,
        confidence=round(weight * 0.85, 4),
        requires_review=requires_review,
        review_reason=review_reason,
    )


class StegoVeritasAdapter(ToolAdapter[StegoInput]):
    """Run stegoVeritas CLI on an uploaded file and parse findings."""

    tool_name = SourceTool.STEGOVERITAS

    def __init__(
        self,
        audit: AuditLogger,
        *,
        stegoveritas_bin: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        super().__init__(audit=audit, rate_limiter=None)
        settings = get_settings()
        self._bin = stegoveritas_bin or settings.stegoveritas_bin
        self._timeout = timeout_seconds or settings.stego_timeout_seconds

    async def _execute(self, input: StegoInput) -> list[Evidence]:
        path = Path(input.file_path).resolve()
        if not path.is_file():
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"File not found or not a file: {path}",
            )

        out_dir = tempfile.mkdtemp(prefix="grond-stego-")
        try:
            cmd = [self._bin, str(path), "-out", out_dir]
            if input.password:
                cmd.extend(["-password", input.password])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._timeout,
                )
            except TimeoutError as exc:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message=f"stegoVeritas timed out after {self._timeout}s",
                    cause=exc,
                ) from exc

            out_txt = stdout.decode("utf-8", errors="replace")
            err_txt = stderr.decode("utf-8", errors="replace")[:500]

            if proc.returncode == 127 or "not found" in err_txt.lower():
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message=f"stegoVeritas not runnable ({self._bin!r}). Install: pip install stegoveritas && stegoveritas_install_deps",
                )

            weight = get_settings().confidence_weight_stegoveritas
            name = input.original_filename
            raw: dict[str, Any] = {
                "stdout_preview": out_txt[:2000],
                "stderr_preview": err_txt[:500],
                "exit_code": proc.returncode,
                "output_dir": out_dir,
            }

            findings = out_txt.lower()
            detected = any(
                kw in findings
                for kw in ("lsb", "hidden", "steghide", "embedded", "trailing data", "extracted", "found")
            )

            evidence: list[Evidence] = []

            if detected:
                evidence.append(
                    _stego_evidence(
                        inp=input,
                        source_tool=SourceTool.STEGOVERITAS,
                        api_endpoint=STEGOVERITAS_ENDPOINT,
                        extractor="stegoveritas.multi",
                        claim=f"Steganography indicators detected in {name} (stegoVeritas)",
                        claim_type=ClaimType.STEGANOGRAPHY,
                        value={
                            "artifact_name": name,
                            "method": "stegoveritas_multi",
                            "detection_confidence": "high" if proc.returncode == 0 else "medium",
                            "findings_summary": out_txt[:500],
                        },
                        raw_response=raw,
                        weight=weight,
                    )
                )

            out_path = Path(out_dir)
            extracted_files = list(out_path.rglob("*")) if out_path.exists() else []
            payload_files = [f for f in extracted_files if f.is_file() and f.stat().st_size > 0]

            for pf in payload_files[:10]:
                try:
                    preview = pf.read_bytes()[:256]
                    try:
                        preview_text = preview.decode("utf-8", errors="replace")[:200]
                    except Exception:
                        preview_text = preview.hex()[:200]
                    evidence.append(
                        _stego_evidence(
                            inp=input,
                            source_tool=SourceTool.STEGOVERITAS,
                            api_endpoint=STEGOVERITAS_ENDPOINT,
                            extractor="stegoveritas.carve",
                            claim=f"Extracted payload from {name}: {pf.name}",
                            claim_type=ClaimType.STEGO_EMBEDDED,
                            value={
                                "artifact_name": name,
                                "method": "stegoveritas_extract",
                                "payload_size": pf.stat().st_size,
                                "payload_preview": preview_text,
                                "payload_filename": pf.name,
                            },
                            raw_response={**raw, "payload_path": str(pf)},
                            weight=weight * 0.9,
                        )
                    )
                except Exception:
                    continue

            if not detected and not payload_files:
                evidence.append(
                    _stego_evidence(
                        inp=input,
                        source_tool=SourceTool.STEGOVERITAS,
                        api_endpoint=STEGOVERITAS_ENDPOINT,
                        extractor="stegoveritas.scan",
                        claim=f"No steganography indicators found in {name} (stegoVeritas clean)",
                        claim_type=ClaimType.STEGANOGRAPHY,
                        value={
                            "artifact_name": name,
                            "method": "stegoveritas_multi",
                            "detection_confidence": "none",
                            "findings_summary": "clean",
                        },
                        raw_response=raw,
                        weight=weight * 0.5,
                        requires_review=False,
                        review_reason=None,
                    )
                )

            return evidence

        except ToolExecutionError:
            raise
        except Exception as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"stegoVeritas execution failed: {exc}",
                cause=exc,
            ) from exc


class LSBFallbackAdapter(ToolAdapter[StegoInput]):
    """Pure-Python LSB bit-plane analysis using Pillow. No external CLI required."""

    tool_name = SourceTool.STEGO_LSB

    def __init__(self, audit: AuditLogger) -> None:
        super().__init__(audit=audit, rate_limiter=None)

    async def _execute(self, input: StegoInput) -> list[Evidence]:
        try:
            from PIL import Image
        except ImportError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="Pillow not installed (pip install Pillow). Required for LSB fallback.",
                cause=exc,
            ) from exc

        path = Path(input.file_path).resolve()
        if not path.is_file():
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"File not found or not a file: {path}",
            )

        try:
            img = Image.open(path)
            img.load()
        except Exception as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"Cannot open image with Pillow: {exc}",
                cause=exc,
            ) from exc

        name = input.original_filename
        width, height = img.size
        mode = img.mode
        weight = get_settings().confidence_weight_stego_lsb

        raw: dict[str, Any] = {
            "image_size": [width, height],
            "image_mode": mode,
            "format": img.format,
        }

        evidence: list[Evidence] = []

        pixels = list(img.getdata())
        total_pixels = len(pixels)

        if total_pixels == 0:
            evidence.append(
                _stego_evidence(
                    inp=input,
                    source_tool=SourceTool.STEGO_LSB,
                    api_endpoint=LSB_ENDPOINT,
                    extractor="lsb.empty_check",
                    claim=f"Empty image: {name}",
                    claim_type=ClaimType.STEGANOGRAPHY,
                    value={"artifact_name": name, "method": "lsb", "detection_confidence": "none"},
                    raw_response=raw,
                    weight=weight * 0.3,
                    requires_review=False,
                    review_reason=None,
                )
            )
            return evidence

        lsb_bits = []
        for px in pixels[:100000]:
            if isinstance(px, (tuple, list)):
                for ch in px[:3]:
                    lsb_bits.append(ch & 1)
            else:
                lsb_bits.append(int(px) & 1)

        total_lsb = len(lsb_bits)
        ones = sum(lsb_bits)
        zeros = total_lsb - ones
        ratio = ones / total_lsb if total_lsb > 0 else 0.0

        raw["lsb_ones"] = ones
        raw["lsb_zeros"] = zeros
        raw["lsb_ratio"] = round(ratio, 4)
        raw["lsb_sample_size"] = total_lsb

        deviation = abs(ratio - 0.5)
        confidence_label = "none"
        if deviation > 0.15:
            confidence_label = "high"
        elif deviation > 0.07:
            confidence_label = "medium"
        elif deviation > 0.03:
            confidence_label = "low"

        if confidence_label != "none":
            byte_data = bytearray()
            for i in range(0, min(len(lsb_bits), 800), 8):
                byte_val = 0
                for bit_idx in range(8):
                    if i + bit_idx < len(lsb_bits):
                        byte_val = (byte_val << 1) | lsb_bits[i + bit_idx]
                    else:
                        byte_val <<= 1
                byte_data.append(byte_val)

            preview_text = ""
            try:
                preview_text = byte_data[:64].decode("ascii", errors="replace")
                if all(c.isprintable() or c in "\n\r\t" for c in preview_text[:8]):
                    raw["lsb_decoded_ascii_preview"] = preview_text[:100]
            except Exception:
                pass

            evidence.append(
                _stego_evidence(
                    inp=input,
                    source_tool=SourceTool.STEGO_LSB,
                    api_endpoint=LSB_ENDPOINT,
                    extractor="lsb.bit_plane",
                    claim=f"LSB anomaly detected in {name} (ratio={ratio:.3f}, deviation={deviation:.3f})",
                    claim_type=ClaimType.STEGANOGRAPHY,
                    value={
                        "artifact_name": name,
                        "method": "lsb_bit_plane",
                        "detection_confidence": confidence_label,
                        "lsb_ratio": round(ratio, 4),
                        "deviation_from_expected": round(deviation, 4),
                        "sample_pixels": total_lsb,
                    },
                    raw_response=raw,
                    weight=weight,
                )
            )

            if preview_text and len(preview_text.strip()) > 3:
                evidence.append(
                    _stego_evidence(
                        inp=input,
                        source_tool=SourceTool.STEGO_LSB,
                        api_endpoint=LSB_ENDPOINT,
                        extractor="lsb.decode",
                        claim=f"LSB-decoded content in {name} ({len(byte_data)} bytes extracted)",
                        claim_type=ClaimType.STEGO_EMBEDDED,
                        value={
                            "artifact_name": name,
                            "method": "lsb_decode",
                            "payload_size": len(byte_data),
                            "payload_preview": preview_text[:200],
                        },
                        raw_response=raw,
                        weight=weight * 0.8,
                    )
                )

        else:
            evidence.append(
                _stego_evidence(
                    inp=input,
                    source_tool=SourceTool.STEGO_LSB,
                    api_endpoint=LSB_ENDPOINT,
                    extractor="lsb.bit_plane",
                    claim=f"No LSB anomaly in {name} (ratio={ratio:.3f}, clean)",
                    claim_type=ClaimType.STEGANOGRAPHY,
                    value={
                        "artifact_name": name,
                        "method": "lsb_bit_plane",
                        "detection_confidence": "none",
                        "lsb_ratio": round(ratio, 4),
                        "deviation_from_expected": round(deviation, 4),
                    },
                    raw_response=raw,
                    weight=weight * 0.4,
                    requires_review=False,
                    review_reason=None,
                )
            )

        return evidence


async def stego_upload_endpoint(
    *,
    audit: AuditLogger,
    target: str,
    analyst_id: str,
    session_id: str,
    original_filename: str,
    data: bytes,
    engine: str = "auto",
    password: str = "",
) -> StegoOutput:
    """Write ``data`` to a temp file and run stego analysis."""
    settings = get_settings()
    if len(data) > settings.stego_max_upload_bytes:
        return StegoOutput(
            evidence=[],
            error=f"File too large ({len(data)} bytes); max {settings.stego_max_upload_bytes}",
        )

    resolved = engine.strip().lower() if engine else "auto"
    if resolved not in ("stegoveritas", "lsb", "auto"):
        return StegoOutput(evidence=[], error="Invalid engine — use stegoveritas, lsb, or auto")

    mode = resolved if resolved != "auto" else settings.stego_engine

    path_str: str | None = None
    try:
        fd, path_str = tempfile.mkstemp(prefix="grond-stego-", suffix=_suffix(original_filename))
        os.close(fd)
        path = Path(path_str)
        path.write_bytes(data)

        inp = StegoInput(
            target=target or "artifact",
            analyst_id=analyst_id,
            session_id=session_id,
            query=f"stego:{original_filename}",
            file_path=str(path.resolve()),
            original_filename=original_filename,
            engine=mode,
            password=password,
        )

        if mode == "stegoveritas":
            if not _stegoveritas_available():
                return StegoOutput(
                    evidence=[],
                    error="stegoVeritas CLI not found. Install: pip install stegoveritas && stegoveritas_install_deps",
                )
            evidence = await StegoVeritasAdapter(audit=audit).run(inp)
            return StegoOutput(evidence=evidence, error=None)

        if mode == "lsb":
            if not _pillow_available():
                return StegoOutput(
                    evidence=[],
                    error="Pillow not installed (pip install Pillow). Required for LSB analysis.",
                )
            evidence = await LSBFallbackAdapter(audit=audit).run(inp)
            return StegoOutput(evidence=evidence, error=None)

        if _stegoveritas_available():
            try:
                evidence = await StegoVeritasAdapter(audit=audit).run(inp)
                return StegoOutput(evidence=evidence, error=None)
            except ToolExecutionError:
                pass

        if _pillow_available():
            evidence = await LSBFallbackAdapter(audit=audit).run(inp)
            return StegoOutput(evidence=evidence, error=None)

        return StegoOutput(
            evidence=[],
            error="No stego engine available. Install stegoVeritas (pip install stegoveritas) or Pillow (pip install Pillow).",
        )

    except ToolExecutionError as exc:
        return StegoOutput(evidence=[], error=str(exc))
    finally:
        if path_str and Path(path_str).exists():
            Path(path_str).unlink(missing_ok=True)
