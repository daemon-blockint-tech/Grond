"""
File metadata adapters (subprocess CLIs).

- **ExifTool** (`exiftool -json`): broad format coverage; same stack as Metaforge
  ( https://github.com/chriswmorris/Metaforge ).
- **Exiv2** (`exiv2 print -pa`): image-focused Exif / IPTC / XMP / ICC metadata
  ( https://github.com/Exiv2/exiv2 , https://exiv2.org ).

Grond maps CLI output to ``Evidence``; it does not bundle upstream GPL report UIs.

**Passive:** analyst uploads a file they are authorized to analyze.
Flag PII/GPS-rich metadata via ``ClaimType.FILE_METADATA`` + review gates.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.audit import AuditLogger
from src.core.config import get_settings
from src.core.exceptions import ToolExecutionError
from src.exiv2_pa_parse import parse_exiv2_print_a
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTier, SourceTool
from src.tools.base import ToolAdapter

EXIFTOOL_JSON_ENDPOINT = "local:exiftool-json"
EXIV2_PRINT_ENDPOINT = "local:exiv2-print-pa"

# ---------------------------------------------------------------------------
# Input / output (HTTP / orchestration)
# ---------------------------------------------------------------------------


class MetadataExtractionInput(BaseModel):
    """Analyze one file on disk (usually a temp path from an upload handler)."""

    target: str = Field(..., min_length=1, description="Investigation / case label")
    analyst_id: str
    session_id: str
    query: str = Field(default="", description="Audit label; defaults to filename")
    file_path: str = Field(..., min_length=1, description="Absolute path to readable file")
    original_filename: str = Field(
        default="upload",
        description="Original client filename for provenance and claims",
    )


class MetadataToolOutput(BaseModel):
    evidence: list[Evidence]
    error: str | None = None


# ---------------------------------------------------------------------------
# Shared Evidence builder
# ---------------------------------------------------------------------------


def _infer_format(tags: dict[str, Any], filename: str) -> str:
    for k in ("FileType", "MIMEType", "Exif.Image.MIMEType"):
        v = tags.get(k)
        if v not in (None, "", "-"):
            return str(v)
    ext = Path(filename).suffix.lstrip(".").lower()
    return ext or "unknown"


def _summarize_tags(tags: dict[str, Any], max_pairs: int = 14) -> str:
    """Human-readable listing of high-signal tags (ExifTool flat + Exiv2 dotted keys)."""
    priority = (
        "FileName",
        "FileType",
        "MIMEType",
        "ImageSize",
        "Exif.Image.ImageWidth",
        "Exif.Image.ImageLength",
        "Exif.Photo.PixelXDimension",
        "Exif.Photo.PixelYDimension",
        "Make",
        "Exif.Image.Make",
        "Exif.Photo.Make",
        "Model",
        "Exif.Image.Model",
        "Exif.Photo.LensModel",
        "Software",
        "Exif.Image.Software",
        "CreatorTool",
        "CreateDate",
        "Exif.Photo.DateTimeOriginal",
        "DateTimeOriginal",
        "GPSLatitude",
        "Exif.GPSInfo.GPSLatitude",
        "GPSLongitude",
        "Exif.GPSInfo.GPSLongitude",
        "GPSPosition",
        "Artist",
        "Author",
        "Title",
        "Subject",
    )
    lines: list[str] = []
    seen: set[str] = set()
    for key in priority:
        if key in tags and tags[key] not in (None, "", "-"):
            lines.append(f"{key}: {tags[key]}")
            seen.add(key)
        if len(lines) >= max_pairs:
            break
    if len(lines) < max_pairs:
        for k, v in tags.items():
            if k in seen or v in (None, "", "-"):
                continue
            lines.append(f"{k}: {v}")
            if len(lines) >= max_pairs:
                break
    extra = len(tags) - len({line.split(":", 1)[0].strip() for line in lines})
    if extra > 0:
        lines.append(f"(+{extra} additional tags)")
    return "\n".join(lines)


def _file_metadata_evidence(
    *,
    tags: dict[str, Any],
    inp: MetadataExtractionInput,
    source_tool: SourceTool,
    api_endpoint: str,
    extractor: str,
    weight: float,
) -> list[Evidence]:
    coll_q = inp.query.strip() or Path(inp.original_filename).name
    collected_at = datetime.now(UTC)
    name = Path(inp.original_filename).name
    fmt = _infer_format(tags, name)
    summary = _summarize_tags(tags)
    snippet = summary[:800] if summary else json.dumps(tags, default=str)[:800]
    # Normalise for Provenance.raw_response (dict[str, Any])
    raw: dict[str, Any] = {str(k): v for k, v in tags.items()}

    prov = Provenance(
        source_tool=source_tool,
        source_tier=SourceTier.COMMUNITY,
        collection_query=coll_q,
        api_endpoint=api_endpoint,
        collected_at=collected_at,
        analyst_id=inp.analyst_id,
        session_id=inp.session_id,
        source_url=f"artifact://{name}",
        raw_snippet=snippet,
        extractor=extractor,
        raw_response=raw,
    )
    label = "exiv2" if source_tool == SourceTool.EXIV2 else "file"
    return [
        Evidence(
            target=inp.target,
            claim=f"File metadata ({label}) — {name}",
            claim_type=ClaimType.FILE_METADATA,
            value={
                "artifact_name": name,
                "format": fmt,
                "summary": summary,
                "tag_count": len(tags),
            },
            provenance=prov,
            confidence=round(weight * 0.92, 4),
            requires_review=True,
            review_reason="file_metadata_may_contain_pii_location_or_device_fingerprint",
        )
    ]


# ---------------------------------------------------------------------------
# ExifTool adapter
# ---------------------------------------------------------------------------


class ExiftoolMetadataAdapter(ToolAdapter[MetadataExtractionInput]):
    """Extract metadata tags via ExifTool JSON export."""

    tool_name = SourceTool.EXIFTOOL

    def __init__(
        self,
        audit: AuditLogger,
        *,
        exiftool_bin: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        super().__init__(audit=audit, rate_limiter=None)
        settings = get_settings()
        self._exiftool = exiftool_bin or settings.exiftool_bin
        self._timeout = timeout_seconds or settings.exiftool_timeout_seconds

    async def _execute(self, input: MetadataExtractionInput) -> list[Evidence]:
        path = Path(input.file_path).resolve()
        if not path.is_file():
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"File not found or not a file: {path}",
            )

        proc = await asyncio.create_subprocess_exec(
            self._exiftool,
            "-json",
            "-n",
            "-struct",
            str(path),
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
                message=f"ExifTool timed out after {self._timeout}s",
                cause=exc,
            ) from exc

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")[:500]
            if proc.returncode == 127 or "not found" in err.lower():
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message=(
                        f"ExifTool not runnable ({self._exiftool!r}). "
                        "Install from https://exiftool.org/"
                    ),
                )
            raise ToolExecutionError(
                tool=self.tool_name,
                message=err or f"ExifTool exit {proc.returncode}",
            )

        try:
            payload: list[dict[str, Any]] = json.loads(
                stdout.decode("utf-8", errors="replace")
            )
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="ExifTool returned invalid JSON",
                cause=exc,
            ) from exc

        if not payload:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="ExifTool returned no metadata objects",
            )

        tags = payload[0]
        weight = get_settings().confidence_weight_exiftool
        return _file_metadata_evidence(
            tags=tags,
            inp=input,
            source_tool=SourceTool.EXIFTOOL,
            api_endpoint=EXIFTOOL_JSON_ENDPOINT,
            extractor="exiftool.json",
            weight=weight,
        )


# ---------------------------------------------------------------------------
# Exiv2 adapter
# ---------------------------------------------------------------------------


class Exiv2MetadataAdapter(ToolAdapter[MetadataExtractionInput]):
    """Extract image metadata via the Exiv2 CLI (``print -pa``)."""

    tool_name = SourceTool.EXIV2

    def __init__(
        self,
        audit: AuditLogger,
        *,
        exiv2_bin: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        super().__init__(audit=audit, rate_limiter=None)
        settings = get_settings()
        self._exiv2 = exiv2_bin or settings.exiv2_bin
        self._timeout = timeout_seconds or settings.exiv2_timeout_seconds

    async def _execute(self, input: MetadataExtractionInput) -> list[Evidence]:
        path = Path(input.file_path).resolve()
        if not path.is_file():
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"File not found or not a file: {path}",
            )

        proc = await asyncio.create_subprocess_exec(
            self._exiv2,
            "print",
            "-pa",
            str(path),
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
                message=f"Exiv2 timed out after {self._timeout}s",
                cause=exc,
            ) from exc

        out_txt = stdout.decode("utf-8", errors="replace")
        err_txt = stderr.decode("utf-8", errors="replace")[:500]

        if proc.returncode != 0:
            if proc.returncode == 127 or "command not found" in err_txt.lower():
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message=(
                        f"Exiv2 not runnable ({self._exiv2!r}). "
                        "Install from https://exiv2.org or your package manager."
                    ),
                )
            raise ToolExecutionError(
                tool=self.tool_name,
                message=err_txt or f"Exiv2 exit {proc.returncode}",
            )

        tags = parse_exiv2_print_a(out_txt)
        if not tags:
            raise ToolExecutionError(
                tool=self.tool_name,
                message=(
                    "Exiv2 returned no parsed tags (unsupported format or stripped metadata). "
                    "Try metadata_engine=exiftool for non-image files."
                ),
            )

        weight = get_settings().confidence_weight_exiv2
        return _file_metadata_evidence(
            tags=tags,
            inp=input,
            source_tool=SourceTool.EXIV2,
            api_endpoint=EXIV2_PRINT_ENDPOINT,
            extractor="exiv2.print-pa",
            weight=weight,
        )


# ---------------------------------------------------------------------------
# Upload handler
# ---------------------------------------------------------------------------


def _suffix(name: str) -> str:
    p = Path(name)
    s = p.suffix
    if s and len(s) <= 16:
        return s
    return ""


def _normalise_engine(requested: str | None) -> str | None:
    if requested is None or str(requested).strip() == "":
        return None
    e = str(requested).strip().lower()
    if e in ("exiftool", "exiv2", "auto"):
        return e
    return "__invalid__"


async def metadata_upload_endpoint(
    *,
    audit: AuditLogger,
    target: str,
    analyst_id: str,
    session_id: str,
    original_filename: str,
    data: bytes,
    engine: str | None = None,
) -> MetadataToolOutput:
    """Write ``data`` to a temp file and run configured metadata CLI(s)."""
    settings = get_settings()
    if len(data) > settings.metadata_max_upload_bytes:
        return MetadataToolOutput(
            evidence=[],
            error=(
                f"File too large ({len(data)} bytes); "
                f"max {settings.metadata_max_upload_bytes}"
            ),
        )

    resolved = _normalise_engine(engine)
    if resolved == "__invalid__":
        return MetadataToolOutput(
            evidence=[],
            error="Invalid engine — use exiftool, exiv2, or auto",
        )

    mode = resolved if resolved is not None else settings.metadata_engine
    path_str: str | None = None
    try:
        fd, path_str = tempfile.mkstemp(
            prefix="grond-meta-", suffix=_suffix(original_filename)
        )
        os.close(fd)
        path = Path(path_str)
        path.write_bytes(data)
        inp = MetadataExtractionInput(
            target=target or "artifact",
            analyst_id=analyst_id,
            session_id=session_id,
            query=f"upload:{original_filename}",
            file_path=str(path.resolve()),
            original_filename=original_filename,
        )

        if mode == "exiftool":
            evidence = await ExiftoolMetadataAdapter(audit=audit).run(inp)
            return MetadataToolOutput(evidence=evidence, error=None)
        if mode == "exiv2":
            evidence = await Exiv2MetadataAdapter(audit=audit).run(inp)
            return MetadataToolOutput(evidence=evidence, error=None)

        # auto: prefer Exiv2 when binary is present, fall back to ExifTool
        if exiv2_available():
            try:
                evidence = await Exiv2MetadataAdapter(audit=audit).run(inp)
                return MetadataToolOutput(evidence=evidence, error=None)
            except ToolExecutionError:
                evidence = await ExiftoolMetadataAdapter(audit=audit).run(inp)
                return MetadataToolOutput(evidence=evidence, error=None)
        evidence = await ExiftoolMetadataAdapter(audit=audit).run(inp)
        return MetadataToolOutput(evidence=evidence, error=None)
    except ToolExecutionError as exc:
        return MetadataToolOutput(evidence=[], error=str(exc))
    finally:
        if path_str and Path(path_str).exists():
            Path(path_str).unlink(missing_ok=True)


def exiftool_available() -> bool:
    return shutil.which(get_settings().exiftool_bin) is not None


def exiv2_available() -> bool:
    return shutil.which(get_settings().exiv2_bin) is not None
