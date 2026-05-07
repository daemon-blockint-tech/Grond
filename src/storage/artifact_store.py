"""
ArtifactStore — S3-compatible object storage for raw scan outputs and reports.

Works with MinIO (self-hosted), Cloudflare R2, or AWS S3.
Configure via environment variables:
    S3_ENDPOINT       — e.g. http://localhost:9000 (omit for AWS S3)
    S3_BUCKET         — default: grond-artifacts
    S3_ACCESS_KEY     — access key ID
    S3_SECRET_KEY     — secret access key
    S3_REGION         — default: us-east-1

Key layout:
    {session_id}/raw/{tool}/{timestamp}.json      — raw API responses
    {session_id}/reports/{report_id}.pdf          — PDF reports
    {session_id}/reports/{report_id}.stix.json    — STIX bundles
    {session_id}/evidence.json                    — full evidence JSON
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import BinaryIO

import structlog

log = structlog.get_logger(__name__)


class ArtifactStore:
    """
    Async S3-compatible artifact storage.
    Uses aiobotocore under the hood (AsyncIO wrapper around botocore).
    """

    def __init__(self) -> None:
        self._bucket = os.environ.get("S3_BUCKET", "grond-artifacts")
        self._endpoint = os.environ.get("S3_ENDPOINT")
        self._region = os.environ.get("S3_REGION", "us-east-1")

    def _client(self):  # type: ignore[no-untyped-def]
        import aiobotocore.session  # noqa: PLC0415

        session = aiobotocore.session.get_session()
        kwargs = dict(
            service_name="s3",
            region_name=self._region,
            aws_access_key_id=os.environ.get("S3_ACCESS_KEY"),
            aws_secret_access_key=os.environ.get("S3_SECRET_KEY"),
        )
        if self._endpoint:
            kwargs["endpoint_url"] = self._endpoint
        return session.create_client(**kwargs)

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    async def save_raw_response(
        self, session_id: str, tool: str, payload: dict
    ) -> str:
        """Save a raw API response JSON and return the S3 key."""
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        key = f"{session_id}/raw/{tool}/{ts}.json"
        body = json.dumps(payload, default=str).encode()
        await self._put(key, body, "application/json")
        log.info("artifact.saved", key=key, size=len(body))
        return key

    async def save_report_pdf(
        self, session_id: str, report_id: str, pdf_bytes: bytes
    ) -> str:
        key = f"{session_id}/reports/{report_id}.pdf"
        await self._put(key, pdf_bytes, "application/pdf")
        log.info("artifact.saved", key=key, size=len(pdf_bytes))
        return key

    async def save_report_stix(
        self, session_id: str, report_id: str, stix_bundle: dict
    ) -> str:
        key = f"{session_id}/reports/{report_id}.stix.json"
        body = json.dumps(stix_bundle, default=str).encode()
        await self._put(key, body, "application/json")
        log.info("artifact.saved", key=key, size=len(body))
        return key

    async def save_evidence_snapshot(
        self, session_id: str, evidence: list[dict]
    ) -> str:
        key = f"{session_id}/evidence.json"
        body = json.dumps(evidence, default=str).encode()
        await self._put(key, body, "application/json")
        return key

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    async def get_object(self, key: str) -> bytes:
        async with self._client() as s3:
            response = await s3.get_object(Bucket=self._bucket, Key=key)
            async with response["Body"] as stream:
                return await stream.read()

    async def generate_presigned_url(self, key: str, expires_in: int = 3600) -> str:
        """Return a time-limited pre-signed download URL."""
        async with self._client() as s3:
            url: str = await s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": self._bucket, "Key": key},
                ExpiresIn=expires_in,
            )
            return url

    async def list_session_artifacts(self, session_id: str) -> list[str]:
        """List all artifact keys for a session."""
        async with self._client() as s3:
            paginator = s3.get_paginator("list_objects_v2")
            keys: list[str] = []
            async for page in paginator.paginate(
                Bucket=self._bucket, Prefix=f"{session_id}/"
            ):
                for obj in page.get("Contents", []):
                    keys.append(obj["Key"])
            return keys

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _put(self, key: str, body: bytes, content_type: str) -> None:
        async with self._client() as s3:
            try:
                await s3.head_bucket(Bucket=self._bucket)
            except Exception:  # noqa: BLE001
                await s3.create_bucket(Bucket=self._bucket)
            await s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
            )
