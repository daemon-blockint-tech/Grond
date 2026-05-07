"""
EmbeddingIndexer — converts Evidence claims into vector embeddings.

Supports two backends (selected via EMBEDDING_BACKEND env var):
  - "pgvector"  : stores embeddings in PostgreSQL `evidence_vectors` table
  - "qdrant"    : stores embeddings in Qdrant collection "evidence"

Embedding model: sentence-transformers/all-MiniLM-L6-v2 (384 dimensions, local)
This avoids API cost for what is primarily short text (claim strings).
"""

from __future__ import annotations

import os
from typing import Literal

import structlog
from sentence_transformers import SentenceTransformer

from src.models.evidence import Evidence

log = structlog.get_logger(__name__)

EmbeddingBackend = Literal["pgvector", "qdrant"]

_MODEL: SentenceTransformer | None = None
_BACKEND: EmbeddingBackend = os.environ.get("EMBEDDING_BACKEND", "pgvector")  # type: ignore[assignment]


def _get_model() -> SentenceTransformer:
    global _MODEL
    if _MODEL is None:
        model_name = os.environ.get(
            "EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
        )
        _MODEL = SentenceTransformer(model_name)
        log.info("embedding.model_loaded", model=model_name)
    return _MODEL


def embed_claim(claim: str) -> list[float]:
    """Convert a claim string to a float vector."""
    model = _get_model()
    vec = model.encode(claim, normalize_embeddings=True)
    return vec.tolist()


class EmbeddingIndexer:
    """Writes evidence vectors to the configured backend."""

    def __init__(self) -> None:
        self._backend: EmbeddingBackend = _BACKEND

    async def index_batch(self, evidence: list[Evidence], session_id: str) -> None:
        log.info(
            "embedding.index_batch.start",
            backend=self._backend,
            count=len(evidence),
            session_id=session_id,
        )
        if self._backend == "pgvector":
            await self._index_pgvector(evidence, session_id)
        else:
            await self._index_qdrant(evidence, session_id)
        log.info("embedding.index_batch.done", session_id=session_id)

    # ------------------------------------------------------------------
    # pgvector backend
    # ------------------------------------------------------------------

    async def _index_pgvector(self, evidence: list[Evidence], session_id: str) -> None:
        import asyncpg  # noqa: PLC0415

        dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_vectors (
                    id          UUID PRIMARY KEY,
                    session_id  TEXT NOT NULL,
                    target      TEXT NOT NULL,
                    claim_type  TEXT NOT NULL,
                    claim       TEXT NOT NULL,
                    confidence  FLOAT NOT NULL,
                    embedding   vector(384)
                )
                """
            )
            rows = [
                (
                    str(ev.id),
                    session_id,
                    ev.target,
                    ev.claim_type,
                    ev.claim,
                    float(ev.confidence),
                    str(embed_claim(ev.claim)),
                )
                for ev in evidence
            ]
            await conn.executemany(
                """
                INSERT INTO evidence_vectors
                  (id, session_id, target, claim_type, claim, confidence, embedding)
                VALUES ($1, $2, $3, $4, $5, $6, $7::vector)
                ON CONFLICT (id) DO UPDATE SET confidence = EXCLUDED.confidence
                """,
                rows,
            )
        finally:
            await conn.close()

    # ------------------------------------------------------------------
    # Qdrant backend
    # ------------------------------------------------------------------

    async def _index_qdrant(self, evidence: list[Evidence], session_id: str) -> None:
        from qdrant_client import AsyncQdrantClient  # noqa: PLC0415
        from qdrant_client.models import Distance, VectorParams, PointStruct  # noqa: PLC0415

        client = AsyncQdrantClient(url=os.environ.get("QDRANT_URL", "http://localhost:6333"))
        collection = "evidence"

        # Ensure collection exists
        collections = await client.get_collections()
        names = {c.name for c in collections.collections}
        if collection not in names:
            await client.create_collection(
                collection,
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )

        points = [
            PointStruct(
                id=str(ev.id),
                vector=embed_claim(ev.claim),
                payload={
                    "session_id": session_id,
                    "target": ev.target,
                    "claim_type": ev.claim_type,
                    "claim": ev.claim,
                    "confidence": float(ev.confidence),
                },
            )
            for ev in evidence
        ]
        await client.upsert(collection_name=collection, points=points)
        await client.close()
