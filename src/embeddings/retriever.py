"""
EvidenceRetriever — semantic search over indexed evidence.

Use this to answer analyst queries like:
  "find all evidence about credential exposure"
  "what do we know about this CVE across all sessions?"
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import structlog

from .indexer import embed_claim, _BACKEND

log = structlog.get_logger(__name__)


@dataclass
class RetrievedEvidence:
    id: str
    session_id: str
    target: str
    claim_type: str
    claim: str
    confidence: float
    score: float  # similarity score 0–1


class EvidenceRetriever:
    """Semantic search over embedded evidence."""

    async def search(
        self,
        query: str,
        top_k: int = 10,
        session_id: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[RetrievedEvidence]:
        """Find evidence semantically similar to a natural-language query."""
        vector = embed_claim(query)
        if _BACKEND == "pgvector":
            return await self._search_pgvector(vector, top_k, session_id, min_confidence)
        return await self._search_qdrant(vector, top_k, session_id, min_confidence)

    async def _search_pgvector(
        self,
        vector: list[float],
        top_k: int,
        session_id: str | None,
        min_confidence: float,
    ) -> list[RetrievedEvidence]:
        import asyncpg  # noqa: PLC0415

        dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
        conn = await asyncpg.connect(dsn)
        try:
            where_clauses = ["confidence >= $3"]
            params: list = [str(vector), top_k, min_confidence]
            if session_id:
                where_clauses.append(f"session_id = ${len(params) + 1}")
                params.append(session_id)

            rows = await conn.fetch(
                f"""
                SELECT id, session_id, target, claim_type, claim, confidence,
                       1 - (embedding <=> $1::vector) AS score
                FROM evidence_vectors
                WHERE {' AND '.join(where_clauses)}
                ORDER BY score DESC
                LIMIT $2
                """,
                *params,
            )
            return [
                RetrievedEvidence(
                    id=str(r["id"]),
                    session_id=r["session_id"],
                    target=r["target"],
                    claim_type=r["claim_type"],
                    claim=r["claim"],
                    confidence=float(r["confidence"]),
                    score=float(r["score"]),
                )
                for r in rows
            ]
        finally:
            await conn.close()

    async def _search_qdrant(
        self,
        vector: list[float],
        top_k: int,
        session_id: str | None,
        min_confidence: float,
    ) -> list[RetrievedEvidence]:
        from qdrant_client import AsyncQdrantClient  # noqa: PLC0415
        from qdrant_client.models import Filter, FieldCondition, MatchValue, Range  # noqa: PLC0415

        client = AsyncQdrantClient(url=os.environ.get("QDRANT_URL", "http://localhost:6333"))
        try:
            conditions = [
                FieldCondition(key="confidence", range=Range(gte=min_confidence))
            ]
            if session_id:
                conditions.append(
                    FieldCondition(key="session_id", match=MatchValue(value=session_id))
                )

            results = await client.search(
                collection_name="evidence",
                query_vector=vector,
                limit=top_k,
                query_filter=Filter(must=conditions),
            )
            return [
                RetrievedEvidence(
                    id=str(r.id),
                    session_id=r.payload["session_id"],  # type: ignore[index]
                    target=r.payload["target"],  # type: ignore[index]
                    claim_type=r.payload["claim_type"],  # type: ignore[index]
                    claim=r.payload["claim"],  # type: ignore[index]
                    confidence=float(r.payload["confidence"]),  # type: ignore[index]
                    score=float(r.score),
                )
                for r in results
            ]
        finally:
            await client.close()
