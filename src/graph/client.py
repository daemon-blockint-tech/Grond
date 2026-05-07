"""
Neo4j graph client — async context manager wrapping the neo4j-python driver.

Graph schema:
    (:Target   {name, type, created_at})
    (:IPAddress {ip, asn, country, org})
    (:Port     {number, protocol})
    (:Service  {product, version})
    (:CVE      {id, cvss, severity, description})
    (:Domain   {name})
    (:Organization {name})
    (:WebMention   {url, title, snippet})

Relationships:
    (Target)-[:RESOLVES_TO]->(IPAddress)
    (Target)-[:MENTIONED_IN]->(WebMention)
    (IPAddress)-[:EXPOSED_ON]->(Port)
    (Port)-[:RUNS]->(Service)
    (Port)-[:AFFECTED_BY]->(CVE)
    (IPAddress)-[:BELONGS_TO]->(Organization)
    (Domain)-[:RESOLVES_TO]->(IPAddress)
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Any

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession


_driver: AsyncDriver | None = None


def _get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "password")
        _driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    return _driver


class GraphClient:
    """Thin async wrapper around the Neo4j driver session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @asynccontextmanager
    @staticmethod
    async def connect() -> AsyncGenerator["GraphClient", None]:
        driver = _get_driver()
        async with driver.session() as s:
            yield GraphClient(s)

    async def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        result = await self._session.run(query, params)
        records = await result.data()
        return records

    async def run_write(self, query: str, **params: Any) -> None:
        await self._session.run(query, params)

    async def close_driver(self) -> None:
        if _driver:
            await _driver.close()


async def get_graph_client() -> AsyncGenerator[GraphClient, None]:
    """FastAPI dependency that yields a GraphClient session."""
    async with GraphClient.connect() as client:
        yield client
