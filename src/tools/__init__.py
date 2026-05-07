from .base import RateLimiter, ToolAdapter
from .harvester_tool import (
    HarvesterAdapter,
    HarvesterInput,
    HarvesterOutput,
    harvest_json_to_evidence,
)
from .metadata_tool import (
    ExiftoolMetadataAdapter,
    Exiv2MetadataAdapter,
    MetadataExtractionInput,
    MetadataToolOutput,
    exiftool_available,
    exiv2_available,
    metadata_upload_endpoint,
)
from .nmap_tool import NmapAdapter, NmapInput, ScanProfile
from .shodan_tool import ShodanAdapter, ShodanInput
from .tavily_tool import (
    TavilyAdapter,
    TavilyExtractAdapter,
    TavilyExtractInput,
    TavilyExtractOutput,
    TavilyInput,
    TavilySearchOutput,
)
from .twitter_query_builder import (
    OsintIntent,
    TwitterOsintTemplates,
    TwitterQueryBuilder,
)

__all__ = [
    "RateLimiter",
    "ToolAdapter",
    "NmapAdapter",
    "NmapInput",
    "ScanProfile",
    "HarvesterAdapter",
    "HarvesterInput",
    "HarvesterOutput",
    "harvest_json_to_evidence",
    "ExiftoolMetadataAdapter",
    "Exiv2MetadataAdapter",
    "MetadataExtractionInput",
    "MetadataToolOutput",
    "exiftool_available",
    "exiv2_available",
    "metadata_upload_endpoint",
    "ShodanAdapter",
    "ShodanInput",
    "TavilyAdapter",
    "TavilyExtractAdapter",
    "TavilyExtractInput",
    "TavilyExtractOutput",
    "TavilyInput",
    "TavilySearchOutput",
    "TwitterAdapter",
    "TwitterInput",
    "TwitterOutput",
    "OsintIntent",
    "TwitterOsintTemplates",
    "TwitterQueryBuilder",
]


def __getattr__(name: str):
    if name in ("TwitterAdapter", "TwitterInput", "TwitterOutput"):
        from .twitter_tool import TwitterAdapter, TwitterInput, TwitterOutput

        return {
            "TwitterAdapter": TwitterAdapter,
            "TwitterInput": TwitterInput,
            "TwitterOutput": TwitterOutput,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
