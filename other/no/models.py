from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class CaseDocument:
    doc_id: str
    cve_id: str
    custom_id: str
    title: str
    summary: str
    reason: str
    evidence_text: str
    content: str
    language: str | None
    source_type: str | None
    project: str | None
    vendor: str | None
    published_year: int | None
    github_repo: str | None
    patch_file: str | None
    patch_owner: str | None
    patch_repo: str | None
    patch_commit: str | None
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    sanitizer_names: tuple[str, ...] = field(default_factory=tuple)
    attack_surfaces: tuple[str, ...] = field(default_factory=tuple)
    defense_mechanisms: tuple[str, ...] = field(default_factory=tuple)
    failure_modes: tuple[str, ...] = field(default_factory=tuple)
    search_text: str = ""
    raw_record_json: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SearchFilters:
    languages: tuple[str, ...] = field(default_factory=tuple)
    source_types: tuple[str, ...] = field(default_factory=tuple)
    sanitizer_names: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    projects: tuple[str, ...] = field(default_factory=tuple)
    vendors: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "languages": list(self.languages),
            "source_types": list(self.source_types),
            "sanitizer_names": list(self.sanitizer_names),
            "cwe_ids": list(self.cwe_ids),
            "projects": list(self.projects),
            "vendors": list(self.vendors),
        }


@dataclass(frozen=True)
class SearchResult:
    doc_id: str
    cve_id: str
    score: float
    bm25_score: float
    rerank_score: float
    title: str
    summary: str
    matched_fields: dict[str, list[str]]
    reason: str
    sanitizer_names: tuple[str, ...]
    source_type: str | None
    language: str | None
    cwe_ids: tuple[str, ...]
    project: str | None
    vendor: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SearchResponse:
    query: str
    rewritten_terms: tuple[str, ...]
    applied_filters: dict[str, list[str]]
    results: tuple[SearchResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "rewritten_terms": list(self.rewritten_terms),
            "applied_filters": self.applied_filters,
            "results": [item.to_dict() for item in self.results],
        }


@dataclass(frozen=True)
class IndexBuildSummary:
    output_db_path: str
    indexed_records: int
    source_label_records: int
    merged_source_labels: int
    schema_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
