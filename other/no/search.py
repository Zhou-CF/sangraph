from __future__ import annotations

import json
import sqlite3
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
import re

from .builder import default_db_path, normalize_cwe_ids, normalize_language, normalize_source_type
from .constants import (
    ATTACK_SURFACE_PATTERNS,
    DEFENSE_MECHANISM_PATTERNS,
    FAILURE_MODE_PATTERNS,
    LANGUAGE_ALIASES,
    QUERY_EXPANSIONS,
    SCHEMA_VERSION,
    SOURCE_TYPE_ALIASES,
)
from .models import SearchFilters, SearchResponse, SearchResult

TOKEN_RE = re.compile(r"[A-Za-z0-9_:.#+\-/]{2,}")
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedQuery:
    rewritten_terms: tuple[str, ...]
    languages: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    source_types: tuple[str, ...]
    sanitizer_names: tuple[str, ...]
    attack_surfaces: tuple[str, ...]
    defense_mechanisms: tuple[str, ...]
    failure_modes: tuple[str, ...]
    projects: tuple[str, ...]
    vendors: tuple[str, ...]


class SanitizerCaseSearcher:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else default_db_path()
        if not self.db_path.exists():
            raise FileNotFoundError(f"Index database not found: {self.db_path}")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._validate_schema()
        self._sanitizer_vocab: dict[str, str] | None = None
        self._project_vocab: dict[str, str] | None = None
        self._vendor_vocab: dict[str, str] | None = None

    def close(self) -> None:
        self.conn.close()

    def search_cases(
        self,
        query: str,
        *,
        top_k: int = 10,
        filters: SearchFilters | None = None,
    ) -> SearchResponse:
        query = (query or "").strip()
        if not query:
            raise ValueError("query must not be empty")

        normalized_filters = normalize_filters(filters)
        parsed = self._parse_query(query, normalized_filters)
        applied_filters = build_applied_filters(parsed, normalized_filters)
        rows = self._retrieve_candidates(parsed, applied_filters, candidate_limit=max(top_k * 10, 50))
        results = self._rerank_rows(rows, parsed, normalized_filters, top_k=top_k)
        return SearchResponse(
            query=query,
            rewritten_terms=parsed.rewritten_terms,
            applied_filters=applied_filters,
            results=tuple(results),
        )

    def _validate_schema(self) -> None:
        row = self.conn.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone()
        if row is None:
            raise RuntimeError("Invalid sanitizer RAG index: missing schema_version metadata")
        if str(row[0]) != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported sanitizer RAG index schema version: {row[0]} (expected {SCHEMA_VERSION})"
            )

    def _parse_query(self, query: str, filters: SearchFilters) -> ParsedQuery:
        lowered = query.lower()
        ordered_terms: OrderedDict[str, None] = OrderedDict()
        languages = OrderedDict((item, None) for item in filters.languages)
        cwe_ids = OrderedDict((item, None) for item in filters.cwe_ids)
        source_types = OrderedDict((item, None) for item in filters.source_types)
        sanitizer_names = OrderedDict((item, None) for item in filters.sanitizer_names)
        projects = OrderedDict((item, None) for item in filters.projects)
        vendors = OrderedDict((item, None) for item in filters.vendors)

        for token in TOKEN_RE.findall(query):
            ordered_terms.setdefault(token, None)

        for alias, canonical in LANGUAGE_ALIASES.items():
            if contains_alias(lowered, alias):
                languages.setdefault(canonical, None)
                ordered_terms.setdefault(canonical, None)

        for cwe in CWE_RE.findall(query):
            canonical = cwe.upper()
            cwe_ids.setdefault(canonical, None)
            ordered_terms.setdefault(canonical, None)

        for alias, canonical in SOURCE_TYPE_ALIASES.items():
            if contains_alias(lowered, alias):
                source_types.setdefault(canonical, None)
                ordered_terms.setdefault(canonical, None)

        for term in self._match_vocab(lowered, self._load_sanitizer_vocab()):
            sanitizer_names.setdefault(term, None)
            ordered_terms.setdefault(term, None)

        for term in self._match_vocab(lowered, self._load_project_vocab()):
            projects.setdefault(term, None)
            ordered_terms.setdefault(term, None)

        for term in self._match_vocab(lowered, self._load_vendor_vocab()):
            vendors.setdefault(term, None)
            ordered_terms.setdefault(term, None)

        attack_surfaces = detect_query_tags(lowered, ATTACK_SURFACE_PATTERNS)
        defense_mechanisms = detect_query_tags(lowered, DEFENSE_MECHANISM_PATTERNS)
        failure_modes = detect_query_tags(lowered, FAILURE_MODE_PATTERNS)

        for collection in (attack_surfaces, defense_mechanisms, failure_modes):
            for tag in collection:
                ordered_terms.setdefault(tag, None)
                for synonym in QUERY_EXPANSIONS.get(tag, []):
                    ordered_terms.setdefault(synonym, None)

        return ParsedQuery(
            rewritten_terms=tuple(ordered_terms.keys()),
            languages=tuple(languages.keys()),
            cwe_ids=tuple(cwe_ids.keys()),
            source_types=tuple(source_types.keys()),
            sanitizer_names=tuple(sanitizer_names.keys()),
            attack_surfaces=attack_surfaces,
            defense_mechanisms=defense_mechanisms,
            failure_modes=failure_modes,
            projects=tuple(projects.keys()),
            vendors=tuple(vendors.keys()),
        )

    def _retrieve_candidates(
        self,
        parsed: ParsedQuery,
        applied_filters: dict[str, list[str]],
        *,
        candidate_limit: int,
    ) -> list[sqlite3.Row]:
        filter_clauses: list[str] = []
        filter_params: list[str] = []

        if applied_filters["languages"]:
            filter_clauses.append(sql_in_clause("c.language", applied_filters["languages"]))
            filter_params.extend(applied_filters["languages"])
        if applied_filters["source_types"]:
            filter_clauses.append(sql_in_clause("c.source_type", applied_filters["source_types"]))
            filter_params.extend(applied_filters["source_types"])
        if applied_filters["projects"]:
            filter_clauses.append(sql_in_clause("c.project", applied_filters["projects"]))
            filter_params.extend(applied_filters["projects"])
        if applied_filters["vendors"]:
            filter_clauses.append(sql_in_clause("c.vendor", applied_filters["vendors"]))
            filter_params.extend(applied_filters["vendors"])
        if applied_filters["cwe_ids"]:
            filter_clauses.append(exists_in_clause("case_cwe", "value", applied_filters["cwe_ids"]))
            filter_params.extend(applied_filters["cwe_ids"])
        if applied_filters["sanitizer_names"]:
            lowered_names = [item.lower() for item in applied_filters["sanitizer_names"]]
            filter_clauses.append(exists_in_clause("case_sanitizer", "value", lowered_names))
            filter_params.extend(lowered_names)

        where_sql = ""
        if filter_clauses:
            where_sql = " AND " + " AND ".join(filter_clauses)

        fts_query = build_fts_query(parsed.rewritten_terms)
        if fts_query:
            sql = f"""
                SELECT c.*, bm25(cases_fts, 8.0, 5.0, 10.0, 4.0, 3.0, 1.0, 2.0) AS raw_bm25
                FROM cases_fts
                JOIN cases c ON c.doc_id = cases_fts.doc_id
                WHERE cases_fts MATCH ? {where_sql}
                ORDER BY raw_bm25 ASC
                LIMIT ?
            """
            params = [fts_query, *filter_params, candidate_limit]
            return list(self.conn.execute(sql, params))

        sql = f"""
            SELECT c.*, NULL AS raw_bm25
            FROM cases c
            WHERE 1=1 {where_sql}
            ORDER BY c.published_year DESC, c.cve_id ASC
            LIMIT ?
        """
        params = [*filter_params, candidate_limit]
        return list(self.conn.execute(sql, params))

    def _rerank_rows(
        self,
        rows: list[sqlite3.Row],
        parsed: ParsedQuery,
        filters: SearchFilters,
        *,
        top_k: int,
    ) -> list[SearchResult]:
        results: list[SearchResult] = []
        total = max(len(rows), 1)
        filter_sanitizers = {item.lower() for item in filters.sanitizer_names}
        filter_projects = set(filters.projects)
        filter_vendors = set(filters.vendors)
        for index, row in enumerate(rows):
            bm25_rank_score = max(0.0, (total - index) / total) * 5.0
            rerank_score = 0.0
            matched_fields: dict[str, list[str]] = {}

            sanitizer_names = tuple(json.loads(row["sanitizer_names_json"]))
            cwe_ids = tuple(json.loads(row["cwe_ids_json"]))
            attack_surfaces = tuple(json.loads(row["attack_surfaces_json"]))
            defense_mechanisms = tuple(json.loads(row["defense_mechanisms_json"]))
            failure_modes = tuple(json.loads(row["failure_modes_json"]))
            search_text_lower = str(row["search_text"] or "").lower()

            sanitizer_overlap = overlap_lower(parsed.sanitizer_names, sanitizer_names)
            if sanitizer_overlap:
                rerank_score += 4.0
                matched_fields["sanitizer_names"] = sanitizer_overlap
            elif filter_sanitizers and overlap_lower(filter_sanitizers, sanitizer_names):
                rerank_score += 4.0
                matched_fields["sanitizer_names"] = overlap_lower(filter_sanitizers, sanitizer_names)

            if parsed.languages and row["language"] in parsed.languages:
                rerank_score += 1.5
                matched_fields["languages"] = [row["language"]]
            if parsed.cwe_ids:
                cwe_overlap = intersect(parsed.cwe_ids, cwe_ids)
                if cwe_overlap:
                    rerank_score += 1.5
                    matched_fields["cwe_ids"] = cwe_overlap
            if parsed.source_types and row["source_type"] in parsed.source_types:
                rerank_score += 1.0
                matched_fields["source_types"] = [row["source_type"]]
            if parsed.projects and row["project"] in parsed.projects:
                rerank_score += 0.8
                matched_fields["projects"] = [row["project"]]
            elif filter_projects and row["project"] in filter_projects:
                rerank_score += 0.8
                matched_fields["projects"] = [row["project"]]
            if parsed.vendors and row["vendor"] in parsed.vendors:
                rerank_score += 0.8
                matched_fields["vendors"] = [row["vendor"]]
            elif filter_vendors and row["vendor"] in filter_vendors:
                rerank_score += 0.8
                matched_fields["vendors"] = [row["vendor"]]

            attack_overlap = intersect(parsed.attack_surfaces, attack_surfaces)
            if attack_overlap:
                rerank_score += 1.5
                matched_fields["attack_surfaces"] = attack_overlap

            defense_overlap = intersect(parsed.defense_mechanisms, defense_mechanisms)
            if defense_overlap:
                rerank_score += 1.0
                matched_fields["defense_mechanisms"] = defense_overlap

            failure_overlap = intersect(parsed.failure_modes, failure_modes)
            if failure_overlap:
                rerank_score += 1.5
                matched_fields["failure_modes"] = failure_overlap

            text_hits = [term for term in parsed.rewritten_terms if term.lower() in search_text_lower]
            if text_hits:
                rerank_score += min(1.5, 0.15 * len(text_hits))
                matched_fields["text_terms"] = text_hits[:10]

            final_score = round(bm25_rank_score + rerank_score, 4)
            results.append(
                SearchResult(
                    doc_id=row["doc_id"],
                    cve_id=row["cve_id"],
                    score=final_score,
                    bm25_score=round(bm25_rank_score, 4),
                    rerank_score=round(rerank_score, 4),
                    title=row["title"],
                    summary=row["summary"],
                    matched_fields=matched_fields,
                    reason=row["reason"],
                    sanitizer_names=sanitizer_names,
                    source_type=row["source_type"],
                    language=row["language"],
                    cwe_ids=cwe_ids,
                    project=row["project"],
                    vendor=row["vendor"],
                )
            )

        results.sort(key=lambda item: (-item.score, item.cve_id))
        return results[:top_k]

    def _load_sanitizer_vocab(self) -> dict[str, str]:
        if self._sanitizer_vocab is None:
            rows = self.conn.execute("SELECT DISTINCT value FROM case_sanitizer").fetchall()
            self._sanitizer_vocab = {str(row[0]).lower(): str(row[0]) for row in rows}
        return self._sanitizer_vocab

    def _load_project_vocab(self) -> dict[str, str]:
        if self._project_vocab is None:
            rows = self.conn.execute("SELECT DISTINCT project FROM cases WHERE project IS NOT NULL AND project != ''").fetchall()
            self._project_vocab = {str(row[0]).lower(): str(row[0]) for row in rows if row[0]}
        return self._project_vocab

    def _load_vendor_vocab(self) -> dict[str, str]:
        if self._vendor_vocab is None:
            rows = self.conn.execute("SELECT DISTINCT vendor FROM cases WHERE vendor IS NOT NULL AND vendor != ''").fetchall()
            self._vendor_vocab = {str(row[0]).lower(): str(row[0]) for row in rows if row[0]}
        return self._vendor_vocab

    @staticmethod
    def _match_vocab(lowered_query: str, vocab: dict[str, str]) -> list[str]:
        matched: list[str] = []
        for key, canonical in vocab.items():
            if len(key) < 3:
                continue
            if key in lowered_query:
                matched.append(canonical)
        matched.sort(key=len, reverse=True)
        return matched[:6]


def normalize_filters(filters: SearchFilters | None) -> SearchFilters:
    if filters is None:
        return SearchFilters()
    return SearchFilters(
        languages=tuple(dict.fromkeys(filter(None, (normalize_language(item) for item in filters.languages))).keys()),
        source_types=tuple(dict.fromkeys(filter(None, (normalize_source_type(item) for item in filters.source_types))).keys()),
        sanitizer_names=tuple(dict.fromkeys(str(item).strip() for item in filters.sanitizer_names if str(item).strip()).keys()),
        cwe_ids=normalize_cwe_ids(list(filters.cwe_ids)),
        projects=tuple(dict.fromkeys(str(item).strip() for item in filters.projects if str(item).strip()).keys()),
        vendors=tuple(dict.fromkeys(str(item).strip() for item in filters.vendors if str(item).strip()).keys()),
    )


def build_applied_filters(parsed: ParsedQuery, filters: SearchFilters) -> dict[str, list[str]]:
    return {
        "languages": list(parsed.languages or filters.languages),
        "source_types": list(parsed.source_types or filters.source_types),
        "sanitizer_names": list(filters.sanitizer_names),
        "cwe_ids": list(parsed.cwe_ids or filters.cwe_ids),
        "projects": list(filters.projects),
        "vendors": list(filters.vendors),
    }


def build_fts_query(terms: tuple[str, ...]) -> str:
    sanitized = []
    for term in terms:
        cleaned = str(term or "").strip().replace('"', " ")
        if len(cleaned) < 2:
            continue
        sanitized.append(f'"{cleaned}"')
    return " OR ".join(dict.fromkeys(sanitized).keys())


def sql_in_clause(column: str, values: list[str]) -> str:
    placeholders = ", ".join("?" for _ in values)
    return f"{column} IN ({placeholders})"


def exists_in_clause(table_name: str, value_column: str, values: list[str]) -> str:
    placeholders = ", ".join("?" for _ in values)
    return (
        f"EXISTS (SELECT 1 FROM {table_name} t WHERE t.doc_id = c.doc_id AND t.{value_column} IN ({placeholders}))"
    )


def detect_query_tags(lowered_query: str, pattern_map: dict[str, list[str]]) -> tuple[str, ...]:
    tags = [key for key, patterns in pattern_map.items() if any(pattern.lower() in lowered_query for pattern in patterns)]
    return tuple(tags)


def contains_alias(lowered_query: str, alias: str) -> bool:
    alias = alias.lower()
    if not alias:
        return False
    if any(ord(char) > 127 for char in alias):
        return alias in lowered_query
    if re.fullmatch(r"[a-z0-9_+#.-]+", alias):
        pattern = rf"(?<![a-z0-9_]){re.escape(alias)}(?![a-z0-9_])"
        return re.search(pattern, lowered_query) is not None
    return alias in lowered_query


def intersect(left: tuple[str, ...] | list[str], right: tuple[str, ...] | list[str]) -> list[str]:
    right_set = set(right)
    return [item for item in left if item in right_set]


def overlap_lower(left: tuple[str, ...] | list[str] | set[str], right: tuple[str, ...] | list[str]) -> list[str]:
    right_map = {item.lower(): item for item in right}
    return [right_map[item.lower()] for item in left if item.lower() in right_map]


def open_index(db_path: str | Path | None = None) -> SanitizerCaseSearcher:
    return SanitizerCaseSearcher(db_path=db_path)


def search_cases(
    query: str,
    *,
    top_k: int = 10,
    filters: SearchFilters | None = None,
    db_path: str | Path | None = None,
) -> SearchResponse:
    searcher = SanitizerCaseSearcher(db_path=db_path)
    try:
        return searcher.search_cases(query, top_k=top_k, filters=filters)
    finally:
        searcher.close()
