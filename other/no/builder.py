from __future__ import annotations

import json
import re
import sqlite3
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .constants import (
    ATTACK_SURFACE_PATTERNS,
    DEFAULT_DB_FILENAME,
    DEFENSE_MECHANISM_PATTERNS,
    FAILURE_MODE_PATTERNS,
    KNOWN_SOURCE_TYPES,
    LANGUAGE_ALIASES,
    QUERY_EXPANSIONS,
    SCHEMA_VERSION,
    SOURCE_TYPE_ALIASES,
)
from .models import CaseDocument, IndexBuildSummary

IDENTIFIER_RE = re.compile(r"`([^`]{1,80})`")
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
SPACE_RE = re.compile(r"\s+")
NON_NAME_RE = re.compile(r"[^A-Za-z0-9_:.#+\-()]+")


def default_db_path() -> Path:
    return Path(__file__).resolve().with_name(DEFAULT_DB_FILENAME)


def build_index(
    input_json: str | Path,
    source_labels_jsonl: str | Path,
    output_db_path: str | Path | None = None,
    *,
    force: bool = False,
) -> IndexBuildSummary:
    input_path = Path(input_json)
    labels_path = Path(source_labels_jsonl)
    db_path = Path(output_db_path) if output_db_path else default_db_path()

    records = _load_main_records(input_path)
    labels_by_custom_id = _load_source_labels(labels_path)

    if db_path.exists():
        if not force:
            raise FileExistsError(f"Output database already exists: {db_path}")
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    merged_source_labels = 0
    try:
        _ensure_fts5_available(conn)
        _create_schema(conn)
        case_docs: list[CaseDocument] = []
        for record in records:
            label = labels_by_custom_id.get(str(record.get("custom_id") or ""))
            if label:
                merged_source_labels += 1
            case_docs.append(_build_case_document(record, label))
        _insert_case_documents(conn, case_docs)
        _write_metadata(
            conn,
            input_path=input_path,
            labels_path=labels_path,
            indexed_records=len(case_docs),
            merged_source_labels=merged_source_labels,
            source_label_records=len(labels_by_custom_id),
        )
        conn.commit()
    finally:
        conn.close()

    return IndexBuildSummary(
        output_db_path=str(db_path),
        indexed_records=len(records),
        source_label_records=len(labels_by_custom_id),
        merged_source_labels=merged_source_labels,
        schema_version=SCHEMA_VERSION,
    )


def _load_main_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array in {path}")
    return [item for item in data if isinstance(item, dict)]


def _load_source_labels(path: Path) -> dict[str, dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                continue
            custom_id = str(payload.get("custom_id") or payload.get("record_id") or "").strip()
            if custom_id:
                labels[custom_id] = payload
    return labels


def _build_case_document(record: dict[str, Any], label: dict[str, Any] | None) -> CaseDocument:
    cve_id = str(record.get("cve_id") or "").strip()
    custom_id = str(record.get("custom_id") or record.get("record_id") or cve_id).strip()
    selected_patch = record.get("selected_patch") if isinstance(record.get("selected_patch"), dict) else {}

    reason = clean_text(str(record.get("reason") or ""))
    evidence_values = record.get("evidence") if isinstance(record.get("evidence"), list) else []
    evidence_text = clean_text(" | ".join(str(item) for item in evidence_values if item))
    content = clean_text(str(record.get("content") or ""))
    combined_text = "\n".join(part for part in (reason, evidence_text, content) if part)

    sanitizer_names = normalize_sanitizer_names(label.get("sanitizer_names") if label else None)
    if not sanitizer_names:
        sanitizer_names = extract_identifier_candidates(reason, evidence_text)

    source_type = normalize_source_type(label.get("source_type") if label else record.get("source_type"))
    language = normalize_language(record.get("language"))
    cwe_ids = normalize_cwe_ids(record.get("cwe_ids"))

    attack_surfaces = infer_tags(combined_text, ATTACK_SURFACE_PATTERNS)
    defense_mechanisms = infer_tags(
        "\n".join([combined_text, " ".join(sanitizer_names)]),
        DEFENSE_MECHANISM_PATTERNS,
    )
    failure_modes = infer_tags(combined_text, FAILURE_MODE_PATTERNS)

    project = normalize_optional_text(record.get("project"))
    vendor = normalize_optional_text(record.get("vendor"))
    github_repo = normalize_optional_text(record.get("github_repo"))

    title = build_title(cve_id, project, vendor, sanitizer_names)
    summary = build_summary(reason, attack_surfaces, failure_modes)
    search_text = build_search_text(
        title=title,
        summary=summary,
        reason=reason,
        evidence_text=evidence_text,
        content=content,
        language=language,
        source_type=source_type,
        project=project,
        vendor=vendor,
        cwe_ids=cwe_ids,
        sanitizer_names=sanitizer_names,
        attack_surfaces=attack_surfaces,
        defense_mechanisms=defense_mechanisms,
        failure_modes=failure_modes,
    )

    return CaseDocument(
        doc_id=custom_id,
        cve_id=cve_id,
        custom_id=custom_id,
        title=title,
        summary=summary,
        reason=reason,
        evidence_text=evidence_text,
        content=content,
        language=language,
        source_type=source_type,
        project=project,
        vendor=vendor,
        published_year=normalize_year(record.get("published_year")),
        github_repo=github_repo,
        patch_file=normalize_optional_text(selected_patch.get("patch_file")),
        patch_owner=normalize_optional_text(selected_patch.get("patch_owner")),
        patch_repo=normalize_optional_text(selected_patch.get("patch_repo")),
        patch_commit=normalize_optional_text(selected_patch.get("patch_commit")),
        cwe_ids=cwe_ids,
        sanitizer_names=sanitizer_names,
        attack_surfaces=attack_surfaces,
        defense_mechanisms=defense_mechanisms,
        failure_modes=failure_modes,
        search_text=search_text,
        raw_record_json=json.dumps(record, ensure_ascii=False, sort_keys=True),
    )


def _ensure_fts5_available(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_check USING fts5(text)")
        conn.execute("DROP TABLE IF EXISTS _fts5_check")
    except sqlite3.OperationalError as exc:
        raise RuntimeError("SQLite FTS5 is required but unavailable in this runtime") from exc


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE cases (
            doc_id TEXT PRIMARY KEY,
            cve_id TEXT NOT NULL,
            custom_id TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_text TEXT NOT NULL,
            content TEXT NOT NULL,
            language TEXT,
            source_type TEXT,
            project TEXT,
            vendor TEXT,
            published_year INTEGER,
            github_repo TEXT,
            patch_file TEXT,
            patch_owner TEXT,
            patch_repo TEXT,
            patch_commit TEXT,
            cwe_ids_json TEXT NOT NULL,
            sanitizer_names_json TEXT NOT NULL,
            attack_surfaces_json TEXT NOT NULL,
            defense_mechanisms_json TEXT NOT NULL,
            failure_modes_json TEXT NOT NULL,
            search_text TEXT NOT NULL,
            raw_record_json TEXT NOT NULL
        );

        CREATE INDEX idx_cases_language ON cases(language);
        CREATE INDEX idx_cases_source_type ON cases(source_type);
        CREATE INDEX idx_cases_project ON cases(project);
        CREATE INDEX idx_cases_vendor ON cases(vendor);
        CREATE INDEX idx_cases_published_year ON cases(published_year);

        CREATE TABLE case_cwe (
            doc_id TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX idx_case_cwe_value ON case_cwe(value);

        CREATE TABLE case_sanitizer (
            doc_id TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX idx_case_sanitizer_value ON case_sanitizer(value);

        CREATE TABLE case_attack_surface (
            doc_id TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX idx_case_attack_surface_value ON case_attack_surface(value);

        CREATE TABLE case_defense_mechanism (
            doc_id TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX idx_case_defense_mechanism_value ON case_defense_mechanism(value);

        CREATE TABLE case_failure_mode (
            doc_id TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX idx_case_failure_mode_value ON case_failure_mode(value);

        CREATE VIRTUAL TABLE cases_fts USING fts5(
            doc_id UNINDEXED,
            title,
            summary,
            sanitizer_names_text,
            reason,
            evidence_text,
            content,
            search_text,
            tokenize = 'unicode61'
        );

        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )


def _insert_case_documents(conn: sqlite3.Connection, case_docs: Iterable[CaseDocument]) -> None:
    case_rows = []
    fts_rows = []
    cwe_rows = []
    sanitizer_rows = []
    attack_rows = []
    defense_rows = []
    failure_rows = []

    for doc in case_docs:
        case_rows.append(
            (
                doc.doc_id,
                doc.cve_id,
                doc.custom_id,
                doc.title,
                doc.summary,
                doc.reason,
                doc.evidence_text,
                doc.content,
                doc.language,
                doc.source_type,
                doc.project,
                doc.vendor,
                doc.published_year,
                doc.github_repo,
                doc.patch_file,
                doc.patch_owner,
                doc.patch_repo,
                doc.patch_commit,
                json.dumps(doc.cwe_ids, ensure_ascii=False),
                json.dumps(doc.sanitizer_names, ensure_ascii=False),
                json.dumps(doc.attack_surfaces, ensure_ascii=False),
                json.dumps(doc.defense_mechanisms, ensure_ascii=False),
                json.dumps(doc.failure_modes, ensure_ascii=False),
                doc.search_text,
                doc.raw_record_json,
            )
        )
        fts_rows.append(
            (
                doc.doc_id,
                doc.title,
                doc.summary,
                " ".join(doc.sanitizer_names),
                doc.reason,
                doc.evidence_text,
                doc.content,
                doc.search_text,
            )
        )
        cwe_rows.extend((doc.doc_id, value) for value in doc.cwe_ids)
        sanitizer_rows.extend((doc.doc_id, value.lower()) for value in doc.sanitizer_names)
        attack_rows.extend((doc.doc_id, value) for value in doc.attack_surfaces)
        defense_rows.extend((doc.doc_id, value) for value in doc.defense_mechanisms)
        failure_rows.extend((doc.doc_id, value) for value in doc.failure_modes)

    conn.executemany(
        """
        INSERT INTO cases (
            doc_id, cve_id, custom_id, title, summary, reason, evidence_text, content,
            language, source_type, project, vendor, published_year, github_repo,
            patch_file, patch_owner, patch_repo, patch_commit, cwe_ids_json,
            sanitizer_names_json, attack_surfaces_json, defense_mechanisms_json,
            failure_modes_json, search_text, raw_record_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        case_rows,
    )
    conn.executemany(
        "INSERT INTO cases_fts (doc_id, title, summary, sanitizer_names_text, reason, evidence_text, content, search_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        fts_rows,
    )
    conn.executemany("INSERT INTO case_cwe (doc_id, value) VALUES (?, ?)", cwe_rows)
    conn.executemany("INSERT INTO case_sanitizer (doc_id, value) VALUES (?, ?)", sanitizer_rows)
    conn.executemany("INSERT INTO case_attack_surface (doc_id, value) VALUES (?, ?)", attack_rows)
    conn.executemany("INSERT INTO case_defense_mechanism (doc_id, value) VALUES (?, ?)", defense_rows)
    conn.executemany("INSERT INTO case_failure_mode (doc_id, value) VALUES (?, ?)", failure_rows)


def _write_metadata(
    conn: sqlite3.Connection,
    *,
    input_path: Path,
    labels_path: Path,
    indexed_records: int,
    merged_source_labels: int,
    source_label_records: int,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    metadata_rows = [
        ("schema_version", SCHEMA_VERSION),
        ("built_at_utc", now),
        ("input_json", str(input_path)),
        ("source_labels_jsonl", str(labels_path)),
        ("indexed_records", str(indexed_records)),
        ("source_label_records", str(source_label_records)),
        ("merged_source_labels", str(merged_source_labels)),
    ]
    conn.executemany("INSERT INTO metadata (key, value) VALUES (?, ?)", metadata_rows)


def clean_text(value: str) -> str:
    text = value.replace("```", " ").replace("`", " ")
    text = text.replace("\r", " ").replace("\n", " ")
    text = SPACE_RE.sub(" ", text)
    return text.strip()


def normalize_optional_text(value: Any) -> str | None:
    text = clean_text(str(value or ""))
    return text or None


def normalize_year(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_language(value: Any) -> str | None:
    text = clean_text(str(value or "")).lower()
    if not text:
        return None
    return LANGUAGE_ALIASES.get(text, text)


def normalize_source_type(value: Any) -> str | None:
    text = clean_text(str(value or "")).lower()
    if not text:
        return None
    normalized = SOURCE_TYPE_ALIASES.get(text, text)
    return normalized if normalized in KNOWN_SOURCE_TYPES else normalized


def normalize_cwe_ids(value: Any) -> tuple[str, ...]:
    items: list[str] = []
    if isinstance(value, list):
        for item in value:
            items.extend(CWE_RE.findall(str(item)))
    else:
        items.extend(CWE_RE.findall(str(value or "")))
    ordered: OrderedDict[str, None] = OrderedDict()
    for item in items:
        ordered[item.upper()] = None
    return tuple(ordered.keys())


def normalize_sanitizer_names(values: Any) -> tuple[str, ...]:
    if not values:
        return ()
    if not isinstance(values, list):
        values = [values]
    ordered: OrderedDict[str, str] = OrderedDict()
    for raw_value in values:
        cleaned = clean_identifier(str(raw_value or ""))
        if not cleaned:
            continue
        ordered.setdefault(cleaned.lower(), cleaned)
    return tuple(ordered.values())


def clean_identifier(value: str) -> str:
    text = clean_text(value).strip("\"'")
    if text.endswith("()"):
        text = text[:-2]
    text = NON_NAME_RE.sub("", text)
    text = text.strip("._:- ")
    if not text:
        return ""
    if text.upper().startswith("CVE-") or text.upper().startswith("CWE-"):
        return ""
    return text


def extract_identifier_candidates(*texts: str) -> tuple[str, ...]:
    ordered: OrderedDict[str, str] = OrderedDict()
    for text in texts:
        for match in IDENTIFIER_RE.findall(text):
            cleaned = clean_identifier(match)
            if not cleaned:
                continue
            if " " in cleaned or len(cleaned) < 3:
                continue
            ordered.setdefault(cleaned.lower(), cleaned)
    return tuple(list(ordered.values())[:6])


def infer_tags(text: str, pattern_map: dict[str, list[str]]) -> tuple[str, ...]:
    lowered = text.lower()
    tags = [key for key, patterns in pattern_map.items() if any(pattern.lower() in lowered for pattern in patterns)]
    return tuple(tags)


def build_title(cve_id: str, project: str | None, vendor: str | None, sanitizer_names: tuple[str, ...]) -> str:
    scope = project or vendor or "unknown-project"
    sanitizer_part = ", ".join(sanitizer_names[:2]) if sanitizer_names else "unknown-sanitizer"
    return f"{cve_id} incomplete sanitizer in {scope} / {sanitizer_part}"


def build_summary(reason: str, attack_surfaces: tuple[str, ...], failure_modes: tuple[str, ...]) -> str:
    pieces = []
    if reason:
        pieces.append(reason)
    if attack_surfaces:
        pieces.append("attack=" + "/".join(attack_surfaces))
    if failure_modes:
        pieces.append("failure=" + "/".join(failure_modes))
    text = "; ".join(pieces)
    if len(text) > 320:
        return text[:317].rstrip() + "..."
    return text


def build_search_text(
    *,
    title: str,
    summary: str,
    reason: str,
    evidence_text: str,
    content: str,
    language: str | None,
    source_type: str | None,
    project: str | None,
    vendor: str | None,
    cwe_ids: tuple[str, ...],
    sanitizer_names: tuple[str, ...],
    attack_surfaces: tuple[str, ...],
    defense_mechanisms: tuple[str, ...],
    failure_modes: tuple[str, ...],
) -> str:
    parts = [
        title,
        summary,
        reason,
        evidence_text,
        content,
        language or "",
        source_type or "",
        project or "",
        vendor or "",
        " ".join(cwe_ids),
        " ".join(sanitizer_names),
        " ".join(attack_surfaces),
        " ".join(defense_mechanisms),
        " ".join(failure_modes),
    ]
    for tag in attack_surfaces + defense_mechanisms + failure_modes:
        parts.extend(QUERY_EXPANSIONS.get(tag, []))
    return clean_text(" ".join(part for part in parts if part))
