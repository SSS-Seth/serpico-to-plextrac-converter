#!/usr/bin/env python3
"""Convert Serpico backup/export data into a PlexTrac findings CSV.

The converter is intentionally dependency-light. It handles JSON, JSONL, ZIP,
and tar archives with the Python standard library. MongoDB BSON dumps are also
supported when the optional ``pymongo`` package is installed.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import re
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PLEXTRAC_HEADERS = [
    "title",
    "severity",
    "status",
    "description",
    "recommendations",
    "references",
    "affected_assets",
    "tags",
    "cvss_temporal",
    "cwe",
    "cve",
    "category",
]

CUSTOM_HEADERS = [
    "serpico_id",
    "serpico_source",
    "serpico_path",
    "serpico_report",
]

SEVERITIES = {
    "informational": "Informational",
    "info": "Informational",
    "none": "Informational",
    "low": "Low",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "high": "High",
    "critical": "Critical",
    "crit": "Critical",
}

STATUS_VALUES = {"open": "Open", "closed": "Closed", "in process": "In Process"}

FIELD_CANDIDATES = {
    "title": ("title", "name", "finding", "vulnerability", "vuln", "issue_name"),
    "severity": ("severity", "risk", "risk_rating", "risk_level", "rating", "impact"),
    "description": (
        "description",
        "desc",
        "overview",
        "executive_summary",
        "summary",
        "issue",
        "details",
        "observation",
    ),
    "recommendations": (
        "recommendations",
        "recommendation",
        "remediation",
        "remediations",
        "solution",
        "mitigation",
        "fix",
    ),
    "references": ("references", "refs", "reference", "links", "external_references"),
    "affected_assets": (
        "affected_assets",
        "assets",
        "affected_hosts",
        "hosts",
        "hostnames",
        "targets",
        "systems",
        "ip",
        "ip_address",
        "hostname",
        "url",
        "urls",
    ),
    "cvss_temporal": ("cvss_temporal", "cvss", "cvss_score", "risk_score", "score"),
    "cwe": ("cwe", "cwes"),
    "cve": ("cve", "cves"),
    "category": ("category", "type", "finding_type", "classification"),
    "serpico_report": ("report", "report_name", "report_title", "project", "project_name"),
}

HTML_TAG_RE = re.compile(r"<[^>]+>")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{2,4}\b", re.IGNORECASE)


@dataclass
class SourceRecord:
    source: str
    path: str
    data: dict[str, Any]


@dataclass
class Diagnostics:
    loaded_documents: int = 0
    candidate_documents: int = 0
    written_findings: int = 0
    skipped: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "\n".join(part for part in (clean_text(item) for item in value) if part)
    if isinstance(value, dict):
        simple = []
        for key, item in value.items():
            rendered = clean_text(item)
            if rendered:
                simple.append(f"{key}: {rendered}")
        return "\n".join(simple)

    text = str(value)
    text = html.unescape(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = HTML_TAG_RE.sub("", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def scalar_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        pieces = re.split(r"[\n;]+", value)
        return [clean_text(piece) for piece in pieces if clean_text(piece)]
    if isinstance(value, dict):
        return [clean_text(value)]
    if isinstance(value, Iterable):
        items: list[str] = []
        for item in value:
            items.extend(scalar_list(item))
        return [item for item in items if item]
    return [clean_text(value)]


def csv_multi(value: Any) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for item in scalar_list(value):
        normalized = item.strip()
        if normalized and normalized.lower() not in seen:
            seen.add(normalized.lower())
            out.append(normalized)
    return ", ".join(out)


def lower_key_map(document: dict[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(key) for key in document}


def first_value(document: dict[str, Any], names: Iterable[str]) -> Any:
    keys = lower_key_map(document)
    for name in names:
        real_key = keys.get(name.lower())
        if real_key is not None:
            value = document.get(real_key)
            if value not in (None, "", [], {}):
                return value
    return None


def normalize_severity(raw: Any, default: str = "Informational") -> str:
    text = clean_text(raw).lower()
    if not text:
        return default
    if text in SEVERITIES:
        return SEVERITIES[text]

    match = re.search(r"\d+(?:\.\d+)?", text)
    if match:
        score = float(match.group(0))
        if score <= 0:
            return "Informational"
        if score < 4:
            return "Low"
        if score < 7:
            return "Medium"
        if score < 9:
            return "High"
        return "Critical"

    for needle, severity in SEVERITIES.items():
        if needle in text:
            return severity
    return default


def normalize_status(raw: str) -> str:
    status = clean_text(raw).lower()
    return STATUS_VALUES.get(status, "Open")


def find_identifiers(document: dict[str, Any], pattern: re.Pattern[str], fields: tuple[str, ...]) -> str:
    explicit = csv_multi(first_value(document, fields))
    haystack = "\n".join(
        clean_text(value)
        for value in (
            explicit,
            first_value(document, FIELD_CANDIDATES["title"]),
            first_value(document, FIELD_CANDIDATES["description"]),
            first_value(document, FIELD_CANDIDATES["references"]),
        )
        if value
    )
    found = sorted({match.upper() for match in pattern.findall(haystack)})
    return ", ".join(found)


def record_id(document: dict[str, Any]) -> str:
    for key in ("_id", "id", "oid", "finding_id", "template_id"):
        if key in document:
            return clean_text(document[key])
    return ""


def map_record(record: SourceRecord, default_status: str, tags: list[str]) -> tuple[dict[str, str], list[str]]:
    doc = record.data
    title = clean_text(first_value(doc, FIELD_CANDIDATES["title"]))
    description = clean_text(first_value(doc, FIELD_CANDIDATES["description"]))
    recommendations = clean_text(first_value(doc, FIELD_CANDIDATES["recommendations"]))
    references = csv_multi(first_value(doc, FIELD_CANDIDATES["references"]))
    affected_assets = csv_multi(first_value(doc, FIELD_CANDIDATES["affected_assets"]))
    severity = normalize_severity(first_value(doc, FIELD_CANDIDATES["severity"]))
    cvss = clean_text(first_value(doc, FIELD_CANDIDATES["cvss_temporal"]))

    row = {
        "title": title,
        "severity": severity,
        "status": normalize_status(clean_text(doc.get("status", default_status))),
        "description": description,
        "recommendations": recommendations,
        "references": references,
        "affected_assets": affected_assets,
        "tags": csv_multi([*tags, first_value(doc, ("tags", "tag", "labels"))]),
        "cvss_temporal": cvss,
        "cwe": find_identifiers(doc, CWE_RE, FIELD_CANDIDATES["cwe"]),
        "cve": find_identifiers(doc, CVE_RE, FIELD_CANDIDATES["cve"]),
        "category": clean_text(first_value(doc, FIELD_CANDIDATES["category"])),
        "serpico_id": record_id(doc),
        "serpico_source": record.source,
        "serpico_path": record.path,
        "serpico_report": clean_text(first_value(doc, FIELD_CANDIDATES["serpico_report"])),
    }

    missing = [name for name in ("title", "description") if not row[name]]
    return row, missing


def looks_like_finding(path: str, document: dict[str, Any]) -> bool:
    path_l = path.lower()
    keys = {str(key).lower() for key in document}
    has_title = any(key in keys for key in FIELD_CANDIDATES["title"])
    has_body = any(
        key in keys
        for key in (
            *FIELD_CANDIDATES["description"],
            *FIELD_CANDIDATES["recommendations"],
            *FIELD_CANDIDATES["severity"],
        )
    )
    path_hint = any(token in path_l for token in ("finding", "vuln", "issue", "template"))
    return bool(has_title and (has_body or path_hint))


def walk_documents(value: Any, source: str, path: str = "$") -> Iterator[SourceRecord]:
    if isinstance(value, dict):
        yield SourceRecord(source=source, path=path, data=value)
        for key, item in value.items():
            yield from walk_documents(item, source, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_documents(item, source, f"{path}[{index}]")


def parse_json_bytes(content: bytes, source: str) -> Iterator[SourceRecord]:
    text = content.decode("utf-8-sig")
    stripped = text.strip()
    if not stripped:
        return

    try:
        value = json.loads(stripped)
        yield from walk_documents(value, source)
        return
    except json.JSONDecodeError:
        pass

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{line_no}: invalid JSON line: {exc}") from exc
        yield from walk_documents(value, source, f"$[{line_no}]")


def parse_bson_bytes(content: bytes, source: str) -> Iterator[SourceRecord]:
    try:
        from bson import decode_all
        from bson.json_util import dumps
    except ImportError as exc:
        raise RuntimeError(
            f"{source} is BSON. Install optional support with: python -m pip install pymongo"
        ) from exc

    decoded = json.loads(dumps(decode_all(content)))
    yield from walk_documents(decoded, source)


def records_from_file(path: Path, diagnostics: Diagnostics) -> Iterator[SourceRecord]:
    suffixes = "".join(path.suffixes).lower()
    if path.is_dir():
        for child in sorted(item for item in path.rglob("*") if item.is_file()):
            yield from records_from_file(child, diagnostics)
        return

    if suffixes.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.endswith("/"):
                    continue
                with archive.open(name) as member:
                    yield from records_from_bytes(member.read(), f"{path}!{name}", diagnostics)
        return

    if suffixes.endswith((".tar", ".tar.gz", ".tgz")):
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                file_obj = archive.extractfile(member)
                if file_obj is None:
                    continue
                yield from records_from_bytes(file_obj.read(), f"{path}!{member.name}", diagnostics)
        return

    yield from records_from_bytes(path.read_bytes(), str(path), diagnostics)


def records_from_bytes(content: bytes, source: str, diagnostics: Diagnostics) -> Iterator[SourceRecord]:
    lower = source.lower()
    try:
        if lower.endswith((".json", ".jsonl", ".ndjson")):
            yield from parse_json_bytes(content, source)
        elif lower.endswith(".bson"):
            yield from parse_bson_bytes(content, source)
        else:
            diagnostics.warnings.append(f"Skipped unsupported file type: {source}")
    except Exception as exc:
        diagnostics.warnings.append(f"Could not parse {source}: {exc}")


def convert(args: argparse.Namespace) -> Diagnostics:
    diagnostics = Diagnostics()
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    collection_re = re.compile(args.collection_pattern, re.IGNORECASE) if args.collection_pattern else None

    for record in records_from_file(args.input, diagnostics):
        diagnostics.loaded_documents += 1
        if collection_re and not collection_re.search(record.source):
            continue
        if not looks_like_finding(record.path, record.data):
            continue
        diagnostics.candidate_documents += 1
        row, missing = map_record(record, args.status, args.tag)
        key = (row["serpico_source"], row["serpico_id"], row["title"])
        if key in seen:
            continue
        seen.add(key)

        if missing:
            diagnostics.skipped.append(
                {
                    "source": record.source,
                    "path": record.path,
                    "reason": f"missing required field(s): {', '.join(missing)}",
                }
            )
            if args.strict:
                continue
        rows.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*PLEXTRAC_HEADERS, *CUSTOM_HEADERS])
        writer.writeheader()
        writer.writerows(rows)

    diagnostics.written_findings = len(rows)
    if args.diagnostics:
        args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
        args.diagnostics.write_text(
            json.dumps(diagnostics.__dict__, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert Serpico backup/export data to PlexTrac report findings CSV."
    )
    parser.add_argument("input", type=Path, help="Serpico backup file, archive, or directory.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("plextrac_findings.csv"),
        help="Output PlexTrac CSV path. Default: plextrac_findings.csv",
    )
    parser.add_argument(
        "--diagnostics",
        type=Path,
        default=Path("conversion_diagnostics.json"),
        help="Write parse/mapping diagnostics JSON. Default: conversion_diagnostics.json",
    )
    parser.add_argument(
        "--status",
        default="Open",
        choices=("Open", "Closed", "In Process"),
        help="Default PlexTrac finding status. Default: Open",
    )
    parser.add_argument(
        "--tag",
        action="append",
        default=[],
        help="Tag to add to every finding. Can be passed multiple times.",
    )
    parser.add_argument(
        "--collection-pattern",
        help="Optional regex filter for source filenames, e.g. findings|report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Skip rows missing PlexTrac-required title or description.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    diagnostics = convert(args)

    print(f"Loaded documents: {diagnostics.loaded_documents}")
    print(f"Candidate findings: {diagnostics.candidate_documents}")
    print(f"Wrote findings: {diagnostics.written_findings}")
    if diagnostics.skipped:
        print(f"Rows with missing required fields: {len(diagnostics.skipped)}")
    if diagnostics.warnings:
        print(f"Warnings: {len(diagnostics.warnings)}")
    print(f"CSV: {args.output}")
    if args.diagnostics:
        print(f"Diagnostics: {args.diagnostics}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
