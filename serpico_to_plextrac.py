#!/usr/bin/env python3
"""Convert Serpico backup/export data into PlexTrac findings CSV files.

The converter is intentionally dependency-light. It handles JSON, JSONL, ZIP,
and tar archives with the Python standard library. MongoDB BSON dumps are also
supported when the optional ``pymongo`` package is installed.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import tarfile
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
    "serpico_client",
    "serpico_owner",
    "serpico_team",
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
    "serpico_report": (
        "report",
        "report_name",
        "report_title",
        "project",
        "project_name",
        "assessment",
        "assessment_name",
    ),
    "serpico_client": ("client", "client_name", "customer", "customer_name", "company"),
    "serpico_owner": (
        "owner",
        "owner_name",
        "report_owner",
        "created_by",
        "creator",
        "author",
        "user",
    ),
    "serpico_team": (
        "team",
        "team_name",
        "owner_team",
        "owning_team",
        "business_unit",
        "department",
        "practice",
    ),
}

HTML_TAG_RE = re.compile(r"<[^>]+>")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{2,4}\b", re.IGNORECASE)


@dataclass
class SourceRecord:
    source: str
    path: str
    data: dict[str, Any]
    context: dict[str, str] = field(default_factory=dict)


@dataclass
class Diagnostics:
    loaded_documents: int = 0
    candidate_documents: int = 0
    written_findings: int = 0
    written_files: int = 0
    scanned_files: int = 0
    parsed_files: int = 0
    unsupported_files: int = 0
    skipped: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unsupported_samples: list[str] = field(default_factory=list)
    unsupported_by_extension: dict[str, int] = field(default_factory=dict)


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


def first_contextual_value(document: dict[str, Any], context: dict[str, str], name: str) -> str:
    value = clean_text(first_value(document, FIELD_CANDIDATES[name]))
    if value:
        return value
    return context.get(name, "")


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


def extract_context(document: dict[str, Any], parent_context: dict[str, str]) -> dict[str, str]:
    context = dict(parent_context)
    for name in ("serpico_report", "serpico_client", "serpico_owner", "serpico_team"):
        value = clean_text(first_value(document, FIELD_CANDIDATES[name]))
        if value:
            context[name] = value
    return context


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
        "serpico_report": first_contextual_value(doc, record.context, "serpico_report"),
        "serpico_client": first_contextual_value(doc, record.context, "serpico_client"),
        "serpico_owner": first_contextual_value(doc, record.context, "serpico_owner"),
        "serpico_team": first_contextual_value(doc, record.context, "serpico_team"),
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


def walk_documents(
    value: Any,
    source: str,
    path: str = "$",
    context: dict[str, str] | None = None,
) -> Iterator[SourceRecord]:
    context = context or {}
    if isinstance(value, dict):
        next_context = extract_context(value, context)
        yield SourceRecord(source=source, path=path, data=value, context=next_context)
        for key, item in value.items():
            yield from walk_documents(item, source, f"{path}.{key}", next_context)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_documents(item, source, f"{path}[{index}]", context)


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


def looks_like_json(content: bytes) -> bool:
    stripped = content.lstrip()
    return stripped.startswith((b"{", b"["))


def parse_bson_bytes(content: bytes, source: str) -> Iterator[SourceRecord]:
    try:
        from bson import decode_all
        from bson.json_util import dumps
    except ImportError as exc:
        raise RuntimeError(
            f"{source} is BSON. Install optional support with: python -m pip install pymongo"
        ) from exc

    decoded = decode_all(content)
    if not decoded:
        raise ValueError("BSON file contained no documents")
    yield from walk_documents(json.loads(dumps(decoded)), source)


def extension_key(path: str) -> str:
    name = path.split("!", 1)[-1].lower()
    suffixes = "".join(Path(name).suffixes)
    return suffixes or "<no extension>"


def remember_unsupported(source: str, diagnostics: Diagnostics) -> None:
    diagnostics.unsupported_files += 1
    extension = extension_key(source)
    diagnostics.unsupported_by_extension[extension] = diagnostics.unsupported_by_extension.get(extension, 0) + 1
    if len(diagnostics.unsupported_samples) < 25:
        diagnostics.unsupported_samples.append(source)


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
    diagnostics.scanned_files += 1
    try:
        if lower.endswith((".json", ".jsonl", ".ndjson")):
            records = list(parse_json_bytes(content, source))
        elif lower.endswith(".bson"):
            records = list(parse_bson_bytes(content, source))
        elif looks_like_json(content):
            records = list(parse_json_bytes(content, source))
        else:
            remember_unsupported(source, diagnostics)
            return
        diagnostics.parsed_files += 1
        yield from records
    except Exception as exc:
        diagnostics.warnings.append(f"Could not parse {source}: {exc}")


def inspect_backup(path: Path) -> dict[str, Any]:
    files: list[Path] = []
    if path.is_dir():
        files = sorted(item for item in path.rglob("*") if item.is_file())
    elif path.is_file():
        files = [path]

    extensions: dict[str, int] = {}
    samples: dict[str, list[str]] = {}
    for file_path in files:
        key = "".join(file_path.suffixes).lower() or "<no extension>"
        extensions[key] = extensions.get(key, 0) + 1
        samples.setdefault(key, [])
        if len(samples[key]) < 5:
            samples[key].append(str(file_path))

    return {"root": str(path), "file_count": len(files), "extensions": extensions, "samples": samples}


def print_inspection(summary: dict[str, Any]) -> None:
    print(f"Inspected: {summary['root']}")
    print(f"Files: {summary['file_count']}")
    print("Extensions:")
    for extension, count in sorted(summary["extensions"].items(), key=lambda item: (-item[1], item[0])):
        print(f"  {extension}: {count}")
        for sample in summary["samples"][extension]:
            print(f"    {sample}")


def collect_rows(args: argparse.Namespace, diagnostics: Diagnostics) -> list[dict[str, str]]:
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
        if args.require_group and not has_required_split_context(row, args.split_by):
            diagnostics.skipped.append(
                {
                    "source": record.source,
                    "path": record.path,
                    "reason": f"missing required split context: {args.split_by}",
                }
            )
            continue
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

    return rows


def group_key_for_row(row: dict[str, str], split_by: str) -> str:
    if split_by == "none":
        return "all-findings"
    if split_by == "report":
        return row.get("serpico_report") or row.get("serpico_source") or "unknown-report"
    if split_by == "team":
        return row.get("serpico_team") or "unknown-team"
    if split_by == "owner":
        return row.get("serpico_owner") or "unknown-owner"
    if split_by == "client":
        return row.get("serpico_client") or "unknown-client"
    if split_by == "report-owner":
        report = row.get("serpico_report") or "unknown-report"
        owner = row.get("serpico_team") or row.get("serpico_owner") or "unknown-owner"
        return f"{owner} - {report}"
    if split_by.startswith("field:"):
        field_name = split_by.split(":", 1)[1]
        return row.get(field_name) or f"unknown-{field_name}"
    raise ValueError(f"Unsupported split mode: {split_by}")


def has_required_split_context(row: dict[str, str], split_by: str) -> bool:
    if split_by == "none":
        return True
    if split_by == "report":
        return bool(row.get("serpico_report"))
    if split_by == "team":
        return bool(row.get("serpico_team"))
    if split_by == "owner":
        return bool(row.get("serpico_owner"))
    if split_by == "client":
        return bool(row.get("serpico_client"))
    if split_by == "report-owner":
        return bool(row.get("serpico_report") and (row.get("serpico_team") or row.get("serpico_owner")))
    if split_by.startswith("field:"):
        field_name = split_by.split(":", 1)[1]
        return bool(row.get(field_name))
    raise ValueError(f"Unsupported split mode: {split_by}")


def safe_filename(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", value).strip(" ._-")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        cleaned = fallback
    return cleaned[:120]


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*PLEXTRAC_HEADERS, *CUSTOM_HEADERS])
        writer.writeheader()
        writer.writerows(rows)


def write_manifest(path: Path, groups: dict[str, list[dict[str, str]]], filenames: dict[str, str]) -> None:
    fieldnames = [
        "group",
        "file",
        "finding_count",
        "reports",
        "clients",
        "owners",
        "teams",
        "sources",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for group in sorted(groups):
            rows = groups[group]
            writer.writerow(
                {
                    "group": group,
                    "file": filenames[group],
                    "finding_count": len(rows),
                    "reports": csv_multi(row.get("serpico_report", "") for row in rows),
                    "clients": csv_multi(row.get("serpico_client", "") for row in rows),
                    "owners": csv_multi(row.get("serpico_owner", "") for row in rows),
                    "teams": csv_multi(row.get("serpico_team", "") for row in rows),
                    "sources": csv_multi(row.get("serpico_source", "") for row in rows),
                }
            )


def convert(args: argparse.Namespace) -> Diagnostics:
    diagnostics = Diagnostics()
    rows = collect_rows(args, diagnostics)
    diagnostics.written_findings = len(rows)

    if args.output:
        write_csv(args.output, rows)
        diagnostics.written_files = 1
    else:
        groups: dict[str, list[dict[str, str]]] = {}
        for row in rows:
            groups.setdefault(group_key_for_row(row, args.split_by), []).append(row)

        args.output_dir.mkdir(parents=True, exist_ok=True)
        filenames: dict[str, str] = {}
        used_filenames: set[str] = set()
        for index, group in enumerate(sorted(groups), start=1):
            base = safe_filename(group, f"group-{index:04d}")
            filename = "all-findings.csv" if args.split_by == "none" else f"{index:04d}_{base}.csv"
            while filename.lower() in used_filenames:
                filename = f"{index:04d}_{base}_{len(used_filenames)}.csv"
            used_filenames.add(filename.lower())
            filenames[group] = filename
            write_csv(args.output_dir / filename, groups[group])

        write_manifest(args.output_dir / "manifest.csv", groups, filenames)
        diagnostics.written_files = len(groups)

    if args.diagnostics:
        args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
        args.diagnostics.write_text(
            json.dumps(diagnostics.__dict__, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert Serpico backup/export data to PlexTrac report findings CSV files."
    )
    parser.add_argument("input", type=Path, help="Serpico backup file, archive, or directory.")
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Summarize backup file extensions and samples, then exit without converting.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write one combined PlexTrac CSV. Omit this to split into multiple CSVs.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("plextrac_exports"),
        help="Directory for split CSV output and manifest. Default: plextrac_exports",
    )
    parser.add_argument(
        "--split-by",
        default="report-owner",
        help=(
            "How to separate output CSV files: report-owner, report, team, owner, "
            "client, none, or field:<csv_header>. Default: report-owner"
        ),
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
    parser.add_argument(
        "--require-group",
        action="store_true",
        help="Skip candidate findings that do not have the selected split context.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.inspect:
        print_inspection(inspect_backup(args.input))
        return 0

    diagnostics = convert(args)

    print(f"Scanned files: {diagnostics.scanned_files}")
    print(f"Parsed files: {diagnostics.parsed_files}")
    print(f"Unsupported files: {diagnostics.unsupported_files}")
    print(f"Loaded documents: {diagnostics.loaded_documents}")
    print(f"Candidate findings: {diagnostics.candidate_documents}")
    print(f"Wrote findings: {diagnostics.written_findings}")
    print(f"Wrote CSV files: {diagnostics.written_files}")
    if diagnostics.skipped:
        print(f"Skipped or incomplete rows: {len(diagnostics.skipped)}")
    if diagnostics.warnings:
        print(f"Warnings: {len(diagnostics.warnings)}")
    if diagnostics.unsupported_by_extension:
        print("Unsupported by extension:")
        for extension, count in sorted(
            diagnostics.unsupported_by_extension.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]:
            print(f"  {extension}: {count}")
    if diagnostics.unsupported_samples:
        print("Unsupported samples:")
        for source in diagnostics.unsupported_samples[:10]:
            print(f"  {source}")
    if args.output:
        print(f"CSV: {args.output}")
    else:
        print(f"Output directory: {args.output_dir}")
        print(f"Manifest: {args.output_dir / 'manifest.csv'}")
    if args.diagnostics:
        print(f"Diagnostics: {args.diagnostics}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
