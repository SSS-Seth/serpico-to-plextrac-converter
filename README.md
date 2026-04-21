# Serpico to PlexTrac Converter

Offline Python converter for migrating a Serpico backup/export that contains
many penetration testing reports into PlexTrac Report Findings CSV files.

The important bit: this does **not** flatten everything into one blob by
default. It writes separate CSV files and a manifest so findings remain grouped
by report and owning team.

## Output

By default, the converter creates:

```text
plextrac_exports/
  manifest.csv
  0001_<team> - <report>.csv
  0002_<team> - <report>.csv
  ...
```

Each numbered CSV is meant to be imported into the corresponding PlexTrac report.
`manifest.csv` is your migration map. It shows the grouping key, output file,
finding count, original Serpico report/client/owner/team values, and source
backup file.

The PlexTrac columns are:

```text
title,severity,status,description,recommendations,references,affected_assets,tags,cvss_temporal,cwe,cve,category
```

The script appends traceability columns:

```text
serpico_id,serpico_source,serpico_path,serpico_report,serpico_client,serpico_owner,serpico_team
```

## What it reads

- A directory of Serpico export/backup files
- `.json`, `.jsonl`, and `.ndjson`
- `.zip`, `.tar`, `.tar.gz`, and `.tgz` archives containing those files
- SQLite-style Serpico database snapshots such as `.db`, `.sqlite`, `.sqlite3`,
  `.db.bak`, `.db.serpico.bkp`, and dated `.db.20240430` files
- `.bson` MongoDB dumps when `pymongo` is installed

Serpico installations vary, so the converter uses conservative field heuristics.
Nested findings inherit context from parent report objects, including report,
client, owner, and team fields when those values exist in the backup.

## Quick start

Windows:

```powershell
python serpico_to_plextrac.py C:\path\to\serpico_backup --tag Serpico
```

Linux/macOS:

```bash
python3 serpico_to_plextrac.py /path/to/serpico_backup --tag Serpico
```

If your backup contains BSON files:

```bash
python3 -m pip install pymongo
python3 serpico_to_plextrac.py /path/to/mongodump --tag Serpico
```

## If You See Unsupported File Types

First inspect the backup:

```bash
python3 serpico_to_plextrac.py /path/to/serpico_backup --inspect
```

Windows:

```powershell
python serpico_to_plextrac.py C:\path\to\serpico_backup --inspect
```

This prints extension counts and sample paths. If the backup contains many
`.bson` files, install `pymongo`. If it contains `.db` snapshots, the converter
will try to parse them as SQLite databases. If it contains mostly attachments,
PDFs, screenshots, office files, templates, or front-end assets, those are
expected to be skipped; the converter only imports structured finding/report
data.

During conversion, unsupported files are summarized by extension and sample path.
They are not conversion failures unless the structured report/finding data is in
one of those unsupported formats.

## Split options

Default:

```bash
python3 serpico_to_plextrac.py ./serpico_backup --split-by report-owner
```

Available split modes:

```text
report-owner   one CSV per owning team/report combination
report         one CSV per Serpico report
team           one CSV per owning team
owner          one CSV per owner
client         one CSV per client/customer
none           one CSV named all-findings.csv in the output directory
field:<header> one CSV per value in any output CSV header
```

Examples:

```bash
python3 serpico_to_plextrac.py ./serpico_backup --split-by team --output-dir plextrac_by_team
python3 serpico_to_plextrac.py ./serpico_backup --split-by client --output-dir plextrac_by_client
python3 serpico_to_plextrac.py ./serpico_backup --split-by field:category
```

To force a legacy single CSV:

```bash
python3 serpico_to_plextrac.py ./serpico_backup -o plextrac_findings_combined.csv
```

## Recommended migration run

```bash
python3 serpico_to_plextrac.py ./serpico_backup \
  --output-dir plextrac_exports \
  --diagnostics conversion_diagnostics.json \
  --split-by report-owner \
  --tag Serpico
```

Then review:

- `plextrac_exports/manifest.csv`
- `conversion_diagnostics.json`
- a few representative generated CSVs before importing into PlexTrac

## Useful options

```text
--strict
  Skip rows missing PlexTrac-required title or description.

--require-group
  Skip findings that do not have the selected split context.

--collection-pattern "findings|reports"
  Only inspect source filenames matching this regex.

--status "Open"
  Set the default PlexTrac status. Allowed values: Open, Closed, In Process.

--tag VALUE
  Add a tag to every row. May be used multiple times.
```

## Importing into PlexTrac

In PlexTrac, create or open the appropriate report, then import that report's
CSV through Findings -> Add Findings -> File Imports and select `CSV` as the
source.

PlexTrac requires `title`, `severity`, and `description`. The converter always
writes the required headers and normalizes severity to `Informational`, `Low`,
`Medium`, `High`, or `Critical`.

## Notes

The converter does not modify the Serpico backup. It only reads backup files and
writes PlexTrac CSVs plus diagnostics.
