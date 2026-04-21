# Serpico to PlexTrac Converter

Offline Python converter for turning Serpico backup/export data into a PlexTrac
Report Findings CSV.

The script targets PlexTrac's Report Findings CSV import headers:

```text
title,severity,status,description,recommendations,references,affected_assets,tags,cvss_temporal,cwe,cve,category
```

It also appends a few custom columns (`serpico_id`, `serpico_source`,
`serpico_path`, `serpico_report`) so you can trace each imported finding back to
the original Serpico document.

## What it reads

- A directory of Serpico export/backup files
- `.json`, `.jsonl`, and `.ndjson`
- `.zip`, `.tar`, `.tar.gz`, and `.tgz` archives containing those files
- `.bson` MongoDB dumps when `pymongo` is installed

Serpico installations vary, so the converter uses conservative field heuristics
instead of assuming one exact backup shape. It looks for finding-like objects and
maps common Serpico-style fields such as `title`, `name`, `overview`,
`description`, `risk`, `severity`, `remediation`, `references`, `hosts`, and
`affected_hosts`.

## Quick start

```powershell
python serpico_to_plextrac.py C:\path\to\serpico_backup -o plextrac_findings.csv --tag Serpico
```

For Linux/macOS:

```bash
python3 serpico_to_plextrac.py /path/to/serpico_backup -o plextrac_findings.csv --tag Serpico
```

If your backup contains BSON files:

```bash
python3 -m pip install pymongo
python3 serpico_to_plextrac.py /path/to/mongodump -o plextrac_findings.csv --tag Serpico
```

## Recommended first run

Run with diagnostics, then inspect the JSON before importing to PlexTrac:

```bash
python3 serpico_to_plextrac.py ./serpico_backup \
  --output plextrac_findings.csv \
  --diagnostics conversion_diagnostics.json \
  --tag Serpico
```

The diagnostics file reports:

- how many documents were loaded
- how many looked like findings
- rows skipped or written with missing required values
- unsupported file types or parse warnings

## Useful options

```text
--strict
  Skip rows missing PlexTrac-required title or description.

--collection-pattern "findings|reports"
  Only inspect source filenames matching this regex.

--status "Open"
  Set the default PlexTrac status. Allowed values: Open, Closed, In Process.

--tag VALUE
  Add a tag to every row. May be used multiple times.
```

## Importing into PlexTrac

In PlexTrac, import the generated CSV into a report through Findings -> Add
Findings -> File Imports, and select `CSV` as the source. PlexTrac requires
`title`, `severity`, and `description`; this script always writes the required
headers and normalizes severity to `Informational`, `Low`, `Medium`, `High`, or
`Critical`.

## Notes

The converter does not modify the Serpico backup. It only reads backup files and
writes a new CSV plus diagnostics.
