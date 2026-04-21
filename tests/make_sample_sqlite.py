#!/usr/bin/env python3
"""Create a small Serpico-like SQLite fixture for smoke testing."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def main() -> None:
    output = Path(__file__).with_name("sample_serpico.db")
    if output.exists():
        output.unlink()

    connection = sqlite3.connect(output)
    try:
        connection.executescript(
            """
            create table reports (
              id integer primary key,
              report_title text,
              client_name text,
              owning_team text
            );

            create table findings (
              id integer primary key,
              report_id integer,
              title text,
              severity text,
              description text,
              remediation text,
              affected_hosts text,
              foreign key(report_id) references reports(id)
            );
            """
        )
        connection.execute(
            "insert into reports values (?, ?, ?, ?)",
            (1, "SQLite External Test", "Example Corp", "Infrastructure Security"),
        )
        connection.execute(
            "insert into findings values (?, ?, ?, ?, ?, ?, ?)",
            (
                101,
                1,
                "SQLite Finding",
                "Critical",
                "A finding loaded from a SQLite database.",
                "Fix the SQLite-backed issue.",
                "sqlite-host.example.test",
            ),
        )
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    main()
