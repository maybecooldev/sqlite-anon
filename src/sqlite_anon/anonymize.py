"""Copy a database, rewriting the columns that hold personal data.

The source file is opened read-only and never written to. The output is a
fresh database built row by row, so a failure halfway through leaves the
original untouched and the half-written output disposable.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field

from .detect import Column, inspect_database
from .transform import Anonymizer

__all__ = ["ANON_SUFFIXES", "ColumnPlan", "Plan", "anonymize", "build_plan"]


@dataclass
class ColumnPlan:
    """One column to rewrite, and how many rows it will touch."""

    column: Column
    #: Distinct values seen while sampling; used to report the rewrite cost
    #: without a second pass over the data.
    distinct_sample: int


@dataclass
class Plan:
    """Everything decided before a single row is written."""

    source: str
    columns: list[ColumnPlan] = field(default_factory=list)
    table_count: int = 0
    row_count: int = 0

    @property
    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.columns:
            counts[item.column.category] = counts.get(item.column.category, 0) + 1
        return counts

    def describe(self) -> str:
        lines = [f"{self.source}: {self.table_count} table(s), {self.row_count} row(s)"]
        for category, count in sorted(self.by_category.items()):
            lines.append(f"  {category:<14} {count} column(s)")
        return "\n".join(lines)


def build_plan(source: str, min_confidence: float = 0.0, sample_rows: int = 200) -> Plan:
    """Decide what would be rewritten, without writing anything."""
    columns = inspect_database(source, sample_rows=sample_rows, min_confidence=min_confidence)
    plan = Plan(source=source)
    for column in columns:
        plan.columns.append(ColumnPlan(column=column, distinct_sample=len(set(column.samples))))
    if os.path.isfile(source):
        connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        try:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            plan.table_count = len(tables)
            for table in tables:
                plan.row_count += connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[
                    0
                ]
        finally:
            connection.close()
    return plan


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def anonymize(
    source: str,
    destination: str,
    key: bytes,
    *,
    min_confidence: float = 0.0,
    sample_rows: int = 200,
    only: set[str] | None = None,
) -> Plan:
    """Write an anonymised copy of ``source`` to ``destination``.

    ``only`` restricts the rewrite to these category names, which is how you
    override the detector when it guesses wrong.
    """
    plan = build_plan(source, min_confidence, sample_rows)
    if only is not None:
        plan.columns = [item for item in plan.columns if item.column.category in only]

    anonymizer = Anonymizer(key=key)

    targets: dict[str, dict[str, str]] = {}
    for item in plan.columns:
        targets.setdefault(item.column.table, {})[item.column.name] = item.column.category

    if os.path.exists(destination):
        os.unlink(destination)

    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        tables = [
            row[0]
            for row in source_connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]

        for table in tables:
            columns_to_rewrite = targets.get(table, {})
            _copy_table(
                source_connection,
                destination_connection,
                table,
                columns_to_rewrite,
                anonymizer,
            )

        destination_connection.commit()
    finally:
        source_connection.close()
        destination_connection.close()

    return plan


def _copy_table(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
    table: str,
    columns_to_rewrite: dict[str, str],
    anonymizer: Anonymizer,
) -> None:
    info = source.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
    if not info:
        return

    names = [row[1] for row in info]
    declared = {row[1]: row[2] for row in info}
    primary_key = next((row[1] for row in info if row[5]), None)

    # Recreate the table with its original definition, so indexes, foreign
    # keys and defaults declared in the schema all survive the copy.
    schema = source.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if schema and schema[0]:
        destination.execute(schema[0])
    else:
        column_sql = ", ".join(f"{_quote(name)} {declared[name] or 'TEXT'}" for name in names)
        destination.execute(f"CREATE TABLE {_quote(table)} ({column_sql})")

    selected = ", ".join(_quote(name) for name in names)
    cursor = source.execute(f"SELECT {selected} FROM {_quote(table)}")

    placeholders = ", ".join("?" for _ in names)
    quoted_columns = ", ".join(_quote(name) for name in names)
    insert = f"INSERT INTO {_quote(table)} ({quoted_columns}) VALUES ({placeholders})"

    index_positions = {name: position for position, name in enumerate(names)}

    while True:
        rows = cursor.fetchmany(1000)
        if not rows:
            break
        batch: list[tuple] = []
        for row in rows:
            values = list(row)
            for column_name, category in columns_to_rewrite.items():
                position = index_positions.get(column_name)
                if position is None:
                    continue
                values[position] = anonymizer.apply(category, values[position])
            batch.append(tuple(values))
        destination.executemany(insert, batch)

    if primary_key:
        destination.execute(
            f"CREATE INDEX IF NOT EXISTS {_quote('idx_' + table + '_' + primary_key)} "
            f"ON {_quote(table)} ({_quote(primary_key)})"
        )


#: Suffixes tried when no destination is given.
ANON_SUFFIXES = (".anon.db", ".anon.sqlite", ".anon.sqlite3")
