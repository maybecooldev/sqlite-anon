"""End-to-end: anonymise the demo database and check what survived.

These are the properties that actually matter. A tool that scrambles PII but
breaks the foreign key, or that maps the same person two different ways, is
worse than no tool at all — it looks like it worked.
"""

import sqlite3

from sqlite_anon.anonymize import anonymize, build_plan
from sqlite_anon.cli import main


def read(path, query):
    connection = sqlite3.connect(path)
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


class TestIntegrity:
    def test_row_counts_are_preserved(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        for table in ("users", "orders", "audit"):
            assert (
                read(out, f"SELECT COUNT(*) FROM {table}")[0][0]
                == read(demo_db, f"SELECT COUNT(*) FROM {table}")[0][0]
            )

    def test_the_foreign_key_join_still_returns_the_same_pairs(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        query = "SELECT o.id, o.user_id, u.id FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.id"
        assert read(out, query) == read(demo_db, query)

    def test_the_schema_is_recreated_intact(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        assert [r[1] for r in read(out, "PRAGMA table_info(users)")] == [
            r[1] for r in read(demo_db, "PRAGMA table_info(users)")
        ]

    def test_the_source_file_is_never_modified(self, demo_db, tmp_path, key):
        before = open(demo_db, "rb").read()  # noqa: SIM115
        anonymize(demo_db, str(tmp_path / "out.db"), key)
        assert open(demo_db, "rb").read() == before  # noqa: SIM115

    def test_non_pii_columns_are_untouched(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        assert read(out, "SELECT country FROM users ORDER BY id") == read(
            demo_db, "SELECT country FROM users ORDER BY id"
        )
        assert read(out, "SELECT total FROM orders ORDER BY id") == read(
            demo_db, "SELECT total FROM orders ORDER BY id"
        )


class TestConsistency:
    def test_the_same_person_maps_to_the_same_value_everywhere(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        # Rows 0 and 4 are the same person, in two tables.
        users = read(out, "SELECT email, full_name, phone, cpf FROM users WHERE id IN (1,5)")
        audit = read(out, "SELECT actor FROM audit WHERE id = 1")
        assert users[0] == users[1]
        assert users[0][0] == audit[0][0]

    def test_distinct_people_stay_distinct(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        emails = [r[0] for r in read(out, "SELECT email FROM users")]
        assert len(set(emails)) == 4  # 5 rows, one person duplicated

    def test_the_scrubbed_address_in_free_text_matches_the_email_column(
        self, demo_db, tmp_path, key
    ):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        email, notes = read(out, "SELECT email, notes FROM users WHERE id = 1")[0]
        assert email in notes

    def test_two_runs_with_the_same_key_are_identical(self, demo_db, tmp_path, key):
        first, second = str(tmp_path / "a.db"), str(tmp_path / "b.db")
        anonymize(demo_db, first, key)
        anonymize(demo_db, second, key)
        query = "SELECT email, full_name, phone, cpf FROM users ORDER BY id"
        assert read(first, query) == read(second, query)

    def test_a_different_key_gives_a_different_result(self, demo_db, tmp_path, key):
        first, second = str(tmp_path / "a.db"), str(tmp_path / "b.db")
        anonymize(demo_db, first, key)
        anonymize(demo_db, second, bytes(32))
        query = "SELECT email FROM users ORDER BY id"
        assert read(first, query) != read(second, query)


class TestLeakage:
    def test_no_original_pii_survives(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        dump = "\n".join(
            str(row)
            for table in ("users", "orders", "audit")
            for row in read(out, f"SELECT * FROM {table}")
        )
        for secret in [
            "ana.silva@empresa.com.br",
            "Ana Silva",
            "+55 (11) 98765-4321",
            "123.456.789-00",
            "192.168.1.44",
            "bruno.costa@empresa.com.br",
        ]:
            assert secret not in dump, f"{secret} survived anonymisation"

    def test_nulls_stay_null(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key)
        assert read(out, "SELECT phone FROM users WHERE id = 4")[0][0] is None


class TestPlan:
    def test_plan_lists_columns_without_writing(self, demo_db):
        plan = build_plan(demo_db)
        names = {item.column.path for item in plan.columns}
        assert "users.email" in names
        assert "users.notes" in names
        assert plan.row_count == 11

    def test_min_confidence_filters_the_plan(self, demo_db):
        loose = build_plan(demo_db, min_confidence=0.0)
        strict = build_plan(demo_db, min_confidence=0.9)
        assert len(strict.columns) < len(loose.columns)

    def test_only_restricts_the_categories(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        anonymize(demo_db, out, key, only={"email"})
        # Email is rewritten...
        assert "ana.silva@empresa.com.br" not in str(read(out, "SELECT email FROM users"))
        # ...but nothing else is.
        assert read(out, "SELECT full_name FROM users WHERE id = 1")[0][0] == "Ana Silva"


class TestCli:
    def test_report_writes_nothing(self, demo_db, tmp_path, capsys):
        import os

        out = str(tmp_path / "out.db")
        assert main([demo_db, "--report", "-o", out]) == 0
        assert not os.path.exists(out)
        assert "users.email" in capsys.readouterr().out

    def test_report_json(self, demo_db, capsys):
        import json

        assert main([demo_db, "--report", "--format", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["rows"] == 11
        assert any(c["column"] == "email" for c in payload["columns"])

    def test_default_output_path(self, demo_db, tmp_path):
        import os

        key_file = str(tmp_path / "anon.key")
        assert main([demo_db, "--key-file", key_file, "--create-key"]) == 0
        assert os.path.exists(demo_db.replace(".db", ".anon.db"))

    def test_refuses_to_overwrite_the_input(self, demo_db, capsys):
        assert main([demo_db, "-o", demo_db]) == 2
        assert "refusing" in capsys.readouterr().err

    def test_missing_file(self, capsys):
        assert main(["/nonexistent.db"]) == 2

    def test_create_key_without_a_path(self, demo_db, capsys):
        assert main([demo_db, "--create-key"]) == 2

    def test_category_filter(self, demo_db, tmp_path, key):
        out = str(tmp_path / "out.db")
        assert main([demo_db, "-o", out, "--category", "email"]) == 0
        assert read(out, "SELECT full_name FROM users WHERE id = 1")[0][0] == "Ana Silva"


class TestSafety:
    def test_an_existing_output_is_replaced_not_appended(self, demo_db, tmp_path, key):
        out = tmp_path / "out.db"
        with open(out, "w") as handle:
            handle.write("stale content that is not a database")
        anonymize(demo_db, str(out), key)
        assert read(str(out), "SELECT COUNT(*) FROM users")[0][0] == 5
