import pytest

from sqlite_anon.detect import (
    Category,
    detect_by_content,
    detect_by_name,
    inspect_table,
    normalise,
)


class TestNormalise:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("email", "email"),
            ("user_email", "user_email"),
            ("UserEmail", "user_email"),
            ("userPhoneNumber", "user_phone_number"),
            ("EMAIL", "email"),
            ("e-mail", "e_mail"),
        ],
    )
    def test_spellings_collapse_to_one_form(self, raw, expected):
        assert normalise(raw) == expected


class TestDetectByName:
    @pytest.mark.parametrize(
        "column,expected",
        [
            ("email", Category.EMAIL),
            ("user_email", Category.EMAIL),
            ("email_address", Category.EMAIL),
            ("phone", Category.PHONE),
            ("mobile_phone", Category.PHONE),
            ("full_name", Category.NAME),
            ("first_name", Category.NAME),
            ("cpf", Category.CPF),
            ("cnpj", Category.CNPJ),
            ("client_ip", Category.IP),
            ("zip_code", Category.POSTAL),
            ("shipping_address", Category.ADDRESS),
        ],
    )
    def test_known_columns(self, column, expected):
        assert detect_by_name(column) == expected

    @pytest.mark.parametrize(
        "column", ["id", "total", "created_at", "quantity", "status", "amount"]
    )
    def test_innocuous_columns(self, column):
        assert detect_by_name(column) is None

    @pytest.mark.parametrize("column", ["username", "filename", "hostname", "nickname"])
    def test_name_lookalikes_are_not_people(self, column):
        # "username" contains "name" but is not a person's name.
        assert detect_by_name(column) is None

    def test_specific_hint_beats_generic(self):
        # "email_address" is an email, not a postal address.
        assert detect_by_name("email_address") == Category.EMAIL


class TestDetectByContent:
    def test_all_values_look_like_emails(self):
        values = ["a@b.com", "c@d.org", "e@f.net", "g@h.io"]
        assert detect_by_content(values)[0] == Category.EMAIL

    def test_mostly_not_emails(self):
        values = ["a@b.com", "hello", "42", "c@d.org"]
        assert detect_by_content(values)[0] is None

    def test_too_few_samples_gives_up(self):
        assert detect_by_content(["a@b.com", "c@d.org"])[0] is None

    def test_ips(self):
        values = ["10.0.0.1", "192.168.0.2", "172.16.0.3", "8.8.8.8"]
        assert detect_by_content(values)[0] == Category.IP

    def test_blank_values_are_ignored(self):
        values = ["", "  ", "a@b.com", "c@d.org", "e@f.net", "g@h.io"]
        category, matches = detect_by_content(values)
        assert category == Category.EMAIL
        assert matches == 4


class TestInspectTable:
    def test_classifies_and_keeps_evidence(self, tmp_path, demo_db):
        import sqlite3

        connection = sqlite3.connect(demo_db)
        try:
            columns = {c.name: c for c in inspect_table(connection, "users")}
        finally:
            connection.close()

        assert columns["email"].category == Category.EMAIL
        assert columns["email"].confidence == 0.95
        assert len(columns["email"].evidence) == 2
        assert columns["email"].path == "users.email"

    def test_ignores_a_missing_table(self, tmp_path):
        import sqlite3

        connection = sqlite3.connect(":memory:")
        try:
            assert inspect_table(connection, "nope") == []
        finally:
            connection.close()


class TestConfidence:
    def test_name_only_match_is_lower_confidence(self, demo_db):
        import sqlite3

        connection = sqlite3.connect(demo_db)
        try:
            columns = {c.name: c for c in inspect_table(connection, "users")}
        finally:
            connection.close()
        # "full_name" is detected from the name only, so it scores lower than
        # email, which name and content both confirm.
        assert columns["full_name"].confidence < columns["email"].confidence

    def test_prose_is_detected_at_a_low_hit_rate(self, demo_db):
        import sqlite3

        connection = sqlite3.connect(demo_db)
        try:
            columns = {c.name: c for c in inspect_table(connection, "users")}
        finally:
            connection.close()
        # One of four notes contains an email. In a prose column that is a leak,
        # even though the column is 75% innocent text.
        assert columns["notes"].category == Category.FREE_TEXT
