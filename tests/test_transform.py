import os
import re
import stat

import pytest

from sqlite_anon.detect import Category
from sqlite_anon.transform import (
    AnonymisationError,
    Anonymizer,
    _cnpj_check_digits,
    _cpf_check_digits,
    _luhn_check_digit,
    load_or_create_key,
)


@pytest.fixture
def anon(key):
    return Anonymizer(key=key)


def cpf_is_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 11 and digits[-2:] == _cpf_check_digits(digits[:9])


def cnpj_is_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 14 and digits[-2:] == _cnpj_check_digits(digits[:12])


def luhn_is_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 16 and digits[-1] == _luhn_check_digit(digits[:15])


class TestKeyHandling:
    def test_rejects_a_wrong_sized_key(self):
        with pytest.raises(AnonymisationError):
            Anonymizer(key=b"too short")

    def test_missing_key_file_is_an_error(self, tmp_path):
        with pytest.raises(AnonymisationError):
            load_or_create_key(str(tmp_path / "nope.key"))

    def test_create_key_writes_a_readable_file(self, tmp_path):
        path = str(tmp_path / "sub" / "anon.key")
        key = load_or_create_key(path, create=True)
        assert len(key) == 32
        assert load_or_create_key(path) == key

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits do not exist on Windows")
    def test_created_key_is_not_world_readable(self, tmp_path):
        path = str(tmp_path / "anon.key")
        load_or_create_key(path, create=True)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode & 0o077 == 0, f"key file is mode {mode:o}, expected no group or other access"

    def test_no_key_file_gives_a_fresh_random_key(self):
        first = load_or_create_key(None)
        second = load_or_create_key(None)
        assert first != second


class TestDeterminism:
    def test_same_input_same_output(self, key, anon):
        other = Anonymizer(key=key)
        assert anon.email("a@b.com") == other.email("a@b.com")

    def test_different_key_different_output(self, key, anon):
        other = Anonymizer(key=bytes(32))
        assert anon.email("a@b.com") != other.email("a@b.com")

    def test_categories_are_salted_separately(self, anon):
        # The same string used as an email and as a phone must not collide,
        # or the columns could be lined up to recover the original.
        assert anon.digest(Category.EMAIL, "x") != anon.digest(Category.PHONE, "x")

    def test_distinct_inputs_stay_distinct(self, anon):
        seen = {anon.email(f"user{i}@example.com") for i in range(200)}
        assert len(seen) == 200


class TestFormatPreservation:
    def test_email_keeps_a_rfc_shaped_local_part(self, anon):
        result = anon.email("ana.silva@empresa.com.br")
        assert re.match(r"^[^@]+@[^@]+\.[a-z]+$", result)
        assert result != "ana.silva@empresa.com.br"

    def test_email_uses_a_reserved_domain(self, anon):
        assert anon.email("a@b.com").split("@")[1] in {
            "example.com",
            "example.org",
            "example.net",
            "invalid",
        }

    def test_phone_keeps_every_separator_and_digit_run_length(self, anon):
        original = "+55 (11) 98765-4321"
        result = anon.phone(original)
        assert result[0] == "+"
        original_runs = re.findall(r"\d+", original)
        result_runs = re.findall(r"\d+", result)
        assert [len(r) for r in original_runs] == [len(r) for r in result_runs]
        assert re.sub(r"\d", "", original) == re.sub(r"\d", "", result)

    def test_unformatted_phone_stays_unformatted(self, anon):
        result = anon.phone("11987654321")
        assert result.isdigit()
        assert len(result) == 11

    def test_cpf_is_11_digits_with_valid_check_digits(self, anon):
        result = anon.cpf("123.456.789-00")
        assert cpf_is_valid(result)
        assert re.match(r"^\d{3}\.\d{3}\.\d{3}-\d{2}$", result)

    def test_cnpj_is_14_digits_with_valid_check_digits(self, anon):
        assert cnpj_is_valid(anon.cnpj("11.222.333/0001-81"))

    def test_credit_card_passes_luhn(self, anon):
        result = anon.credit_card("4111 1111 1111 1111")
        assert luhn_is_valid(result)
        assert " " in result

    def test_unformatted_card_has_no_spaces(self, anon):
        result = anon.credit_card("4111111111111111")
        assert result.isdigit() and luhn_is_valid(result)

    def test_ip_lands_in_the_documentation_range(self, anon):
        for original in ["10.0.0.1", "8.8.8.8", "192.168.1.44", "172.16.0.3"]:
            assert anon.ip(original).startswith("192.0.2.")

    def test_name_keeps_the_number_of_parts(self, anon):
        assert len(anon.name("Ana").split()) == 1
        assert len(anon.name("Ana Silva").split()) == 2
        assert len(anon.name("Ana Maria Silva").split()) == 3

    def test_name_uses_the_synthetic_word_list(self, anon):
        assert anon.name("Ana Silva") != "Ana Silva"


class TestFreeText:
    def test_scrubs_an_email_but_keeps_the_sentence(self, anon):
        result = anon.free_text("Prefere contato por email ana@empresa.com.br")
        assert "ana@empresa.com.br" not in result
        assert "Prefere contato por email" in result

    def test_scrubs_a_phone(self, anon):
        result = anon.free_text("ligar para 11 98765-4321 hoje")
        assert "98765-4321" not in result

    def test_leaves_innocent_text_alone(self, anon):
        assert anon.free_text("solicitou retorno") == "solicitou retorno"

    def test_the_same_identifier_scrubs_to_the_same_value(self, anon):
        # The point of determinism: the address in the notes column must map to
        # the same fake as the address in the email column, or the two can be
        # correlated back to the original.
        sentence = anon.free_text("write to ana@empresa.com.br")
        assert anon.email("ana@empresa.com.br") in sentence


class TestApply:
    def test_none_passes_through(self, anon):
        assert anon.apply(Category.EMAIL, None) is None

    def test_empty_string_passes_through(self, anon):
        assert anon.apply(Category.EMAIL, "") == ""

    def test_unknown_category_passes_through(self, anon):
        assert anon.apply("nonsense", "value") == "value"

    def test_booleans_are_not_mangled(self, anon):
        assert anon.apply(Category.NAME, True) is True

    def test_numbers_are_left_alone(self, anon):
        # A numeric column misdetected as a name should not become a column
        # of invented names.
        assert anon.apply(Category.NAME, 42) == 42
        assert anon.apply(Category.EMAIL, 99) == 99


class TestCheckDigits:
    def test_cpf_check_digits_match_the_known_value(self):
        # The canonical example: 111.444.777-35 is a valid CPF.
        assert _cpf_check_digits("111444777") == "35"

    def test_cnpj_check_digits_match_a_known_value(self):
        assert _cnpj_check_digits("112223330001") == "81"

    def test_luhn_check_digit_for_a_known_card(self):
        assert _luhn_check_digit("411111111111111") == "1"
