"""Rewrite personal data into safe equivalents.

The central design decision is that anonymisation must be *deterministic and
format-preserving*:

* **Deterministic** — the same input always maps to the same output, so
  foreign keys still join, ``GROUP BY email`` still groups, and a bug that
  only reproduces for one user still reproduces. It is done with keyed
  HMAC-SHA256, not a random draw, precisely so these properties hold.
* **Format-preserving** — ``+55 (11) 98765-4321`` stays the shape of a
  Brazilian mobile number. A dataset where every phone is the same length of
  random digits still leaks the distribution, and it also breaks anything
  downstream that validates the format.

The key never leaves the machine unless you export it, and losing it means the
mapping is gone for good — which is the point.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from .detect import Category

__all__ = ["AnonymisationError", "Anonymizer", "load_or_create_key"]


class AnonymisationError(Exception):
    """Raised when a key is missing or the wrong length."""


KEY_BYTES = 32


def load_or_create_key(path: str | None, *, create: bool = False) -> bytes:
    """Read the key from ``path``, or generate one when asked to."""
    if path is None:
        return secrets.token_bytes(KEY_BYTES)

    if os.path.exists(path):
        with open(path, "rb") as handle:
            key = handle.read()
        if len(key) != KEY_BYTES:
            raise AnonymisationError(f"key at {path} is {len(key)} bytes; expected {KEY_BYTES}")
        return key

    if not create:
        raise AnonymisationError(
            f"no key at {path}. Pass --create-key to generate one, or --key-file."
        )

    key = secrets.token_bytes(KEY_BYTES)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    # 0600: this file is the only thing standing between the original data and
    # the pseudonymised copy.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key)
    return key


#: Identifiers scrubbed out of free-text columns, as a single alternation
#: rather than a list of patterns applied in turn. Applying them in sequence
#: means the second pass re-scans text the first pass already rewrote, and
#: happily mangles the hex digits of a freshly generated email address.
_PROSE_TEXT = re.compile(
    "|".join(
        [
            r"(?P<email>[\w.+-]+@[\w-]+(?:\.[a-zA-Z]{2,})+)",
            r"(?P<cpf>\d{3}\.?\d{3}\.?\d{3}-?\d{2})",
            r"(?P<cnpj>\d{2}\.?\d{3}\.?\d{3}\.?\d{4}-?\d{2})",
            r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)",
            r"(?P<phone>\+?\d{2,3}[\s-]?\(?\d{2,3}\)?[\s-]?\d{4,5}[\s-]?\d{0,4})",
        ]
    )
)


# ---------------------------------------------------------------------------
# Word lists
#
# Small, and deliberately not exhaustive. The goal is a value that is
# obviously synthetic and structurally plausible, not a realistic name.
# ---------------------------------------------------------------------------

GIVEN_NAMES = (
    "Ana",
    "Bruno",
    "Carla",
    "Diego",
    "Elisa",
    "Felipe",
    "Gabriela",
    "Henrique",
    "Isabela",
    "João",
    "Karina",
    "Lucas",
    "Mariana",
    "Nathan",
    "Olívia",
    "Paulo",
    "Rita",
    "Samuel",
    "Tatiana",
    "Vinícius",
)

FAMILY_NAMES = (
    "Almeida",
    "Barbosa",
    "Cardoso",
    "Duarte",
    "Esteves",
    "Ferreira",
    "Gonçalves",
    "Henriques",
    "Inácio",
    "Jardim",
    "Klein",
    "Lima",
    "Machado",
    "Nogueira",
    "Oliveira",
    "Pereira",
    "Quintana",
    "Ribeiro",
    "Santos",
    "Teixeira",
)

STREETS = (
    "Rua das Acácias",
    "Avenida Sete de Setembro",
    "Travessa Bela Vista",
    "Rua Ipê Amarelo",
    "Alameda dos Anjos",
    "Rua do Comércio",
)

CITIES = (
    "São Paulo",
    "Belo Horizonte",
    "Curitiba",
    "Florianópolis",
    "Recife",
    "Natal",
    "Porto Alegre",
    "Goiânia",
)

STATES = ("SP", "MG", "PR", "SC", "PE", "RN", "RS", "GO")

EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "invalid")

CREDIT_CARD_PREFIXES = ("411111", "550000", "340000")


@dataclass
class Anonymizer:
    """Turns a value in one category into a safe stand-in."""

    key: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) != KEY_BYTES:
            raise AnonymisationError(f"key must be {KEY_BYTES} bytes")
        # Bind the category methods to a name -> callable table once, instead of
        # re-resolving them by attribute on every single cell.
        self.handlers: dict[str, Callable[[str], str]] = {
            Category.EMAIL: self.email,
            Category.PHONE: self.phone,
            Category.NAME: self.name,
            Category.CPF: self.cpf,
            Category.CNPJ: self.cnpj,
            Category.SSN: self.ssn,
            Category.CREDIT_CARD: self.credit_card,
            Category.IP: self.ip,
            Category.POSTAL: self.postal,
            Category.ADDRESS: self.address,
            Category.FREE_TEXT: self.free_text,
        }

    # -- core ---------------------------------------------------------------

    def digest(self, category: str, value: str) -> bytes:
        """A stable pseudorandom value for ``value`` within ``category``.

        The category is part of the HMAC message, so the same email address
        does not produce the same fake phone number. Without that, an attacker
        could line the columns up and recover the original.
        """
        message = f"{category}\x00{value}".encode()
        return hmac.new(self.key, message, hashlib.sha256).digest()

    def index(self, category: str, value: str, modulus: int) -> int:
        if modulus <= 0:
            return 0
        return int.from_bytes(self.digest(category, value)[:8], "big") % modulus

    def choice(self, category: str, value: str, options: tuple[str, ...]) -> str:
        return options[self.index(category, value, len(options))]

    def digits(self, category: str, value: str, count: int) -> str:
        """``count`` decimal digits, derived from the HMAC."""
        out: list[str] = []
        block = 0
        counter = 0
        while len(out) < count:
            if block == 0:
                material = self.digest(category, f"{value}#{counter}")
                block = int.from_bytes(material, "big")
                counter += 1
            out.append(str(block % 10))
            block //= 10
        return "".join(out[:count])

    # -- per category --------------------------------------------------------

    def email(self, value: str) -> str:
        # Keep the local part's length and general shape, but never its
        # content: a real-looking handle is still a real handle.
        local = value.split("@", 1)[0]
        size = max(3, min(20, len(local)))
        stem = self.digest(Category.EMAIL, value).hex()
        local_part = stem[:size]
        domain = self.choice(Category.EMAIL, value, EMAIL_DOMAINS)
        return f"{local_part}@{domain}"

    def phone(self, value: str) -> str:
        """Preserve the punctuation pattern of the input.

        Every run of digits in the input becomes a run of digits in the output
        of the same length, and every separator is kept. That keeps
        ``+55 (11) 98765-4321`` looking like a Brazilian mobile number without
        being one.
        """
        out: list[str] = []
        run = ""
        for char in value:
            if char.isdigit():
                run += char
                continue
            if run:
                out.append(self.digits(Category.PHONE, value, len(run)))
                run = ""
            out.append(char)
        if run:
            out.append(self.digits(Category.PHONE, value, len(run)))
        return "".join(out)

    def name(self, value: str) -> str:
        parts = [p for p in value.replace(",", " ").split() if p]
        if not parts:
            return value
        given = self.choice(Category.NAME, value, GIVEN_NAMES)
        if len(parts) == 1:
            return given
        family = self.choice(Category.NAME, value + ":family", FAMILY_NAMES)
        if len(parts) == 2:
            return f"{given} {family}"
        return " ".join([given, *parts[1:-1], family])

    def cpf(self, value: str) -> str:
        """11 digits with valid Brazilian check digits, so validation passes."""
        base = self.digits(Category.CPF, value, 9)
        digits = base + _cpf_check_digits(base)
        return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"

    def cnpj(self, value: str) -> str:
        base = self.digits(Category.CNPJ, value, 12)
        digits = base + _cnpj_check_digits(base)
        return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}.{digits[8:12]}-{digits[12:]}"

    def credit_card(self, value: str) -> str:
        """16 digits with a Luhn check digit, matching the input's shape."""
        digits = self.digits(Category.CREDIT_CARD, value, 15)
        prefix = self.choice(Category.CREDIT_CARD, value, CREDIT_CARD_PREFIXES)
        body = (prefix + digits)[:15]
        body = body + _luhn_check_digit(body)
        grouped = " ".join(body[i : i + 4] for i in range(0, 16, 4))
        return grouped if " " in value else body

    def ssn(self, value: str) -> str:
        digits = self.digits(Category.SSN, value, 9)
        return f"{digits[:3]}-{digits[3:5]}-{digits[5:]}"

    def ip(self, value: str) -> str:
        # RFC 5737 documentation range: guaranteed never to be a real host.
        return ".".join(["192", "0", "2", str(self.index(Category.IP, value, 254) + 1)])

    def postal(self, value: str) -> str:
        digits = self.digits(Category.POSTAL, value, 8)
        return f"{digits[:5]}-{digits[5:]}" if "-" in value else digits

    def address(self, value: str) -> str:
        street = self.choice(Category.ADDRESS, value, STREETS)
        number = self.digits(Category.ADDRESS, value, 3)
        city = self.choice(Category.ADDRESS, value + ":city", CITIES)
        state = self.choice(Category.ADDRESS, value + ":state", STATES)
        return f"{street}, {number} - {city}/{state}"

    def free_text(self, value: str) -> str:
        """Scrub identifiers out of prose, keeping the sentence readable.

        Replacing the whole string would destroy the text's usefulness for
        debugging; the point is that the identifiers in it stop being real.
        """
        return _PROSE_TEXT.sub(
            lambda match: self._substitute(match.lastgroup or "", match.group(0)), value
        )

    def _substitute(self, category: str, match: str) -> str:
        handler: Callable[[str], str] | None = getattr(self, category, None)
        if handler is None:
            return match
        try:
            return handler(match)
        except (AnonymisationError, ValueError, IndexError):
            return match

    def apply(self, category: str, value: object) -> object:
        """Rewrite one value. Nulls, blanks and unknown categories pass through."""
        if category not in self.handlers:
            return value
        # Only text is rewritten. A column of integers that the detector
        # mislabelled should come out the other side still holding integers,
        # not a column of invented names.
        if not isinstance(value, str) or not value.strip():
            return value

        handler = self.handlers[category]

        # A column of people can hold addresses: an `actor` or `owner` column
        # is frequently an email. Route on the shape of the value so the output
        # keeps that shape, and so the same address maps the same way whether
        # it was found in a `name` column or an `email` one.
        if category == Category.NAME and self._looks_like_email(value):
            handler = self.email

        return handler(value)

    @staticmethod
    def _looks_like_email(value: str) -> bool:
        return (
            "@" in value
            and _PROSE_TEXT.search(value) is not None
            and _PROSE_TEXT.search(value).lastgroup == "email"
        )


#: Identifiers scrubbed out of free-text columns. Built once at import so
#: :meth:`Anonymizer.free_text` does no work beyond the substitution.


# ---------------------------------------------------------------------------
# Check digits
# ---------------------------------------------------------------------------


def _cpf_check_digits(base: str) -> str:
    """The two check digits a Brazilian CPF must carry to be valid.

    The first is computed over the 9 payload digits with weights 10..2; the
    second over those 9 *plus the first check digit*, with weights 11..2.
    Feeding the same 9 digits to both rounds is the classic way to get this
    subtly wrong.
    """
    out = ""
    digits = base
    for size in (9, 10):
        total = sum(int(d) * (size + 1 - index) for index, d in enumerate(digits))
        remainder = (total * 10) % 11
        out += str(0 if remainder == 10 else remainder)
        digits = base + out
    return out


def _cnpj_check_digits(base: str) -> str:
    """The two check digits of a CNPJ, computed the same way round by round."""
    out = ""
    digits = base
    for weights in (
        [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2],
        [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2],
    ):
        total = sum(int(d) * w for d, w in zip(digits, weights, strict=True))
        remainder = total % 11
        out += str(0 if remainder < 2 else 11 - remainder)
        digits = base + out
    return out


def _luhn_check_digit(base: str) -> str:
    total = 0
    for index, char in enumerate(reversed(base)):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - (total % 10)) % 10)
