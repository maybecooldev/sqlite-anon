"""Decide which columns hold personal data.

Two independent signals, because neither is sufficient on its own:

* the column *name* — ``email``, ``user_phone``, ``cpf`` are strong hints, and
  they cost nothing to check;
* the column *contents* — a column called ``notes`` is just as likely to hold
  an email address as a column called ``contact_email`` is to hold a phone
  number.

Name detection alone misses free-text columns. Content detection alone flags
any column that happens to contain six digits. Requiring both to agree would
miss the free-text case, so each signal votes and the rules below decide what
counts as enough.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

__all__ = [
    "CATEGORIES",
    "Category",
    "Column",
    "Evidence",
    "inspect_database",
    "inspect_table",
]


class Category:
    """The kinds of personal data this tool knows how to rewrite."""

    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    CPF = "cpf"
    CNPJ = "cnpj"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP = "ip"
    POSTAL = "postal"
    ADDRESS = "address"
    #: A column of prose that happens to contain some of the above.
    FREE_TEXT = "free_text"


#: Every category this tool knows how to rewrite.
CATEGORIES = frozenset(
    {
        Category.EMAIL,
        Category.PHONE,
        Category.NAME,
        Category.CPF,
        Category.CNPJ,
        Category.SSN,
        Category.CREDIT_CARD,
        Category.IP,
        Category.POSTAL,
        Category.ADDRESS,
        Category.FREE_TEXT,
    }
)


#: Ordered so that more specific patterns win over generic digit matching.
DETECTORS: dict[str, re.Pattern[str]] = {
    Category.EMAIL: re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.IGNORECASE),
    Category.CREDIT_CARD: re.compile(r"^(?:\d[ -]?){13,19}$"),
    # 11 digits, optionally with a country code, punctuation or a +55 prefix.
    Category.PHONE: re.compile(r"^\+?\d{0,3}[\s-]?\(?\d{2,3}\)?[\s-]?\d{4,5}[\s-]?\d{0,4}$"),
    # Brazilian CPF: 11 digits, and it fails its own check-digit test about
    # 90% of the time, which makes false positives rare.
    Category.CPF: re.compile(r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$"),
    Category.CNPJ: re.compile(r"^\d{2}\.?\d{3}\.?\d{3}\.?\d{4}-?\d{2}$"),
    Category.SSN: re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    Category.IP: re.compile(r"^\d{1,3}(\.\d{1,3}){3}$"),
    Category.POSTAL: re.compile(r"^\d{5}-?\d{3}$"),
}

#: Name hints, checked against a normalised column name.
NAME_HINTS: dict[str, tuple[str, ...]] = {
    Category.EMAIL: ("email", "e_mail", "mail"),
    Category.PHONE: ("phone", "mobile", "celular", "telefone", "tel", "whatsapp"),
    Category.NAME: (
        "full_name",
        "first_name",
        "last_name",
        "surname",
        "given_name",
        "givenname",
        "family_name",
        "fullname",
        "nome",
        "name",
        # Columns that record who did something. They hold a person, and in
        # practice they usually hold that person's email address.
        "actor",
        "owner",
        "author",
        "created_by",
        "updated_by",
    ),
    Category.CPF: ("cpf",),
    Category.CNPJ: ("cnpj",),
    Category.SSN: ("ssn", "social_security", "national_id", "nif", "nino"),
    Category.CREDIT_CARD: ("card", "credit_card", "ccnum", "pan", "card_number"),
    Category.IP: ("ip", "ip_address", "remote_addr", "client_ip"),
    Category.POSTAL: ("postal", "zip", "zipcode", "cep"),
    Category.ADDRESS: ("address", "street", "addr", "logradouro", "rua", "endereco"),
}

#: Substrings that mark a column as prose, where a hit is expected.
TEXT_HINTS = (
    "body",
    "text",
    "notes",
    "note",
    "comment",
    "message",
    "bio",
    "description",
    "content",
    "payload",
    "search",
    "query",
    "free",
)

#: A value must look like this many percent of non-null samples to count.
MATCH_THRESHOLD = 0.6

#: Below this many non-null samples, content detection has nothing to go on.
MIN_SAMPLES = 4

#: Words that make a column a person or org name rather than free text.
_NAME_STOPWORDS = ("username", "filename", "hostname", "nickname")


@dataclass
class Evidence:
    """Why a column was classified, so a human can argue with the tool."""

    source: str  # "name" or "content"
    detail: str
    matches: int = 0
    samples: int = 0

    def describe(self) -> str:
        if self.source == "name":
            return f"column name suggests {self.detail}"
        ratio = self.matches / self.samples if self.samples else 0
        return f"{self.matches}/{self.samples} sampled values look like {self.detail} ({ratio:.0%})"


@dataclass
class Column:
    """One column and its verdict."""

    table: str
    name: str
    declared_type: str
    category: str | None
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)

    @property
    def is_pii(self) -> bool:
        return self.category is not None

    @property
    def path(self) -> str:
        return f"{self.table}.{self.name}"


def normalise(name: str) -> str:
    """``UserPhoneNumber`` / ``user_phone`` -> ``user_phone``."""
    # Split on a lower/digit -> upper boundary only, so acronyms survive:
    # "UserEmail" -> user_email, but "EMAIL" stays one token.
    cleaned = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[^a-z0-9]+", "_", cleaned.lower()).strip("_")


def detect_by_name(name: str) -> Category | None:
    """Classify from the column name alone."""
    normalised = normalise(name)
    if any(stop in normalised for stop in _NAME_STOPWORDS):
        return None
    tokens = normalised.split("_")

    # Leftmost match wins, longest wins within a position. So "email_address"
    # is an email and not a postal address, because the qualifying part comes
    # first. This is a heuristic and it can be argued with: "billing_address_email"
    # reads as an address by this rule. Override it with --category when the
    # detector guesses wrong on your schema.
    best: tuple[int, int, Category] | None = None
    for category, hints in NAME_HINTS.items():
        for hint in hints:
            position = tokens.index(hint) if hint in tokens else (0 if hint == normalised else -1)
            if position < 0 and hint in normalised:
                # A hint can also appear as part of a compound token, e.g.
                # "ipaddress" or "celular".
                position = normalised.index(hint)
            if position < 0:
                continue
            candidate = (position, -len(hint), category)
            if best is None or candidate < best:
                best = candidate
    if best:
        return best[2]

    for category, hints in NAME_HINTS.items():
        for hint in hints:
            if hint in normalised:
                return category
    return None


def detect_by_content(values: list[str]) -> tuple[Category | None, int]:
    """Classify from sampled values. Returns (category, matching samples)."""
    samples = [v.strip() for v in values if v and v.strip()]
    if len(samples) < MIN_SAMPLES:
        return None, 0

    for category, pattern in DETECTORS.items():
        matches = sum(1 for value in samples if pattern.match(value))
        if matches / len(samples) >= MATCH_THRESHOLD:
            return category, matches

    return None, 0


#: Unanchored variants, for finding an identifier *inside* a sentence. The
#: DETECTORS patterns are anchored so that a column of values is not mistaken
#: for a column that merely mentions one.
PROSE_PATTERNS: dict[str, re.Pattern[str]] = {
    Category.EMAIL: re.compile(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}"),
    Category.CPF: re.compile(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}"),
    Category.CNPJ: re.compile(r"\d{2}\.?\d{3}\.?\d{3}\.?\d{4}-?\d{2}"),
    Category.SSN: re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    Category.IP: re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
}

#: Categories worth scrubbing out of prose. A name is not PII on its own in a
#: support ticket, but an email address pasted into one certainly is.
_TEXT_SCRUBBABLE = (Category.EMAIL, Category.CPF, Category.CNPJ, Category.SSN, Category.IP)


def _detect_in_prose(values: list[str]) -> tuple[Category, int, int] | None:
    """Look for identifiers in a free-text column, with a much lower bar.

    The 60% threshold is right for a column of phone numbers, where anything
    else would be a mistake. It is far too high for a column of prose: real
    tickets mention one address each, so a column can be 95% innocent text and
    still leak every address in it.
    """
    samples = [v.strip() for v in values if v and v.strip()]
    if len(samples) < MIN_SAMPLES:
        return None
    for category in _TEXT_SCRUBBABLE:
        pattern = PROSE_PATTERNS[category]
        matches = sum(1 for value in samples if pattern.search(value))
        if matches:
            return category, matches, len(samples)
    return None


def _classify(name: str, values: list[str]) -> tuple[str | None, float, list[Evidence]]:
    """Combine both signals into one verdict with a confidence score."""
    evidence: list[Evidence] = []
    by_name = detect_by_name(name)
    by_content, matches = detect_by_content(values)
    samples = [v for v in values if v and v.strip()]

    if by_content:
        evidence.append(
            Evidence(
                "content",
                by_content,
                matches,
                len(samples),
            )
        )

    if by_name:
        evidence.append(Evidence("name", by_name))
        # Both signals agreeing is the strong case.
        if by_content == by_name:
            return by_name, 0.95, evidence
        # Only the name matched: trust it for the specific kinds, which a
        # content sample is unlikely to have confirmed by chance.
        if by_name in (Category.CPF, Category.CNPJ, Category.SSN, Category.EMAIL):
            return by_name, 0.7, evidence
        return by_name, 0.5, evidence

    normalised = normalise(name)
    looks_like_prose = any(hint in normalised for hint in TEXT_HINTS)

    if looks_like_prose:
        prose_hit = _detect_in_prose(values)
        if prose_hit:
            category, found, total = prose_hit
            evidence.append(Evidence("prose", category, found, total))
            return Category.FREE_TEXT, 0.8, evidence
        return None, 0.0, evidence

    if by_content:
        return by_content, 0.6, evidence

    return None, 0.0, evidence


def inspect_table(
    connection: sqlite3.Connection, table: str, sample_rows: int = 200
) -> list[Column]:
    """Inspect one table and classify each of its columns."""
    columns: list[Column] = []
    try:
        info = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    except sqlite3.Error:
        return columns
    if not info:
        return columns

    names = [row[1] for row in info]
    types = {row[1]: (row[2] or "") for row in info}

    quoted = ", ".join(f'"{name}"' for name in names)
    try:
        rows = connection.execute(
            f'SELECT {quoted} FROM "{table}" LIMIT ?', (sample_rows,)
        ).fetchall()
    except sqlite3.Error:
        rows = []

    for index, name in enumerate(names):
        values = [str(row[index]) for row in rows if row[index] is not None]
        category, confidence, evidence = _classify(name, values)
        columns.append(
            Column(
                table=table,
                name=name,
                declared_type=types.get(name, ""),
                category=category,
                confidence=confidence,
                evidence=evidence,
                samples=values[:5],
            )
        )

    return columns


def inspect_database(
    path: str, sample_rows: int = 200, min_confidence: float = 0.0
) -> list[Column]:
    """Inspect every user table in the database at ``path``."""
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        found: list[Column] = []
        for table in tables:
            for column in inspect_table(connection, table, sample_rows):
                if column.is_pii and column.confidence >= min_confidence:
                    found.append(column)
        return found
    finally:
        connection.close()
