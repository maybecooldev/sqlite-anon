"""sqlite-anon — anonymise a SQLite database without breaking its joins."""

from .anonymize import Plan, anonymize, build_plan
from .detect import CATEGORIES, Category, Column, inspect_database
from .transform import AnonymisationError, Anonymizer, load_or_create_key

__version__ = "0.1.0"

__all__ = [
    "CATEGORIES",
    "AnonymisationError",
    "Anonymizer",
    "Category",
    "Column",
    "Plan",
    "__version__",
    "anonymize",
    "build_plan",
    "inspect_database",
    "load_or_create_key",
]
