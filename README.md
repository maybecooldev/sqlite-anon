# sqlite-anon

Make an anonymised copy of a SQLite database without breaking its joins.

Handing someone a database dump to debug a bug is normal. Handing them the
customer's email addresses, phone numbers and tax IDs along with it is a
reportable incident under GDPR and LGPD. `sqlite-anon` writes a copy with the
personal data replaced, and — this is the part that matters — a copy that
still behaves like the original: foreign keys still join, `GROUP BY email`
still groups, and the same person is the same person in every table.

```
$ sqlite-anon app.db --report
app.db: 3 table(s), 11 row(s)

  orders.client_ip                 ip             0.95
      4/4 sampled values look like ip (100%)
      column name suggests ip
  users.email                      email          0.95
      5/5 sampled values look like email (100%)
      column name suggests email
  users.full_name                  name           0.50
      column name suggests name
  users.notes                      free_text      0.80
      1/4 sampled values look like email (25%)

$ sqlite-anon app.db -o app.anon.db --key-file .anon.key --create-key
wrote app.anon.db
  7 column(s) rewritten across 11 row(s)
```

Nothing is written until you ask for it. `--report` is read-only.

## Install

```sh
pipx install sqlite-anon
```

No runtime dependencies — `sqlite3`, `hmac`, `hashlib` and `secrets` are all
in the standard library.

## How it works

**Detection** uses two independent signals. The column *name* is checked
against a table of hints (`email`, `mobile_phone`, `cpf`, `client_ip`…); the
column *contents* are checked against patterns. Name detection alone misses
free-text columns, and content detection alone flags any column that happens
to contain six digits, so the rules combine them: both agreeing is high
confidence, only the name matching is medium, and a disagreement is reported
rather than hidden.

Every finding carries its own reasoning, because a detector you cannot argue
with is a detector you will eventually turn off.

**Rewriting** is deterministic and format-preserving:

- *Deterministic* — `HMAC-SHA256(key, category + value)`. The same input
  always produces the same output, which is what keeps joins and grouping
  intact, and what makes a bug that only reproduces for one user still
  reproducible. The category is inside the HMAC, so the same string used as an
  email and as a phone number does not produce the same fake — otherwise the
  columns could be lined up and the original recovered.
- *Format-preserving* — `+55 (11) 98765-4321` keeps every separator and every
  digit-run length. Generated CPFs and CNPJs carry valid check digits and
  cards pass Luhn, so downstream validation keeps working. A dataset where
  every phone is the same length of random digits still leaks the shape of the
  real one.

The original file is opened read-only and never written to. The output is
built row by row, so a failure halfway through leaves the original intact and
the partial output disposable.

## The key

`--key-file` holds the 32-byte HMAC key, created with mode `0600`. Two
databases anonymised with the same key map consistently, so you can join
across them.

Losing the key means the mapping is gone for good. That is the point. If you
do not pass `--key-file`, a random key is generated for that run and the
result cannot be reproduced — the tool says so on stderr.

## Usage

```sh
sqlite-anon app.db --report                  # what would change, write nothing
sqlite-anon app.db --report --format json    # same, machine-readable
sqlite-anon app.db -o app.anon.db            # write a copy
sqlite-anon app.db --category email          # override the detector
sqlite-anon app.db --min-confidence 0.9      # only the high-confidence findings
sqlite-anon app.db --category email --report # check the override first
```

When the detector guesses wrong, `--category` is the override. Check it with
`--report` before writing.

## What it detects

| Category | Recognised by |
| --- | --- |
| `email` | column name, or an address-shaped value |
| `phone` | name, or a digit run with plausible punctuation |
| `name` | name; values that are actually addresses are routed to the email handler |
| `cpf`, `cnpj` | name, or a value matching the Brazilian format |
| `ssn` | name, or `NNN-NN-NNNN` |
| `credit_card` | name, or 13–19 digits |
| `ip` | name, or four dotted octets |
| `postal` | name, or `NNNNN-NNN` |
| `address` | name |
| `free_text` | a prose column containing an email, CPF, CNPJ, SSN or IP |

The `free_text` rule uses a much lower bar than the others on purpose. A
column of phone numbers needs 60% of its values to match before it counts,
because anything else would be a mistake. A column of support tickets needs
one address in it to be a leak, because real tickets mention one address
each — a column can be 95% innocent text and still leak every address in it.

## Known limits

- **Detection needs at least 4 non-null samples per column.** Below that,
  content detection declines to guess and only the column name is used. A
  table with two rows may pass PII through untouched. `--report` is how you
  find out.
- **Only text is rewritten.** A column of integers that is misdetected comes
  out still holding integers, which is safer than the reverse but means a
  numeric identifier column is not covered.
- **The word lists are small and Brazilian.** Names come from a list of about
  forty given names and surnames. The goal is a value that is obviously
  synthetic, not a realistic one.
- **This is pseudonymisation, not anonymisation.** The values are derived, so
  anyone holding the key can reverse the mapping. Under GDPR that is still
  personal data. Treat the output as sensitive.
- `matches`-style free-text scrubbing covers email, CPF, CNPJ, SSN and IP.
  Other identifiers in a text column pass through.

## Development

```sh
git clone https://github.com/maybecooldev/sqlite-anon
cd sqlite-anon
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

93 tests. The ones that matter most are in `tests/test_anonymize.py`: they
assert that the foreign key join returns the same pairs, that the same person
maps to the same value in every table, and that no original PII survives in
the output.

## License

MIT
