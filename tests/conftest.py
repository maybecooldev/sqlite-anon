import sqlite3

import pytest

PEOPLE = [
    (
        "ana.silva@empresa.com.br",
        "Ana Silva",
        "+55 (11) 98765-4321",
        "123.456.789-00",
        "BR",
        "Prefere contato por email ana.silva@empresa.com.br",
    ),
    (
        "bruno.costa@empresa.com.br",
        "Bruno Costa",
        "11 98888-7777",
        "987.654.321-00",
        "BR",
        "solicitou retorno",
    ),
    ("carla.dias@outro.com", "Carla Dias", "+55 21 3555-1234", "111.222.333-44", "PT", "atendente"),
    ("dana@exemplo.org", "Dana Alves", None, None, "US", ""),
    # Same person as row 0, on purpose: referential integrity has to survive.
    (
        "ana.silva@empresa.com.br",
        "Ana Silva",
        "+55 (11) 98765-4321",
        "123.456.789-00",
        "BR",
        "segunda linha",
    ),
]


@pytest.fixture
def demo_db(tmp_path):
    """A small database with a foreign key and duplicated PII."""
    path = tmp_path / "demo.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            full_name TEXT,
            phone TEXT,
            cpf TEXT,
            country TEXT,
            notes TEXT
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            total REAL,
            client_ip TEXT
        );
        CREATE TABLE audit (
            id INTEGER PRIMARY KEY,
            actor TEXT,
            at TEXT
        );
        """
    )
    connection.executemany(
        "INSERT INTO users (email, full_name, phone, cpf, country, notes) VALUES (?,?,?,?,?,?)",
        PEOPLE,
    )
    connection.executemany(
        "INSERT INTO orders (user_id, total, client_ip) VALUES (?,?,?)",
        [
            (1, 99.9, "192.168.1.44"),
            (1, 15.0, "10.0.0.7"),
            (2, 250.0, "192.168.1.44"),
            (3, 42.0, "8.8.8.8"),
        ],
    )
    connection.executemany(
        "INSERT INTO audit (actor, at) VALUES (?,?)",
        [("ana.silva@empresa.com.br", "2026-01-01"), ("root", "2026-01-02")],
    )
    connection.commit()
    connection.close()
    return str(path)


@pytest.fixture
def key():
    return b"\x01" * 32
