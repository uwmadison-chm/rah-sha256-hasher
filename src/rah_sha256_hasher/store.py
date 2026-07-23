# This file is part of rah-sha256-hasher, an example handler for rah.
# Copyright (c) Board of Regents of the University of Wisconsin System
# Distributed under the MIT license; see LICENSE in the project root.

"""The sqlite claim store that keeps one message from being hashed in twice.

A handler that times out is abandoned, not killed: the watcher counts the
attempt as a transient failure and comes around again while the first thread
may still be finishing its import. rah keys idempotency on the message, so
the thing this store guards is the message id -- process each alert once, no
matter how many times a retry hands it back.

Unlike a handler that picks a value at random, there is nothing here to pin:
the hash is a pure function of the message body, so a retry re-derives the
same digest on its own and this store never has to remember it. It carries
just the message id and whether that message finished. `claim` records the id
before the import runs and reports whether the message is already done;
`mark_completed` stamps it once REDCap has accepted the write. A row with a
null `completed_at` is a message that was claimed but never confirmed done --
a first attempt that timed out mid-import, say -- and a retry is free to run
it again, since importing the same record's same value twice is harmless.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

_CONNECT_TIMEOUT = 30.0

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS processed_messages (
    internet_message_id TEXT PRIMARY KEY,
    completed_at TEXT
)
"""


def claim(db_path: Path, internet_message_id: str) -> bool:
    """Record a message id before its import runs; report whether it's already done.

    The insert only takes effect the first time a message is seen; a later
    call for the same id leaves the row alone. Returns True when the message
    has already been marked completed, so the caller can skip the import
    entirely, and False when it still needs to run -- whether this is the
    first attempt or a retry of one that never confirmed.
    """
    with closing(sqlite3.connect(db_path, timeout=_CONNECT_TIMEOUT)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(_CREATE_TABLE)
        with connection:
            connection.execute(
                "INSERT INTO processed_messages (internet_message_id) VALUES (?) "
                "ON CONFLICT (internet_message_id) DO NOTHING",
                (internet_message_id,),
            )
            row = connection.execute(
                "SELECT completed_at FROM processed_messages WHERE internet_message_id = ?",
                (internet_message_id,),
            ).fetchone()
        (completed_at,) = row
        return completed_at is not None


def mark_completed(db_path: Path, internet_message_id: str) -> None:
    """Stamp a message as processed, once REDCap has accepted the import."""
    with closing(sqlite3.connect(db_path, timeout=_CONNECT_TIMEOUT)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(_CREATE_TABLE)
        with connection:
            connection.execute(
                "UPDATE processed_messages SET completed_at = ? WHERE internet_message_id = ?",
                (datetime.now(UTC).isoformat(), internet_message_id),
            )
