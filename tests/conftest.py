# This file is part of rah-sha256-hasher, an example handler for rah.
# Copyright (c) Board of Regents of the University of Wisconsin System
# Distributed under the MIT license; see LICENSE in the project root.

import json
import sqlite3
import urllib.parse
from datetime import UTC, datetime

import httpx
import pytest
from rah_sha256_hasher import handler

from redcap_alert_handler.handlers import Context, Message

# A sentinel a config override can use to drop a key that the base config
# would otherwise include, so a test can build a config that is missing one.
DELETE = object()


class FakeRedcap:
    """A stand-in REDCap that records every request and answers on demand.

    A test picks one of the `respond_*` / `raise_*` modes, runs the handler,
    and then reads back the requests it saw to check the form fields and the
    JSON that was posted.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self._responder = self._respond_ok

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responder(request)

    def _respond_ok(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"count": 1})

    def respond_ok(self) -> None:
        self._responder = self._respond_ok

    def respond_count(self, count: object) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"count": count})

        self._responder = responder

    def respond_error(self, status_code: int, error: str) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, json={"error": error})

        self._responder = responder

    def raise_timeout(self) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("simulated timeout")

        self._responder = responder

    def raise_connect_error(self) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated connection failure")

        self._responder = responder

    def build_client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handle))

    @property
    def request_count(self) -> int:
        return len(self.requests)

    def last_form(self) -> dict[str, str]:
        request = self.requests[-1]
        return dict(urllib.parse.parse_qsl(request.content.decode()))

    def last_json_records(self) -> list[dict[str, str]]:
        return json.loads(self.last_form()["data"])


@pytest.fixture
def fake_redcap(monkeypatch):
    fake = FakeRedcap()
    monkeypatch.setattr(handler, "_build_client", fake.build_client)
    return fake


@pytest.fixture
def write_info(tmp_path):
    """Write a redcap_info TOML file and return its path.

    Pass `contents` to control exactly what lands in the file; the default is
    a usable url/token pair.
    """

    def write(contents: dict[str, str] | None = None):
        if contents is None:
            contents = {
                "url": "https://redcap.example.edu/api/",
                "token": "SECRET-TOKEN-DO-NOT-LOG",
                "salt": "SECRET-SALT-DO-NOT-LOG",
            }
        path = tmp_path / "redcap_info.toml"
        lines = [f'{key} = "{value}"' for key, value in contents.items()]
        path.write_text("\n".join(lines) + "\n")
        return path

    return write


@pytest.fixture
def make_config(write_info):
    def build(info_path=None, **overrides):
        if info_path is None:
            info_path = write_info()
        config = {
            "redcap_info_file": str(info_path),
            "redcap_id_field": "record_id",
            "hashed_value_field": "value_hash",
        }
        for key, value in overrides.items():
            if value is DELETE:
                config.pop(key, None)
            else:
                config[key] = value
        return config

    return build


@pytest.fixture
def make_context(tmp_path):
    """Build a Context whose state_dir already exists, as the watcher leaves it."""

    def build(config, slug="hasher"):
        state_dir = tmp_path / "state" / slug
        state_dir.mkdir(parents=True, exist_ok=True)
        return Context(slug=slug, config=config, state_dir=state_dir)

    return build


@pytest.fixture
def make_message():
    def build(
        record_id="R-1001",
        value="mrn-8675309",
        body_text=None,
        message_id="<msg-1@example.edu>",
    ):
        if body_text is None:
            body_text = f'id = "{record_id}"\nvalue = "{value}"\n'
        return Message(
            internet_message_id=message_id,
            subject="REDCap alert",
            body_text=body_text,
            body_html=None,
            sender="redcap@example.edu",
            received_at=datetime(2026, 7, 12, 9, 30, tzinfo=UTC),
        )

    return build


@pytest.fixture
def read_completed_at():
    """Read completed_at for a message id straight out of the sqlite file."""

    def read(state_dir, internet_message_id):
        db_path = state_dir / "processed.sqlite3"
        with sqlite3.connect(db_path) as connection:
            try:
                row = connection.execute(
                    "SELECT completed_at FROM processed_messages WHERE internet_message_id = ?",
                    (internet_message_id,),
                ).fetchone()
            except sqlite3.OperationalError:
                # A dry run never creates the store, so the table won't exist;
                # that's the same "nothing recorded" answer as an empty table.
                return None
        return row[0] if row is not None else None

    return read
