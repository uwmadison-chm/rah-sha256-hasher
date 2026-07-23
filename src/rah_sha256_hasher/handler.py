# This file is part of rah-sha256-hasher, an example handler for rah.
# Copyright (c) Board of Regents of the University of Wisconsin System
# Distributed under the MIT license; see LICENSE in the project root.

"""The hash_field handler: SHA-256 one field from the alert, write it to REDCap.

Each alert names one record and one value in its TOML body. The handler takes
the SHA-256 of the value (UTF-8, lowercase hex) and imports that digest into
`hashed_value_field` for the named record through the REDCap API. This is the
kind of thing REDCap can't do on its own -- a worked example that wires an
alert all the way through to a record write.

Nothing here logs a record id, the value, or the digest: the value comes from
a participant's record, so a hash of it is participant-adjacent too, and the
log lines carry only the message's internet id and what happened. The logger
comes from rah's `get_logger`, so those lines land in rah's own output
instead of an unconfigured hierarchy nobody sees. REDCap's own error text can
go into a `PermanentError` message, but the API token never does.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import httpx

from rah_sha256_hasher import store
from redcap_alert_handler import (
    Context,
    HandlerError,
    Message,
    PermanentError,
    TransientError,
    get_logger,
)

logger = get_logger(__name__)

REQUEST_TIMEOUT = 30.0


@dataclass(frozen=True, slots=True)
class _HandlerConfig:
    redcap_info_file: str
    redcap_id_field: str
    hashed_value_field: str
    dry_run: bool


@dataclass(frozen=True, slots=True)
class _RedcapInfo:
    url: str
    token: str


def _build_client() -> httpx.Client:
    # The one place a client is built, so a test can monkeypatch it to a
    # client wired to httpx.MockTransport without touching the network.
    return httpx.Client(timeout=REQUEST_TIMEOUT)


def _require_nonempty_str(config: Mapping[str, object], key: str) -> str:
    if key not in config:
        raise PermanentError(f"config is missing required key {key!r}")
    value = config[key]
    if not isinstance(value, str):
        raise PermanentError(f"config key {key!r} must be a string")
    if not value.strip():
        raise PermanentError(f"config key {key!r} must not be empty")
    return value


def _optional_bool(config: Mapping[str, object], key: str, default: bool) -> bool:
    if key not in config:
        return default
    value = config[key]
    if not isinstance(value, bool):
        raise PermanentError(f"config key {key!r} must be a boolean")
    return value


def _read_config(config: Mapping[str, object]) -> _HandlerConfig:
    return _HandlerConfig(
        redcap_info_file=_require_nonempty_str(config, "redcap_info_file"),
        redcap_id_field=_require_nonempty_str(config, "redcap_id_field"),
        hashed_value_field=_require_nonempty_str(config, "hashed_value_field"),
        dry_run=_optional_bool(config, "dry_run", default=False),
    )


def _read_body(body_text: str | None) -> tuple[str, str]:
    """Pull the record id and the value to hash out of the message's TOML body.

    This handler's alerts are TOML with a string `id` and a string `value`;
    other handlers can expect whatever body shape suits them. A blank `value`
    is a misfire -- an alert fired on an empty field -- and hashing it would
    write a constant digest to the record, so it's a `PermanentError` rather
    than something a retry could fix.
    """
    if body_text is None:
        raise PermanentError("message has no text body")
    try:
        data = tomllib.loads(body_text)
    except tomllib.TOMLDecodeError as e:
        raise PermanentError(f"message body is not valid TOML: {e}") from e

    record_id = data.get("id")
    if not isinstance(record_id, str):
        raise PermanentError("message body has no string 'id'")
    record_id = record_id.strip()
    if not record_id:
        raise PermanentError("message body 'id' is empty")

    value = data.get("value")
    if not isinstance(value, str):
        raise PermanentError("message body has no string 'value'")
    if not value:
        raise PermanentError("message body 'value' is empty")

    return record_id, value


def _read_info(path_str: str) -> _RedcapInfo:
    path = Path(path_str)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise PermanentError(f"could not read redcap_info_file {path_str!r}: {e}") from e
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise PermanentError(f"redcap_info_file {path_str!r} is not valid TOML: {e}") from e
    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        raise PermanentError(f"redcap_info_file {path_str!r} has no string 'url'")
    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        # Never put the token in an error; only its absence is reportable.
        raise PermanentError(f"redcap_info_file {path_str!r} has no string 'token'")
    return _RedcapInfo(url=url, token=token)


def _redcap_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict) and "error" in payload:
        return str(payload["error"])
    return response.text[:500]


def _import_record(info: _RedcapInfo, json_data: str) -> None:
    form = {
        "token": info.token,
        "content": "record",
        "action": "import",
        "format": "json",
        "overwriteBehavior": "normal",
        "forceAutoNumber": "false",
        "returnContent": "count",
        "data": json_data,
    }
    try:
        with _build_client() as client:
            response = client.post(info.url, data=form)
    except httpx.TimeoutException as e:
        raise TransientError(f"REDCap request timed out: {e}") from e
    except httpx.HTTPError as e:
        raise PermanentError(f"REDCap request failed: {e}") from e

    if response.status_code != 200:
        detail = _redcap_error_detail(response)
        raise PermanentError(f"REDCap returned HTTP {response.status_code}: {detail}")

    try:
        logger.debug(f"REDCap response: {response.text}")
        payload = response.json()
    except ValueError as e:
        raise PermanentError(f"REDCap response was not JSON: {response.text[:500]}") from e
    count = payload.get("count") if isinstance(payload, dict) else None
    if count != 1:
        raise PermanentError(f"REDCap imported {count!r} records, expected exactly 1")


def hash_field(message: Message, context: Context) -> None:
    """Hash the value named in the message and import the digest to REDCap.

    Reads its route's config (see the README for the keys), pulls `id` and
    `value` from the TOML body, claims the message in the store, and imports
    `sha256(value)` into `hashed_value_field` for record `id`. A message the
    store already has marked complete returns without an import. A REDCap
    timeout raises `TransientError` so the message retries; every other
    failure raises `PermanentError`.

    With `dry_run = true` on the route, it does everything up to the import --
    parse the body, read the info file, compute the digest -- then logs where
    it would have written and returns without calling REDCap or touching the
    store. rah writes nothing back for a dry-run message, so it stays in place;
    there's no separate signal to raise.
    """
    try:
        config = _read_config(context.config)
        record_id, value = _read_body(message.body_text)
        info = _read_info(config.redcap_info_file)
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()

        json_data = json.dumps(
            {
                config.redcap_id_field: record_id,
                config.hashed_value_field: digest
            }
        )
        logger.debug(f"Built JSON data: {json_data}")
        if config.dry_run:
            logger.info(
                "hash_field: dry run for %s -- would import to %s; REDCap not called",
                message.internet_message_id,
                info.url,
            )
            return

        db_path = context.state_dir / "processed.sqlite3"
        if store.claim(db_path, message.internet_message_id):
            logger.info("hash_field: %s already processed, skipping", message.internet_message_id)
            return

        _import_record(info, json_data)
        store.mark_completed(db_path, message.internet_message_id)
        logger.info("hash_field: hashed one field for %s", message.internet_message_id)
    except HandlerError:
        # TransientError and PermanentError are the handler's own vocabulary;
        # let them through untouched.
        raise
    except Exception as e:
        raise PermanentError(f"unexpected failure in hash_field handler: {e}") from e
