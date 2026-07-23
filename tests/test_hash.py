# This file is part of rah-sha256-hasher, an example handler for rah.
# Copyright (c) Board of Regents of the University of Wisconsin System
# Distributed under the MIT license; see LICENSE in the project root.

import hashlib
import logging
from datetime import UTC, datetime

import pytest
import rah_sha256_hasher
from conftest import DELETE
from rah_sha256_hasher.handler import hash_field

from redcap_alert_handler.handlers import Message
from redcap_alert_handler.handlers.errors import PermanentError, TransientError
from redcap_alert_handler.handlers.loader import resolve_handler


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# The registration goes through real importlib.metadata, so this only passes
# once the package is installed into the venv with `uv sync`.
def test_entry_point_resolves_to_the_same_callable():
    resolved = resolve_handler("rah-sha256-hasher:hash_field")

    assert resolved is rah_sha256_hasher.hash_field


def test_happy_path_posts_the_expected_form_and_completes(
    fake_redcap, make_config, make_context, make_message, read_completed_at
):
    context = make_context(make_config())
    message = make_message(record_id="R-1001", value="mrn-8675309")

    hash_field(message, context)

    form = fake_redcap.last_form()
    assert form["content"] == "record"
    assert form["action"] == "import"
    assert form["format"] == "csv"
    assert form["token"] == "SECRET-TOKEN-DO-NOT-LOG"

    header, row = fake_redcap.last_csv_rows()
    assert header == ["record_id", "value_hash"]
    assert row == ["R-1001", sha256_hex("mrn-8675309")]

    assert read_completed_at(context.state_dir, message.internet_message_id) is not None


def test_logs_under_rah_hierarchy_and_never_logs_record_id_value_or_digest(
    fake_redcap, make_config, make_context, make_message, caplog
):
    context = make_context(make_config())
    message = make_message(record_id="R-1001", value="mrn-8675309")

    with caplog.at_level(logging.INFO, logger="redcap_alert_handler"):
        hash_field(message, context)

    ours = [
        record
        for record in caplog.records
        if record.name.startswith("redcap_alert_handler.handlers.rah_sha256_hasher")
    ]
    assert ours
    for record in ours:
        text = record.getMessage()
        assert "R-1001" not in text
        assert "mrn-8675309" not in text
        assert sha256_hex("mrn-8675309") not in text


def test_same_message_processed_once(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config())
    message = make_message(message_id="<only-once@example.edu>")

    hash_field(message, context)
    assert fake_redcap.request_count == 1

    hash_field(message, context)

    assert fake_redcap.request_count == 1


def test_different_messages_same_record_each_process(
    fake_redcap, make_config, make_context, make_message
):
    # Idempotency keys on the message, not the record: two distinct alerts
    # naming the same record are two separate writes, not a duplicate.
    context = make_context(make_config())

    hash_field(make_message(record_id="R-1001", message_id="<first@example.edu>"), context)
    hash_field(make_message(record_id="R-1001", message_id="<second@example.edu>"), context)

    assert fake_redcap.request_count == 2


def test_dry_run_returns_without_calling_or_storing_anything(
    fake_redcap, make_config, make_context, make_message, read_completed_at
):
    context = make_context(make_config(dry_run=True))
    message = make_message()

    # No raise: rah writes nothing back for a dry-run message, so the handler
    # just returns.
    hash_field(message, context)

    assert fake_redcap.request_count == 0
    # Nothing written to the store either -- no row for this message.
    assert read_completed_at(context.state_dir, message.internet_message_id) is None


def test_dry_run_leaves_the_message_for_a_later_real_run(
    fake_redcap, make_config, make_context, make_message, read_completed_at
):
    message = make_message(record_id="R-1001", value="mrn-8675309")

    hash_field(message, make_context(make_config(dry_run=True)))
    assert fake_redcap.request_count == 0

    # Same state dir (same slug), dry_run now off: the message processes for real.
    real_context = make_context(make_config())
    hash_field(message, real_context)

    _, row = fake_redcap.last_csv_rows()
    assert row == ["R-1001", sha256_hex("mrn-8675309")]
    assert fake_redcap.request_count == 1
    assert read_completed_at(real_context.state_dir, message.internet_message_id) is not None


def test_dry_run_logs_target_but_no_participant_data(
    fake_redcap, make_config, make_context, make_message, caplog
):
    context = make_context(make_config(dry_run=True))
    message = make_message(record_id="R-1001", value="mrn-8675309")

    with caplog.at_level(logging.INFO, logger="redcap_alert_handler"):
        hash_field(message, context)

    ours = [
        record
        for record in caplog.records
        if record.name.startswith("redcap_alert_handler.handlers.rah_sha256_hasher")
    ]
    assert ours
    joined = " ".join(record.getMessage() for record in ours)
    assert "https://redcap.example.edu/api/" in joined
    assert "value_hash" in joined
    assert "R-1001" not in joined
    assert "mrn-8675309" not in joined
    assert sha256_hex("mrn-8675309") not in joined


def test_non_bool_dry_run_is_permanent(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config(dry_run="yes"))

    with pytest.raises(PermanentError) as exc_info:
        hash_field(make_message(), context)

    assert "dry_run" in str(exc_info.value)


def test_timeout_retry_completes_on_the_same_message(
    fake_redcap, make_config, make_context, make_message, read_completed_at
):
    context = make_context(make_config())
    message = make_message(value="mrn-8675309")

    fake_redcap.raise_timeout()
    with pytest.raises(TransientError):
        hash_field(message, context)

    assert read_completed_at(context.state_dir, message.internet_message_id) is None

    fake_redcap.respond_ok()
    hash_field(message, context)

    header, row = fake_redcap.last_csv_rows()
    assert row[1] == sha256_hex("mrn-8675309")
    assert read_completed_at(context.state_dir, message.internet_message_id) is not None


def test_connect_error_is_permanent(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config())
    fake_redcap.raise_connect_error()

    with pytest.raises(PermanentError):
        hash_field(make_message(), context)


def test_error_status_is_permanent_and_leaks_no_record_id_or_value(
    fake_redcap, make_config, make_context, make_message, read_completed_at
):
    context = make_context(make_config())
    fake_redcap.respond_error(400, "The value you provided is out of range.")
    message = make_message(record_id="R-SECRET-9999", value="mrn-SECRET")

    with pytest.raises(PermanentError) as exc_info:
        hash_field(message, context)

    text = str(exc_info.value)
    assert "400" in text
    assert "out of range" in text
    assert "R-SECRET-9999" not in text
    assert "mrn-SECRET" not in text

    assert read_completed_at(context.state_dir, message.internet_message_id) is None


def test_wrong_count_is_permanent(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config())
    fake_redcap.respond_count(0)

    with pytest.raises(PermanentError):
        hash_field(make_message(), context)


def test_non_toml_body_is_permanent_with_no_request(
    fake_redcap, make_config, make_context, make_message
):
    context = make_context(make_config())
    message = make_message(body_text="this is not = valid = toml")

    with pytest.raises(PermanentError):
        hash_field(message, context)

    assert fake_redcap.request_count == 0


def test_body_missing_id_is_permanent(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config())
    message = make_message(body_text='value = "mrn-8675309"\n')

    with pytest.raises(PermanentError):
        hash_field(message, context)

    assert fake_redcap.request_count == 0


def test_body_missing_value_is_permanent(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config())
    message = make_message(body_text='id = "R-1001"\n')

    with pytest.raises(PermanentError):
        hash_field(message, context)

    assert fake_redcap.request_count == 0


def test_empty_value_is_permanent(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config())
    message = make_message(body_text='id = "R-1001"\nvalue = ""\n')

    with pytest.raises(PermanentError):
        hash_field(message, context)

    assert fake_redcap.request_count == 0


def test_none_body_is_permanent(fake_redcap, make_config, make_context):
    context = make_context(make_config())
    message = Message(
        internet_message_id="<msg-1@example.edu>",
        subject="REDCap alert",
        body_text=None,
        body_html=None,
        sender="redcap@example.edu",
        received_at=datetime(2026, 7, 12, 9, 30, tzinfo=UTC),
    )

    with pytest.raises(PermanentError):
        hash_field(message, context)

    assert fake_redcap.request_count == 0


def test_missing_config_key_names_the_key(fake_redcap, make_config, make_context, make_message):
    context = make_context(make_config(hashed_value_field=DELETE))

    with pytest.raises(PermanentError) as exc_info:
        hash_field(make_message(), context)

    assert "hashed_value_field" in str(exc_info.value)


def test_missing_info_file_is_permanent_and_leaks_no_token(
    fake_redcap, make_config, make_context, make_message, tmp_path
):
    missing = tmp_path / "nope" / "redcap_info.toml"
    context = make_context(make_config(redcap_info_file=str(missing)))

    with pytest.raises(PermanentError) as exc_info:
        hash_field(make_message(), context)

    assert "SECRET-TOKEN-DO-NOT-LOG" not in str(exc_info.value)


def test_info_file_missing_token_is_permanent(
    fake_redcap, make_config, make_context, make_message, write_info
):
    info_path = write_info({"url": "https://redcap.example.edu/api/"})
    context = make_context(make_config(info_path=info_path))

    with pytest.raises(PermanentError) as exc_info:
        hash_field(make_message(), context)

    assert "token" in str(exc_info.value)
