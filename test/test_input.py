import io
import json
import logging
from types import SimpleNamespace
from unittest.mock import Mock
from xml.etree import ElementTree

import cloudflare_access_auth_helper as helper
import pytest
from cloudflare_access import (
    Checkpoint,
    CollectionError,
    ErrorKind,
    FileState,
    parse_time,
)
from splunklib import modularinput as smi

ACCOUNT_ID = "a" * 32
STANZA = "cloudflare_access_auth://test"


@pytest.fixture
def harness(tmp_path, monkeypatch):
    logger = logging.getLogger("test_input")
    monkeypatch.setattr(
        helper.log, "Logs", lambda: SimpleNamespace(get_logger=lambda name: logger)
    )
    monkeypatch.setattr(helper.conf_manager, "get_log_level", lambda **kwargs: "INFO")
    account = {"account_id": ACCOUNT_ID, "api_token": "very-secret-token"}
    conf = Mock()
    conf.get_conf.return_value.get.return_value = account
    factory = Mock(return_value=conf)
    monkeypatch.setattr(helper.conf_manager, "ConfManager", factory)
    parameters = {
        "account": "cf",
        "index": "default",
        "interval": "300",
        "per_page": "100",
        "initial_lookback": "86400",
    }
    inputs = SimpleNamespace(
        inputs={STANZA: parameters},
        metadata={
            "session_key": "splunk-session-secret",
            "checkpoint_dir": str(tmp_path),
        },
    )
    return inputs, factory, tmp_path


def test_input_writes_one_json_event_and_uses_encrypted_account_realm(
    harness, monkeypatch
):
    inputs, factory, directory = harness
    original = {
        "created_at": "2026-10-06T00:00:00Z",
        "ray_id": "ray",
        "allowed": False,
        "unknown": ["é"],
    }

    def poll(client, checkpoint, until, per_page, emit, logger):
        stamp = parse_time(original["created_at"])
        emit(original, stamp)
        return Checkpoint(checkpoint.initial_since, stamp, {"ray": stamp})

    monkeypatch.setattr(helper, "poll", poll)
    output = io.StringIO()
    writer = smi.EventWriter(output=output)
    helper.stream_events(inputs, writer)
    writer.close()
    xml = ElementTree.fromstring(output.getvalue())
    events = xml.findall("event")
    assert len(events) == 1
    event = events[0]
    assert event.attrib["stanza"] == STANZA
    assert json.loads(event.findtext("data") or "{}") == original
    assert event.findtext("sourcetype") == "cloudflare:access:auth"
    assert event.findtext("source") == f"cloudflare:access:auth:{ACCOUNT_ID}"
    assert event.findtext("index") == "default"
    assert (
        float(event.findtext("time")) == parse_time(original["created_at"]).timestamp()  # ty: ignore[invalid-argument-type]
    )
    assert (
        factory.call_args.kwargs["realm"]
        == "__REST_CREDENTIAL__#TA_cloudflare_logs#configs/conf-ta_cloudflare_logs_account"
    )
    state = FileState(directory, next(directory.glob("*.json")).stem).load()
    assert state.max_created_at == parse_time(original["created_at"])
    assert "very-secret-token" not in next(directory.glob("*.json")).read_text()


def test_initial_checkpoint_survives_failure_and_failed_poll_never_advances(
    harness, monkeypatch, caplog
):
    inputs, _, directory = harness
    monkeypatch.setattr(
        helper, "poll", Mock(side_effect=CollectionError(ErrorKind.HTTP, 503))
    )
    with pytest.raises(RuntimeError), caplog.at_level(logging.ERROR):
        helper.stream_events(inputs, Mock())
    path = next(directory.glob("*.json"))
    initial = json.loads(path.read_text())
    assert initial["max_created_at"] is None

    def fail(client, checkpoint, *args):
        assert checkpoint.encode() == initial
        raise RuntimeError("very-secret-token splunk-session-secret")

    monkeypatch.setattr(helper, "poll", fail)
    with pytest.raises(RuntimeError):
        helper.stream_events(inputs, Mock())
    assert json.loads(path.read_text()) == initial
    assert "very-secret-token" not in caplog.text
    assert "splunk-session-secret" not in caplog.text


def test_disabled_input_does_not_read_secrets_or_poll(harness):
    inputs, factory, directory = harness
    inputs.inputs[STANZA]["disabled"] = "true"
    helper.stream_events(inputs, Mock())
    factory.assert_not_called()
    assert list(directory.iterdir()) == []


def test_changing_destination_index_isolates_checkpoint(harness, monkeypatch):
    inputs, _, directory = harness
    seen = []

    def collect(client, checkpoint, *args):
        seen.append(checkpoint.max_created_at)
        return Checkpoint(checkpoint.initial_since, parse_time("2026-10-06T00:00:00Z"))

    monkeypatch.setattr(helper, "poll", collect)
    helper.stream_events(inputs, Mock())
    helper.stream_events(inputs, Mock())
    inputs.inputs[STANZA]["index"] = "security"
    helper.stream_events(inputs, Mock())
    assert seen == [None, parse_time("2026-10-06T00:00:00Z"), None]
    assert len(list(directory.glob("*.json"))) == 2


def test_global_config_encryption_and_new_input_defaults():
    from pathlib import Path

    config = json.loads(
        (Path(__file__).resolve().parents[1] / "globalConfig.json").read_text()
    )
    account = config["pages"]["configuration"]["tabs"][0]
    fields = {entity["field"]: entity for entity in account["entity"]}
    assert fields["api_token"]["encrypted"] is True
    assert fields["api_token"]["required"] is True
    service = config["pages"]["inputs"]["services"][0]
    assert service["disableNewInput"] is True
    assert service["inputHelperModule"] == "cloudflare_access_auth_helper"


def test_rate_limit_cooldown_is_persisted_without_advancing_timestamp(
    harness, monkeypatch
):
    from datetime import datetime, timedelta, timezone

    inputs, _factory, directory = harness
    retry_at = datetime.now(timezone.utc) + timedelta(hours=1)
    collect = Mock(side_effect=CollectionError(ErrorKind.RATE_LIMIT, 429, retry_at))
    monkeypatch.setattr(helper, "poll", collect)
    with pytest.raises(RuntimeError):
        helper.stream_events(inputs, Mock())
    path = next(directory.glob("*.json"))
    store = FileState(directory, path.stem)
    state = store.load()
    assert state.max_created_at is None
    assert state.retry_not_before == retry_at
    helper.stream_events(inputs, Mock())
    assert collect.call_count == 1
