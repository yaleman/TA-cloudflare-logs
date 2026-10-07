import logging
from datetime import timedelta
from unittest.mock import Mock

import pytest
import requests
from cloudflare_access import (
    Checkpoint,
    CloudflareClient,
    CollectionError,
    ErrorKind,
    FileState,
    integer_option,
    parse_time,
    poll,
    validate_account,
)

LOGGER = logging.getLogger("test_cloudflare")
START = parse_time("2026-10-06T00:00:00Z")
END = START + timedelta(hours=1)


def record(seconds, ray="ray", **extra):
    return {
        "created_at": (START + timedelta(seconds=seconds)).isoformat(),
        "ray_id": ray,
        **extra,
    }


def response(status=200, body=None, headers=None):
    result = Mock(status_code=status, headers=headers or {})
    result.json.return_value = (
        body if body is not None else {"success": True, "result": []}
    )
    return result


def client(pages):
    session = Mock()
    session.get.side_effect = pages
    sleep = Mock()
    return (
        CloudflareClient(session, "a" * 32, "secret-token", LOGGER, sleep),
        session,
        sleep,
    )


def test_pagination_uses_fixed_window_and_does_not_stop_on_short_page():
    api, session, _ = client(
        [
            response(body={"success": True, "result": [record(20, "one")]}),
            response(body={"success": True, "result": [record(30, "two")]}),
            response(),
        ]
    )
    events = []
    original = Checkpoint(START)
    result = poll(
        api, original, END, 100, lambda data, stamp: events.append(data), LOGGER
    )
    assert [event["ray_id"] for event in events] == ["one", "two"]
    assert result.max_created_at == START + timedelta(seconds=30)
    assert original.max_created_at is None
    assert [call.kwargs["params"]["page"] for call in session.get.call_args_list] == [
        1,
        2,
        3,
    ]
    for call in session.get.call_args_list:
        assert call.kwargs["params"] == {
            "since": "2026-10-06T00:00:00Z",
            "until": "2026-10-06T01:00:00Z",
            "direction": "asc",
            "page": call.kwargs["params"]["page"],
            "per_page": 100,
        }
        assert call.kwargs["allow_redirects"] is False
        assert call.kwargs["timeout"] == (10, 60)


def test_overlap_deduplicates_boundary_and_new_ids_at_same_timestamp():
    maximum = START + timedelta(seconds=120)
    state = Checkpoint(
        START, maximum, {"old": maximum, "edge": maximum - timedelta(seconds=60)}
    )
    api = Mock()
    api.page.side_effect = [
        [record(60, "edge"), record(120, "old"), record(120, "new")],
        [],
    ]
    events = []
    result = poll(api, state, END, 100, lambda data, stamp: events.append(data), LOGGER)
    assert [event["ray_id"] for event in events] == ["new"]
    assert api.page.call_args_list[0].args[0] == maximum - timedelta(seconds=60)
    assert result.max_created_at == maximum
    assert set(result.recent_ids) == {"old", "edge", "new"}
    assert set(state.recent_ids) == {"old", "edge"}


def test_deduplication_across_pages_and_pruning():
    api = Mock()
    api.page.side_effect = [
        [record(0, "old"), record(10, "a")],
        [record(10, "a"), record(120, "b")],
        [],
    ]
    events = []
    result = poll(
        api,
        Checkpoint(START),
        END,
        100,
        lambda data, stamp: events.append(data),
        LOGGER,
    )
    assert [event["ray_id"] for event in events] == ["old", "a", "b"]
    assert set(result.recent_ids) == {"b"}


def test_malformed_objects_are_preserved_and_non_objects_skipped(caplog):
    api = Mock()
    invalid = {"created_at": "broken", "extra": {"x": [1, True]}, "ray_id": "bad"}
    no_ray = record(10, None, unknown="preserved")
    api.page.side_effect = [[None, "invalid", invalid, no_ray], []]
    events = []
    with caplog.at_level(logging.WARNING):
        result = poll(
            api,
            Checkpoint(START),
            END,
            100,
            lambda data, stamp: events.append((data, stamp)),
            LOGGER,
        )
    assert events == [(invalid, None), (no_ray, START + timedelta(seconds=10))]
    assert result.recent_ids == {}
    assert result.max_created_at == START + timedelta(seconds=10)
    assert "Malformed records=3" in caplog.text
    assert "broken" not in caplog.text


@pytest.mark.parametrize(
    "failure", [CollectionError(ErrorKind.HTTP, 500), RuntimeError("write failed")]
)
def test_failed_page_or_writer_leaves_original_state_untouched(failure):
    original = Checkpoint(START)
    api = Mock()
    api.page.side_effect = [[record(10)], failure]
    events = []

    def emit(data, stamp):
        if isinstance(failure, RuntimeError):
            raise failure
        events.append(data)

    with pytest.raises(type(failure)):
        poll(api, original, END, 100, emit, LOGGER)
    assert original.encode() == Checkpoint(START).encode()


def test_repeated_page_fails_instead_of_skipping_data():
    api = Mock()
    api.page.side_effect = [[record(10)], [record(10)]]
    with pytest.raises(CollectionError) as failure:
        poll(api, Checkpoint(START), END, 100, Mock(), LOGGER)
    assert failure.value.kind is ErrorKind.PAGINATION


def test_api_records_outside_window_are_filtered_without_advancing_checkpoint():
    api = Mock()
    api.page.side_effect = [
        [record(-1, "older"), record(10, "valid"), record(3601, "future")],
        [],
    ]
    emitted = []
    result = poll(
        api,
        Checkpoint(START),
        END,
        100,
        lambda data, stamp: emitted.append(data),
        LOGGER,
    )
    assert [event["ray_id"] for event in emitted] == ["valid"]
    assert result.max_created_at == START + timedelta(seconds=10)
    assert set(result.recent_ids) == {"valid"}


@pytest.mark.parametrize(
    "status,kind",
    [
        (401, ErrorKind.AUTHORIZATION),
        (403, ErrorKind.AUTHORIZATION),
        (400, ErrorKind.HTTP),
        (302, ErrorKind.HTTP),
    ],
)
def test_non_retryable_errors(status, kind, caplog):
    reply = response(status, body={"secret-token": "must not log"})
    api, session, sleep = client([reply])
    with pytest.raises(CollectionError) as failure:
        api.page(START, END, 1, 100)
    assert failure.value.kind is kind
    assert failure.value.status == status
    assert session.get.call_count == 1
    sleep.assert_not_called()
    reply.close.assert_called_once()
    assert "secret-token" not in caplog.text


def test_rate_limit_and_server_error_backoff(caplog):
    api, session, sleep = client(
        [response(429, headers={"Retry-After": "12"}), response(503), response()]
    )
    with caplog.at_level(logging.WARNING):
        assert api.page(START, END, 1, 100) == []
    assert sleep.call_args_list[0].args[0] == 12
    assert 2 <= sleep.call_args_list[1].args[0] <= 3
    assert session.get.call_count == 3
    assert "secret-token" not in caplog.text


def test_retry_exhaustion():
    api, session, sleep = client([requests.Timeout("secret-token")] * 5)
    with pytest.raises(CollectionError) as failure:
        api.page(START, END, 1, 100)
    assert failure.value.kind is ErrorKind.TRANSPORT
    assert session.get.call_count == 5
    assert sleep.call_count == 4
    assert "secret-token" not in str(failure.value)


def test_long_retry_after_defers_to_next_scheduled_poll():
    api, _session, sleep = client([response(429, headers={"Retry-After": "600"})])
    with pytest.raises(CollectionError) as failure:
        api.page(START, END, 1, 100)
    assert failure.value.kind is ErrorKind.RATE_LIMIT
    sleep.assert_not_called()


@pytest.mark.parametrize(
    "body",
    [
        {"success": False, "result": []},
        {"success": True},
        {"success": True, "result": {}},
        [],
    ],
)
def test_bad_api_envelope(body):
    reply = response()
    reply.json.return_value = body
    api, _, sleep = client([reply])
    with pytest.raises(CollectionError) as failure:
        api.page(START, END, 1, 100)
    assert failure.value.kind is ErrorKind.RESPONSE
    sleep.assert_not_called()


def test_invalid_json_and_tls_fail_safely():
    reply = response()
    reply.json.side_effect = ValueError("secret-token")
    api, _, _ = client([reply])
    with pytest.raises(CollectionError) as failure:
        api.page(START, END, 1, 100)
    assert failure.value.kind is ErrorKind.RESPONSE
    api, session, _ = client([requests.exceptions.SSLError("secret-token")])
    with pytest.raises(CollectionError) as failure:
        api.page(START, END, 1, 100)
    assert failure.value.kind is ErrorKind.TLS
    assert session.get.call_count == 1


def test_checkpoint_roundtrip_lock_and_corruption(tmp_path):
    store = FileState(tmp_path, "input")
    with store.locked() as acquired:
        assert acquired
        assert store.load() is None
        state = Checkpoint(START, START, {"ray": START})
        store.save(state)
        assert store.load() == state
        assert store.path.stat().st_mode & 0o777 == 0o600
        with FileState(tmp_path, "input").locked() as second:
            assert not second
    with store.locked() as acquired:
        assert acquired
    store.path.write_text("{broken")
    with pytest.raises(CollectionError) as failure:
        store.load()
    assert failure.value.kind is ErrorKind.CHECKPOINT


def test_failed_atomic_replace_preserves_previous_checkpoint(tmp_path, monkeypatch):
    store = FileState(tmp_path, "input")
    original = Checkpoint(START)
    store.save(original)
    monkeypatch.setattr(
        "cloudflare_access.os.replace", Mock(side_effect=OSError("disk full"))
    )
    with pytest.raises(CollectionError):
        store.save(Checkpoint(START, END))
    assert store.load() == original
    assert list(tmp_path.iterdir()) == [store.path]


@pytest.mark.parametrize("value", ["oops", "-1", "1.5", "2592001", True])
def test_invalid_lookback(value):
    with pytest.raises(CollectionError) as failure:
        integer_option(value, 86400, 0, 2592000)
    assert failure.value.kind is ErrorKind.CONFIGURATION


def test_config_and_empty_checkpoint():
    assert integer_option("", 86400, 0, 2592000) == 86400
    assert validate_account({"account_id": "a" * 32, "api_token": "token"}) == (
        "a" * 32,
        "token",
    )
    with pytest.raises(CollectionError):
        validate_account({"account_id": "../bad", "api_token": "token"})
    with pytest.raises(CollectionError):
        Checkpoint.decode({"version": 2})
    api = Mock()
    api.page.return_value = []
    initial = Checkpoint(START)
    assert poll(api, initial, END, 100, Mock(), LOGGER) == initial


def test_retry_after_http_date():
    from datetime import datetime, timezone
    from email.utils import format_datetime

    future = datetime.now(timezone.utc) + timedelta(seconds=90)
    api, _, sleep = client(
        [response(429, headers={"Retry-After": format_datetime(future)}), response()]
    )
    assert api.page(START, END, 1, 100) == []
    assert 88 <= sleep.call_args.args[0] <= 90


def test_boundary_capacity_fails_without_mutating_state(monkeypatch):
    monkeypatch.setattr("cloudflare_access.MAX_RECENT_IDS", 1)
    api = Mock()
    api.page.return_value = [record(10, "a"), record(10, "b")]
    initial = Checkpoint(START)
    with pytest.raises(CollectionError) as failure:
        poll(api, initial, END, 100, Mock(), LOGGER)
    assert failure.value.kind is ErrorKind.CAPACITY
    assert initial.recent_ids == {}


def test_clock_rollback_does_not_query_future_window():
    api = Mock()
    state = Checkpoint(END)
    assert poll(api, state, START, 100, Mock(), LOGGER) == state
    api.page.assert_not_called()
