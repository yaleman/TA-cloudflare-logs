import importlib.util
import json
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "live_testing.py"
spec = importlib.util.spec_from_file_location("live_testing", MODULE_PATH)
live = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = live
spec.loader.exec_module(live)


def test_init_protects_credentials_and_refuses_overwrite(tmp_path):
    path = tmp_path / ".live" / "config.json"
    live.initialize(path)
    assert path.stat().st_mode & 0o777 == 0o600
    config = live.load_config(path)
    assert len(config.password) >= 12
    assert config.api_token == ""
    with pytest.raises(live.TestFailure):
        live.initialize(path)
    path.chmod(0o644)
    with pytest.raises(live.TestFailure):
        live.load_config(path)


def test_upsert_uses_structured_missing_status_and_rejects_collision():
    splunk = live.Splunk(live.Config("secret-password"))
    splunk.request = Mock(side_effect=[{"entry": []}, {}])
    splunk.upsert("/endpoint", "test", {"token": "secret"})
    assert splunk.request.call_args.args == (
        "POST",
        "/endpoint",
        {"name": "test", "token": "secret"},
    )
    splunk.request = Mock(
        return_value={
            "entry": [{"name": "test", "content": {"account_id": "different"}}]
        }
    )
    with pytest.raises(live.TestFailure) as failure:
        splunk.upsert(
            "/endpoint", "test", {"token": "secret"}, expected={"account_id": "wanted"}
        )
    assert failure.value.kind is live.FailureKind.COLLISION
    assert splunk.request.call_count == 1
    splunk.close()


@pytest.mark.parametrize(
    "status,kind",
    [
        (401, live.FailureKind.AUTHORIZATION),
        (403, live.FailureKind.AUTHORIZATION),
        (409, live.FailureKind.HTTP),
        (302, live.FailureKind.HTTP),
    ],
)
def test_http_errors_do_not_include_response_secrets(status, kind):
    splunk = live.Splunk(live.Config("secret-password"))
    response = Mock(status_code=status)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.text = "secret-password api-token"
    splunk.session.request = Mock(return_value=response)
    with pytest.raises(live.TestFailure) as failure:
        splunk.request("POST", "/endpoint")
    assert failure.value.kind is kind
    assert "secret-password" not in str(failure.value)
    assert splunk.session.request.call_args.kwargs["allow_redirects"] is False
    assert splunk.url == "https://127.0.0.1:18090"
    splunk.close()


def test_structural_event_validation():
    expected = {"ray": {"ray_id": "ray", "allowed": False, "extra": {"x": [1, 2]}}}
    rows = [{"_raw": '{"extra":{"x":[1,2]}, "allowed": false, "ray_id":"ray"}'}]
    assert live.verify_events(rows, expected) == {"ray"}
    with pytest.raises(live.TestFailure) as failure:
        live.verify_events([{"_raw": '{"ray_id":"ray","allowed":true}'}], expected)
    assert failure.value.kind is live.FailureKind.EVENT_MISMATCH


def test_input_is_disabled_after_timeout(monkeypatch):
    config = live.Config("secret-password", "a" * 32, "api-secret")
    monkeypatch.setattr(
        live,
        "expected_events",
        lambda config: (
            live.parse_time("2026-10-06T00:00:00Z"),
            {"ray": {"ray_id": "ray"}},
        ),
    )
    monkeypatch.setattr(live.time, "monotonic", Mock(side_effect=[0, 2]))
    monkeypatch.setattr(
        live,
        "datetime",
        Mock(now=Mock(return_value=live.parse_time("2026-10-06T01:00:00Z"))),
    )
    splunk = Mock()
    splunk.request.side_effect = [
        {"entry": [{"content": {"api_token": "******"}}]},
        {},
        {},
        {},
    ]
    with pytest.raises(live.TestFailure) as failure:
        live.live_test(config, splunk, 1)
    assert failure.value.kind is live.FailureKind.TIMEOUT
    assert splunk.request.call_args.args == (
        "POST",
        live.INPUT_ENDPOINT + "/cloudflare_live",
        {"disabled": "1"},
    )


@pytest.mark.parametrize("timeout", [600, 7200])
def test_live_test_covers_slow_setup_and_filters_reference_ids(monkeypatch, timeout):
    since = live.parse_time("2026-10-06T00:00:00Z")
    # Preflight and configuration took two hours beyond the one-hour reference window.
    setup_finished = since + timedelta(hours=3)
    expected = {
        f"ray-{number}": {"ray_id": f"ray-{number}", "created_at": since.isoformat()}
        for number in range(99)
    }
    expected['ray-"\\*'] = {"ray_id": 'ray-"\\*', "created_at": since.isoformat()}
    monkeypatch.setattr(live, "expected_events", lambda config: (since, expected))
    monkeypatch.setattr(live, "datetime", Mock(now=Mock(return_value=setup_finished)))
    splunk = Mock()
    splunk.request.return_value = {"entry": [{"content": {"api_token": "******"}}]}
    splunk.search.side_effect = [
        [{"_raw": json.dumps(record)} for record in expected.values()],
        [{"count": "0"}],
        [{"count": "1"}],
    ]

    live.live_test(live.Config("password", "a" * 32, "token"), splunk, timeout)

    lookback = int(splunk.upsert.call_args.args[2]["initial_lookback"])
    # Even a collector starting an hour after setup still covers the oldest record.
    assert setup_finished + timedelta(hours=1) - timedelta(seconds=lookback) <= since
    assert lookback >= 10800 + max(3600, timeout)
    query, earliest = splunk.search.call_args_list[0].args
    filter_args = query.split("| where in(ray_id, ", 1)[1].split(") |", 1)[0]
    assert json.loads("[" + filter_args + "]") == list(expected)
    assert query.endswith("| dedup _raw | fields _raw")
    assert earliest <= since.timestamp()
    assert splunk.request.call_args.args[2] == {"disabled": "1"}


def test_live_test_rejects_window_exceeding_collector_limit(monkeypatch):
    since = live.parse_time("2026-10-06T00:00:00Z")
    monkeypatch.setattr(
        live, "expected_events", lambda config: (since, {"ray": {"ray_id": "ray"}})
    )
    monkeypatch.setattr(
        live, "datetime", Mock(now=Mock(return_value=since + timedelta(days=30)))
    )
    splunk = Mock()
    splunk.request.return_value = {"entry": [{"content": {"api_token": "******"}}]}

    with pytest.raises(live.TestFailure) as failure:
        live.live_test(live.Config("password", "a" * 32, "token"), splunk, 600)

    assert failure.value.kind is live.FailureKind.CONFIGURATION
    assert splunk.upsert.call_count == 1  # Only the account, no invalid input update.


def test_cloudflare_preflight_failure_does_not_change_splunk(monkeypatch):
    monkeypatch.setattr(
        live,
        "expected_events",
        Mock(side_effect=live.TestFailure(live.FailureKind.NO_DATA)),
    )
    splunk = Mock()
    with pytest.raises(live.TestFailure):
        live.live_test(live.Config("password"), splunk, 60)
    assert splunk.method_calls == []


def test_docker_password_is_environment_only(monkeypatch):
    run = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(live.subprocess, "run", run)
    live.docker(live.Config("secret-password"), "up", "-d", "splunk")
    assert "secret-password" not in str(run.call_args.args)
    assert run.call_args.kwargs["env"]["SPLUNK_PASSWORD"] == "secret-password"


def test_search_api_errors_are_not_successful_results():
    splunk = live.Splunk(live.Config("password"))
    splunk.request = Mock(
        return_value={"results": [], "messages": [{"type": "ERROR", "text": "secret"}]}
    )
    with pytest.raises(live.TestFailure) as failure:
        splunk.search("search index=test")
    assert failure.value.kind is live.FailureKind.RESPONSE
    splunk.close()


def test_install_smoke_checks_secret_storage_disabled_input_and_cleans_up():
    splunk = Mock()
    splunk.request.side_effect = [
        {},
        {"entry": [{"content": {"api_token": "******"}}]},
        {},
        {"entry": [{"content": {"disabled": "1"}}]},
        {},
        {},
    ]
    live.smoke_configuration(splunk)
    calls = splunk.request.call_args_list
    assert "disabled" not in calls[2].args[2]
    assert calls[2].args[2]["index"] == "main"
    assert calls[-2].args[0] == "DELETE"
    assert calls[-1].args[0] == "DELETE"


def test_install_smoke_cleans_account_after_secret_storage_failure():
    splunk = Mock()
    splunk.request.side_effect = [
        {},
        {"entry": [{"content": {"api_token": "plaintext"}}]},
        {},
    ]
    with pytest.raises(live.TestFailure) as failure:
        live.smoke_configuration(splunk)
    assert failure.value.kind is live.FailureKind.SECRET_STORAGE
    assert splunk.request.call_args.args[0] == "DELETE"


def test_existing_test_input_is_disabled_before_configuration_update():
    splunk = live.Splunk(live.Config("secret-password"))
    splunk.request = Mock(
        side_effect=[
            {
                "entry": [
                    {
                        "name": "input",
                        "content": {"account": "account", "index": "index"},
                    }
                ]
            },
            {},
            {},
        ]
    )
    splunk.upsert(
        live.INPUT_ENDPOINT,
        "input",
        {"interval": "60"},
        expected={"account": "account", "index": "index"},
    )
    assert splunk.request.call_args_list[1].args == (
        "POST",
        live.INPUT_ENDPOINT + "/input",
        {"disabled": "1"},
    )
    assert splunk.request.call_args_list[2].args == (
        "POST",
        live.INPUT_ENDPOINT + "/input",
        {"interval": "60"},
    )
    splunk.close()


@pytest.mark.parametrize("has_valid_record", [True, False])
def test_preflight_filters_api_records_outside_requested_window(
    monkeypatch, has_valid_record
):
    end = live.parse_time("2026-10-06T01:00:00Z")
    monkeypatch.setattr(live, "datetime", Mock(now=Mock(return_value=end)))
    older = {"ray_id": "older", "created_at": "2026-10-05T23:59:59Z"}
    future = {"ray_id": "future", "created_at": "2026-10-06T01:00:01Z"}
    valid = {"ray_id": "valid", "created_at": "2026-10-06T00:10:00Z"}
    api = Mock()
    api.page.side_effect = [[older, future] + ([valid] if has_valid_record else []), []]
    monkeypatch.setattr(live, "CloudflareClient", Mock(return_value=api))
    config = live.Config("password", "a" * 32, "api-token", lookback=3600)
    if has_valid_record:
        since, expected = live.expected_events(config)
        assert since == live.parse_time("2026-10-06T00:00:00Z")
        assert expected == {"valid": valid}
    else:
        with pytest.raises(live.TestFailure) as failure:
            live.expected_events(config)
        assert failure.value.kind is live.FailureKind.NO_DATA


def test_cli_lookback_override_leaves_loaded_config_unchanged(monkeypatch):
    original = live.Config("password")
    monkeypatch.setattr(
        live.sys, "argv", ["app_test.py", "--test", "--lookback", "86400"]
    )
    monkeypatch.setattr(live, "load_config", Mock(return_value=original))
    splunk = Mock()
    monkeypatch.setattr(live, "Splunk", Mock(return_value=splunk))
    check = Mock()
    monkeypatch.setattr(live, "live_test", check)
    assert live.cli() == 0
    assert check.call_args.args[0].lookback == 86400
    assert original.lookback == 3600
    splunk.close.assert_called_once()
