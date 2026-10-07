import importlib.util
import json
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "live_testing.py"
spec = importlib.util.spec_from_file_location("live_testing", MODULE_PATH)
if spec is None:
    raise ImportError("Could not load live_testing module")
live = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = live
if spec.loader is None:
    raise ImportError("Could not load live_testing module")
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
    assert lookback >= 10800 + max(86400, timeout)
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


@pytest.fixture
def docker_client(monkeypatch):
    client = Mock()
    client.containers.list.return_value = []
    client.networks.get.side_effect = live.NotFound("missing")
    client.networks.create.return_value.name = "ta-cloudflare-logs-live_default"
    monkeypatch.setattr(live.docker_sdk, "from_env", Mock(return_value=client))
    return client


def owned_container():
    container = Mock()
    container.labels = {
        live.PROJECT_LABEL: live.DOCKER_PROJECT,
        live.SERVICE_LABEL: "splunk",
    }
    return container


def test_docker_creates_loopback_container_with_private_environment(
    docker_client, tmp_path, monkeypatch
):
    monkeypatch.setattr(live, "ROOT", tmp_path)
    (tmp_path / "docker-compose.yml").write_text(
        (MODULE_PATH.parents[1] / "docker-compose.yml").read_text()
    )
    (tmp_path / "TA_cloudflare_logs-0.1.0.tar.gz").touch()
    live.docker(live.Config("secret-password"), live.DockerAction.START)
    values = docker_client.containers.run.call_args.kwargs
    assert values["environment"]["SPLUNK_PASSWORD"] == "secret-password"
    assert values["ports"] == {
        "8089/tcp": ("127.0.0.1", 18090),
        "8000/tcp": ("127.0.0.1", 18001),
    }
    assert values["platform"] == "linux/amd64"
    assert values["mounts"][0]["ReadOnly"] is True
    assert values["mounts"][0]["Source"] == str(
        tmp_path / "TA_cloudflare_logs-0.1.0.tar.gz"
    )
    assert values["use_config_proxy"] is False
    docker_client.close.assert_called_once()


def test_docker_reuses_existing_container_without_recreating_data(docker_client):
    container = owned_container()
    docker_client.containers.list.return_value = [container]
    live.docker(live.Config("secret-password"), live.DockerAction.START)
    container.start.assert_called_once()
    docker_client.containers.run.assert_not_called()
    docker_client.images.pull.assert_not_called()
    container.remove.assert_not_called()


def test_docker_restart_preserves_existing_container(docker_client):
    container = owned_container()
    docker_client.containers.list.return_value = [container]
    live.docker(live.Config("secret-password"), live.DockerAction.RESTART)
    container.restart.assert_called_once_with(timeout=30)
    container.remove.assert_not_called()


def test_docker_cleanup_removes_only_owned_resources(docker_client):
    container = owned_container()
    network = Mock(attrs={"Labels": {live.PROJECT_LABEL: live.DOCKER_PROJECT}})
    docker_client.containers.list.return_value = [container]
    docker_client.networks.get.side_effect = None
    docker_client.networks.get.return_value = network
    live.docker(live.Config("secret-password"), live.DockerAction.CLEANUP)
    container.stop.assert_called_once_with(timeout=30)
    container.remove.assert_called_once_with()
    network.remove.assert_called_once_with()
    assert docker_client.containers.list.call_args.kwargs == {
        "all": True,
        "filters": {"label": ["com.docker.compose.project=ta-cloudflare-logs-live"]},
    }


def test_docker_cleanup_refuses_foreign_network_before_removing_container(
    docker_client,
):
    container = owned_container()
    network = Mock(attrs={"Labels": {}})
    docker_client.containers.list.return_value = [container]
    docker_client.networks.get.side_effect = None
    docker_client.networks.get.return_value = network
    with pytest.raises(live.TestFailure) as failure:
        live.docker(live.Config("secret-password"), live.DockerAction.CLEANUP)
    assert failure.value.kind is live.FailureKind.COLLISION
    container.stop.assert_not_called()
    network.remove.assert_not_called()
    docker_client.close.assert_called_once()


def test_docker_failure_suppresses_sdk_diagnostics(docker_client):
    docker_client.containers.list.side_effect = live.docker_sdk.errors.APIError(
        "secret-password"
    )
    with pytest.raises(live.TestFailure) as failure:
        live.docker(live.Config("secret-password"), live.DockerAction.START)
    assert failure.value.kind is live.FailureKind.DOCKER
    assert "secret-password" not in str(failure.value)
    assert failure.value.__suppress_context__
    docker_client.close.assert_called_once()


def test_docker_cleanup_without_existing_resources_is_safe(docker_client):
    live.docker(live.Config("secret-password"), live.DockerAction.CLEANUP)
    docker_client.containers.run.assert_not_called()
    docker_client.networks.create.assert_not_called()


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
    original = live.Config("password", lookback=86400)
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
    assert original.lookback == 86400
    splunk.close.assert_called_once()


@pytest.mark.parametrize("count", [1, 2])
def test_docker_refuses_unexpected_project_containers(docker_client, count):
    containers = [owned_container() for _ in range(count)]
    if count == 1:
        containers[0].labels[live.SERVICE_LABEL] = "other"
    docker_client.containers.list.return_value = containers
    with pytest.raises(live.TestFailure) as failure:
        live.docker(live.Config("secret-password"), live.DockerAction.CLEANUP)
    assert failure.value.kind is live.FailureKind.COLLISION
    for container in containers:
        container.stop.assert_not_called()
        container.remove.assert_not_called()


def test_docker_rejects_non_loopback_ports_before_creating_resources(
    docker_client, tmp_path, monkeypatch
):
    monkeypatch.setattr(live, "ROOT", tmp_path)
    definition = (MODULE_PATH.parents[1] / "docker-compose.yml").read_text()
    (tmp_path / "docker-compose.yml").write_text(
        definition.replace("127.0.0.1", "0.0.0.0")
    )
    with pytest.raises(live.TestFailure) as failure:
        live.docker(live.Config("secret-password"), live.DockerAction.START)
    assert failure.value.kind is live.FailureKind.CONFIGURATION
    docker_client.networks.create.assert_not_called()
    docker_client.containers.run.assert_not_called()


def test_cli_no_reference_events_explains_skipped_configuration(monkeypatch, capsys):
    monkeypatch.setattr(live.sys, "argv", ["app_test.py", "--test"])
    monkeypatch.setattr(live, "load_config", Mock(return_value=live.Config("password")))
    splunk = Mock()
    monkeypatch.setattr(live, "Splunk", Mock(return_value=splunk))
    monkeypatch.setattr(
        live,
        "expected_events",
        Mock(side_effect=live.TestFailure(live.FailureKind.NO_DATA)),
    )
    assert live.cli() == 2
    message = capsys.readouterr().err
    assert "Splunk configuration was not changed" in message
    assert "--test --lookback 86400" in message
    assert "password" not in message
    splunk.upsert.assert_not_called()
    splunk.request.assert_not_called()
    splunk.close.assert_called_once()
