"""Install and test the add-on against a dedicated Docker Splunk instance."""

import argparse
import json
import math
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import quote

import docker as docker_sdk
import requests
import yaml
from docker.errors import DockerException, NotFound
from docker.types import Mount

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "package" / "bin"))
from cloudflare_access import (
    CloudflareClient,
    CollectionError,
    parse_time,
    validate_account,
)

APP = "TA_cloudflare_logs"
NAMESPACE = f"/servicesNS/nobody/{APP}"
ACCOUNT_ENDPOINT = NAMESPACE + "/TA_cloudflare_logs_account"
INPUT_ENDPOINT = NAMESPACE + "/TA_cloudflare_logs_cloudflare_access_auth"
CONFIG_PATH = ROOT / ".live" / "config.json"


class FailureKind(Enum):
    CONFIGURATION = "configuration"
    DOCKER = "docker"
    CONNECTION = "connection"
    AUTHORIZATION = "authorization"
    HTTP = "http"
    RESPONSE = "response"
    TIMEOUT = "timeout"
    COLLISION = "configuration_collision"
    SECRET_STORAGE = "secret_storage"
    NO_DATA = "no_cloudflare_events"
    EVENT_MISMATCH = "event_mismatch"
    COLLECTOR = "collector_error"


class TestFailure(Exception):
    def __init__(self, kind, status=None):
        self.kind = kind
        self.status = status
        super().__init__(kind.value)


@dataclass
class Config:
    password: str
    account_id: str = ""
    api_token: str = ""
    account_name: str = "cloudflare_live"
    input_name: str = "cloudflare_live"
    index: str = "cloudflare_access_live"
    lookback: int = 86400


def initialize(path):
    if path.exists():
        raise TestFailure(
            FailureKind.CONFIGURATION, status="Config file already exists"
        )
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = {
        "password": "CfLive-" + secrets.token_urlsafe(24),
        "account_id": "",
        "api_token": "",
        "account_name": "cloudflare_live",
        "input_name": "cloudflare_live",
        "index": "cloudflare_access_live",
        "lookback": 86400,
    }
    with path.open("x", encoding="utf-8") as handle:
        os.chmod(path, 0o600)
        json.dump(data, handle, indent=2)
        handle.write("\n")


def load_config(path):
    try:
        if path.stat().st_mode & 0o077:
            raise TestFailure(FailureKind.CONFIGURATION)
        config = Config(**json.loads(path.read_text(encoding="utf-8")))
        if not isinstance(config.password, str) or len(config.password) < 12:
            raise ValueError
        for name in (config.account_name, config.input_name, config.index):
            if not isinstance(name, str) or not re.fullmatch(
                r"[a-zA-Z][a-zA-Z0-9_]{0,99}", name
            ):
                raise ValueError
        if type(config.lookback) is not int or not 60 <= config.lookback <= 2591940:
            raise ValueError
        return config
    except (OSError, ValueError, TypeError):
        raise TestFailure(FailureKind.CONFIGURATION) from None


class DockerAction(Enum):
    START = "start"
    RESTART = "restart"
    CLEANUP = "cleanup"


DOCKER_PROJECT = "ta-cloudflare-logs-live"
PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"


def docker(config, action):
    client = None
    try:
        client = docker_sdk.from_env(timeout=180)
        containers = client.containers.list(
            all=True,
            filters={"label": [f"{PROJECT_LABEL}={DOCKER_PROJECT}"]},
        )
        if len(containers) > 1 or any(
            container.labels.get(SERVICE_LABEL) != "splunk" for container in containers
        ):
            raise TestFailure(FailureKind.COLLISION)
        container = containers[0] if containers else None
        try:
            network = client.networks.get(DOCKER_PROJECT + "_default")
        except NotFound:
            network = None
        if (
            network is not None
            and (network.attrs.get("Labels") or {}).get(PROJECT_LABEL) != DOCKER_PROJECT
        ):
            raise TestFailure(FailureKind.COLLISION)
        if action is DockerAction.CLEANUP:
            if container is not None:
                container.stop(timeout=30)
                container.remove()
            if network is not None:
                network.remove()
        elif action is DockerAction.RESTART:
            if container is None:
                raise TestFailure(FailureKind.DOCKER)
            container.restart(timeout=30)
        elif action is DockerAction.START:
            if container is not None:
                # Reuse the writable layer and anonymous volumes of existing installs.
                container.start()
                return
            definition = yaml.safe_load(
                (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
            )
            service = definition["services"]["splunk"]
            environment = dict(service["environment"])
            environment["SPLUNK_PASSWORD"] = config.password
            ports = {}
            for binding in service["ports"]:
                host, external, internal = binding.split(":")
                if host != "127.0.0.1":
                    raise TestFailure(FailureKind.CONFIGURATION)
                ports[internal + "/tcp"] = (host, int(external))
            mounts = []
            for binding in service["volumes"]:
                source, target, mode = binding.split(":")
                source = (ROOT / source).resolve()
                if not source.is_file() or mode != "ro":
                    raise TestFailure(FailureKind.CONFIGURATION)
                mounts.append(Mount(target, str(source), type="bind", read_only=True))
            client.images.pull(service["image"], platform=service["platform"])
            if network is None:
                network = client.networks.create(
                    DOCKER_PROJECT + "_default",
                    labels={
                        PROJECT_LABEL: DOCKER_PROJECT,
                        "com.docker.compose.network": "default",
                    },
                )
            client.containers.run(
                service["image"],
                name=DOCKER_PROJECT + "-splunk-1",
                detach=True,
                platform=service["platform"],
                environment=environment,
                ports=ports,
                mounts=mounts,
                network=network.name,
                labels={PROJECT_LABEL: DOCKER_PROJECT, SERVICE_LABEL: "splunk"},
                restart_policy={"Name": "no"},
                use_config_proxy=False,
            )
    except (DockerException, requests.RequestException, OSError):
        # SDK diagnostics can contain container configuration, including credentials.
        raise TestFailure(FailureKind.DOCKER) from None
    except (yaml.YAMLError, KeyError, TypeError, ValueError):
        raise TestFailure(FailureKind.CONFIGURATION) from None
    finally:
        if client is not None:
            client.close()


class Splunk:
    def __init__(self, config):
        self.session = requests.Session()
        self.session.auth = ("admin", config.password)
        self.session.trust_env = False
        # Only this hard-coded loopback URL accepts the test container's self-signed certificate.
        self.url = "https://127.0.0.1:18090"

    def close(self):
        self.session.close()

    def request(self, method, endpoint, values=None, allow_missing=False):
        try:
            response = self.session.request(
                method,
                self.url + endpoint,
                params={"output_mode": "json"},
                data=values,
                timeout=(5, 90),
                verify=False,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise TestFailure(FailureKind.CONNECTION) from None
        with response:
            if allow_missing and response.status_code == 404:
                return None
            if response.status_code in (401, 403):
                raise TestFailure(FailureKind.AUTHORIZATION, response.status_code)
            if not 200 <= response.status_code < 300:
                raise TestFailure(FailureKind.HTTP, response.status_code)
            if response.status_code == 204:
                return {}
            try:
                return response.json()
            except ValueError:
                raise TestFailure(FailureKind.RESPONSE) from None

    def wait(self, timeout, endpoint="/services/server/info"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return self.request("GET", endpoint)
            except TestFailure as error:
                if (
                    error.kind is FailureKind.AUTHORIZATION
                    or error.kind is FailureKind.RESPONSE
                ):
                    raise
                if error.kind is FailureKind.HTTP and error.status not in (
                    404,
                    500,
                    502,
                    503,
                ):
                    raise
                time.sleep(3)
        raise TestFailure(FailureKind.TIMEOUT)

    def upsert(self, endpoint, name, values, expected=None):
        resource = endpoint + "/" + quote(name, safe="")
        # UCC may wrap an individual missing-resource 404 in a generic HTTP 500.
        # Use the structured collection instead of interpreting exception text.
        collection = self.request("GET", endpoint + "?count=0")
        if not isinstance(collection, dict) or not isinstance(
            collection.get("entry"), list
        ):
            raise TestFailure(FailureKind.RESPONSE)
        matches = [
            entry
            for entry in collection["entry"]
            if isinstance(entry, dict) and entry.get("name") == name
        ]
        if not matches:
            return self.request("POST", endpoint, {"name": name, **values})
        existing = {"entry": matches}
        if expected:
            content = entry_content(existing)
            if any(content.get(key) != value for key, value in expected.items()):
                raise TestFailure(FailureKind.COLLISION)
        if endpoint == INPUT_ENDPOINT:
            self.request("POST", resource, {"disabled": "1"})
        return self.request("POST", resource, values)

    def search(self, query, earliest="-1h"):
        result = self.request(
            "POST",
            "/services/search/jobs",
            {
                "search": query,
                "exec_mode": "oneshot",
                "earliest_time": str(earliest),
                "latest_time": "now",
                "count": "10000",
                "output_mode": "json",
            },
        )
        if not isinstance(result, dict) or not isinstance(result.get("results"), list):
            raise TestFailure(FailureKind.RESPONSE)
        if any(
            message.get("type") in ("ERROR", "FATAL")
            for message in result.get("messages", [])
        ):
            raise TestFailure(FailureKind.RESPONSE)
        return result["results"]


def entry_content(result):
    try:
        content = result["entry"][0]["content"]
        if not isinstance(content, dict):
            raise TypeError("Content is not a dictionary")
        return content
    except (KeyError, IndexError, TypeError, ValueError):
        raise TestFailure(FailureKind.RESPONSE) from None


def install(config, splunk, timeout):
    archive = ROOT / "TA_cloudflare_logs-0.1.0.tar.gz"
    if not archive.is_file():
        raise TestFailure(FailureKind.CONFIGURATION)
    print(
        "Starting dedicated Docker Splunk; waiting for its management API", flush=True
    )
    docker(config, DockerAction.START)
    splunk.wait(timeout)
    splunk.request(
        "POST",
        "/services/apps/local",
        {
            "name": "/tmp/TA_cloudflare_logs.tar.gz",
            "filename": "true",
            "update": "true",
        },
    )
    print("Package installed; restarting the test container", flush=True)
    docker(config, DockerAction.RESTART)
    splunk.wait(timeout)
    splunk.wait(timeout, ACCOUNT_ENDPOINT)
    splunk.wait(timeout, INPUT_ENDPOINT)
    app = entry_content(splunk.request("GET", "/services/apps/local/" + APP))
    if app.get("version") != "0.1.0":
        raise TestFailure(FailureKind.RESPONSE)
    smoke_configuration(splunk)
    print(
        "Install smoke test passed: package, UCC endpoints, encrypted storage and disabled input ready",
        flush=True,
    )


def smoke_configuration(splunk):
    name = "install_smoke_" + secrets.token_hex(6)
    account_created = input_created = False
    try:
        splunk.request(
            "POST",
            ACCOUNT_ENDPOINT,
            {
                "name": name,
                "account_id": "0" * 32,
                "api_token": "install-smoke-placeholder",
            },
        )
        account_created = True
        stored = entry_content(
            splunk.request(
                "GET", NAMESPACE + "/configs/conf-ta_cloudflare_logs_account/" + name
            )
        )
        if stored.get("api_token") != "******":
            raise TestFailure(FailureKind.SECRET_STORAGE)
        splunk.request(
            "POST",
            INPUT_ENDPOINT,
            {
                "name": name,
                "account": name,
                "index": "main",
                "interval": "60",
                "per_page": "100",
                "initial_lookback": "60",
            },
        )
        input_created = True
        content = entry_content(splunk.request("GET", INPUT_ENDPOINT + "/" + name))
        if str(content.get("disabled")).lower() not in ("1", "true"):
            raise TestFailure(FailureKind.RESPONSE)
    finally:
        if input_created:
            splunk.request("DELETE", INPUT_ENDPOINT + "/" + name)
        if account_created:
            splunk.request("DELETE", ACCOUNT_ENDPOINT + "/" + name)


def expected_events(config):
    import logging

    validate_account({"account_id": config.account_id, "api_token": config.api_token})
    until = datetime.now(timezone.utc)
    since = until - timedelta(seconds=config.lookback)
    expected = {}
    with requests.Session() as session:
        client = CloudflareClient(
            session,
            config.account_id,
            config.api_token,
            logging.getLogger("live_cloudflare"),
        )
        previous = None
        for page in range(1, 101):
            records = client.page(since, until, page, 100)
            if not records:
                break
            if records == previous:
                raise TestFailure(FailureKind.RESPONSE)
            previous = records
            for record in records:
                if (
                    isinstance(record, dict)
                    and isinstance(record.get("ray_id"), str)
                    and record["ray_id"]
                ):
                    try:
                        stamp = parse_time(record.get("created_at"))
                    except (ValueError, TypeError):
                        continue
                    if since <= stamp <= until:
                        expected[record["ray_id"]] = record
            if len(expected) >= 100:
                break
    if not expected:
        raise TestFailure(FailureKind.NO_DATA)
    return since, dict(list(expected.items())[:100])


def verify_events(rows, expected):
    found = set()
    for row in rows:
        try:
            record = json.loads(row["_raw"])
        except (KeyError, ValueError, TypeError):
            raise TestFailure(FailureKind.EVENT_MISMATCH) from None
        if not isinstance(record, dict):
            raise TestFailure(FailureKind.EVENT_MISMATCH)
        ray = record.get("ray_id")
        if ray in expected:
            if record != expected[ray]:
                raise TestFailure(FailureKind.EVENT_MISMATCH)
            found.add(ray)
    return found


def live_test(config, splunk, timeout):
    # Query before configuring the input; an invalid token must not change Splunk configuration.
    since, expected = expected_events(config)
    started = time.time()
    splunk.upsert(
        ACCOUNT_ENDPOINT,
        config.account_name,
        {"account_id": config.account_id, "api_token": config.api_token},
        expected={"account_id": config.account_id},
    )
    stored = entry_content(
        splunk.request(
            "GET",
            NAMESPACE
            + "/configs/conf-ta_cloudflare_logs_account/"
            + config.account_name,
        )
    )
    if stored.get("api_token") != "******":
        raise TestFailure(FailureKind.SECRET_STORAGE)
    index_endpoint = "/servicesNS/nobody/system/data/indexes"
    if (
        splunk.request("GET", index_endpoint + "/" + config.index, allow_missing=True)
        is None
    ):
        splunk.request("POST", index_endpoint, {"name": config.index})
    # Cover time spent in preflight/setup plus a generous collector startup allowance.
    initial_lookback = math.ceil(
        (datetime.now(timezone.utc) - since).total_seconds()
    ) + max(86400, timeout)
    if not 0 <= initial_lookback <= 2592000:
        raise TestFailure(FailureKind.CONFIGURATION)
    splunk.upsert(
        INPUT_ENDPOINT,
        config.input_name,
        {
            "account": config.account_name,
            "index": config.index,
            "interval": "60",
            "initial_lookback": str(initial_lookback),
            "per_page": "100",
        },
        expected={"account": config.account_name, "index": config.index},
    )
    resource = INPUT_ENDPOINT + "/" + config.input_name
    enabled = False
    try:
        enabled = True
        splunk.request("POST", resource, {"disabled": "0"})
        print(
            f"Test input enabled; checking {len(expected)} Cloudflare records and collector completion",
            flush=True,
        )
        deadline = time.monotonic() + timeout
        source = f"cloudflare:access:auth:{config.account_id}"
        ray_ids = ", ".join(json.dumps(ray) for ray in expected)
        while time.monotonic() < deadline:
            rows = splunk.search(
                f'search index={config.index} sourcetype="cloudflare:access:auth" source="{source}" '
                f"| where in(ray_id, {ray_ids}) | dedup _raw | fields _raw",
                int(since.timestamp()) - 1,
            )
            found = verify_events(rows, expected)
            errors = splunk.search(
                'search index=_internal source="*ta_cloudflare_logs_access_auth.log" ("Collection failed" OR "Malformed records") | stats count',
                int(started),
            )
            if errors and int(errors[0].get("count", 0)):
                raise TestFailure(FailureKind.COLLECTOR)
            completed = splunk.search(
                'search index=_internal source="*ta_cloudflare_logs_access_auth.log" "Poll complete" | stats count',
                int(started),
            )
            if (
                found == set(expected)
                and completed
                and int(completed[0].get("count", 0))
            ):
                print(
                    f"Live test passed: {len(found)} preserved JSON records indexed; collector poll completed",
                    flush=True,
                )
                return
            time.sleep(5)
        raise TestFailure(FailureKind.TIMEOUT)
    finally:
        if enabled:
            splunk.request("POST", resource, {"disabled": "1"})
            print("Test input disabled", flush=True)


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create ignored local config with a random Docker admin password",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Start local Docker Splunk, install/upgrade package, and verify UCC endpoints",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Configure account and run real Cloudflare-to-Splunk ingestion checks",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove only this workflow's test container and network",
    )
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument(
        "--lookback",
        type=int,
        help="Override the live-test reference window in seconds without editing credentials",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Readiness/ingestion deadline in seconds",
    )
    args = parser.parse_args()
    if not any((args.init, args.install, args.test, args.cleanup)):
        parser.error("Select --init, --install, --test, or --cleanup")
    if args.lookback is not None and (
        not args.test or not 60 <= args.lookback <= 2591940
    ):
        parser.error(
            "--lookback requires --test and must be between 60 and 2591940 seconds"
        )
    args.timeout = max(args.timeout, 30)
    if (args.init and any((args.install, args.test, args.cleanup))) or (
        args.cleanup and (args.install or args.test)
    ):
        parser.error("Run --init and --cleanup separately from installation/testing")
    try:
        if args.init:
            initialize(args.config)
            print(
                "Created local config; add Cloudflare account_id and api_token before --test"
            )
            return 0
        config = load_config(args.config)
        if args.lookback is not None:
            config = replace(config, lookback=args.lookback)
        if args.cleanup:
            docker(config, DockerAction.CLEANUP)
            print(
                "Dedicated test container and network removed; local credential file retained"
            )
            return 0
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        splunk = Splunk(config)
        try:
            if args.install:
                install(config, splunk, args.timeout)
            if args.test:
                live_test(config, splunk, args.timeout)
        finally:
            splunk.close()
        return 0
    except TestFailure as error:
        if error.kind is FailureKind.NO_DATA:
            print(
                "Live ingestion validation unavailable: no usable Cloudflare "
                "authentication events in the reference window. Splunk configuration "
                "was not changed. Retry with --test --lookback 86400 for a 24-hour "
                "window, or a larger window within the 30-day limit.",
                file=sys.stderr,
            )
            return 2
        print(
            f"Workflow failed: kind={error.kind.value} status={error.status} {error}",
            file=sys.stderr,
        )
        return 1
    except CollectionError as error:
        print(
            f"Cloudflare API check failed: kind={error.kind.value} status={error.status}",
            file=sys.stderr,
        )
        return 1
    except Exception:  # noqa: BLE001 -- never expose exception strings that can contain credentials
        print(
            "Workflow failed unexpectedly; exception details suppressed to protect credentials",
            file=sys.stderr,
        )
        return 1
