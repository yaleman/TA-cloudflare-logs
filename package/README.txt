# Cloudflare Access API Logs for Splunk

A UCC-generated Splunk add-on that polls Cloudflare Zero Trust Access **authentication** logs from `GET /client/v4/accounts/{account_id}/access/logs/access_requests`. It emits one JSON event per authentication record with sourcetype `cloudflare:access:auth`, preserving Cloudflare's field names and unknown fields. This input collects authentication audit events; it does not collect every request to protected applications.

## Install and configure

1. Install `TA_cloudflare_logs-0.1.0.tar.gz` using Splunk's **Apps → Manage Apps → Install app from file**. Restart if Splunk requests it.
2. Open **Cloudflare Access API Logs → Configuration → Accounts**. Add a name, your 32-character Cloudflare account ID, and an account-scoped API token with **Access: Audit Logs Read** permission.
3. Under **Inputs**, create an **Access authentication logs** input, select the account and destination index, and save. New inputs start disabled. Enable it using the status control in the input table.
4. Open **Access authentication** from the app navigation. Choose a time range, index, username (Cloudflare `user_email`), status, and IP address, then submit. Text filters accept `*` wildcards; `*` includes all values.
5. For a manual search, use `index=<your_index> sourcetype=cloudflare:access:auth`.

The Simple XML dashboard deduplicates `ray_id` before filtering and aggregation. It shows authentication totals, allowed/denied counts, unique known users, a five-minute status timeline, status distribution, and the top 20 users and IP addresses. Records without a ray ID remain separate because they cannot be reliably deduplicated. All panels share the same filtered search.

Install the collector on one Linux heavy forwarder or standalone Splunk Enterprise instance. macOS is also supported for development. Windows collectors are unsupported because checkpoint locking uses POSIX advisory locks. Use Splunk's Python 3 runtime (3.9 or newer). On a distributed deployment, deploy the search-time `props.conf` to search heads. Do not configure collection on multiple hosts for the same account unless duplicate ingestion is intended. This has not yet been certified for Splunk Cloud or validated against a running Splunk instance.

The account UI uses UCC's `encrypted` field handling and Splunk credential storage. Only the account reference goes in the input; do not put tokens in `inputs.conf`, source control, or command-line arguments. Token rotation through the account UI preserves checkpoints. Configuration and input changes should be limited to trusted Splunk administrators.

| Setting | Default | Allowed values |
| --- | --- | --- |
| Interval | 300 seconds | 60–86400 seconds |
| Initial lookback | 3600 seconds | Blank = 3600; 0–2592000 seconds |
| Index | Splunk default index | Select an existing destination index |
| Records per page | 100 | 1–1000 |
| New input status | Disabled | Enable/disable from Inputs |

Initial lookback applies only when no checkpoint exists. Cloudflare's retention and permissions govern which events are available. Choose a lookback inside your account's retention. Page-size limits are not specified in the endpoint reference; reduce this value if your account rejects it. The collector continues to an empty page even when Cloudflare returns fewer records than requested.

## Polling and recovery

Each poll freezes `until` to the poll start time and sends `direction=asc`, `page`, `per_page`, and `since` on every request. The initial start time is persisted before the first request so an initial failed run cannot silently move the lookback forward. Subsequent polls start 60 seconds before the maximum successfully collected `created_at`. Page numbers are never saved as checkpoints.

Checkpoints are atomic JSON files under Splunk's supplied modular-input checkpoint directory. A checkpoint belongs to the input stanza, Cloudflare account ID, and index. Changing any of these starts a new collection history. Deleting and recreating the same input with the same account ID and index resumes its saved history. Removing its checkpoint file while the input is disabled resets it to the configured initial lookback. Back up this directory when moving a collector.

The collector saves the maximum timestamp and ray IDs in its last 60 seconds only after every page and event write succeeds. Duplicate ray IDs in this boundary window and within a page are suppressed. Records without a usable `ray_id` may repeat. Objects with a missing or malformed timestamp are preserved and emitted without an explicit event time; they cannot advance the checkpoint or be reliably deduplicated. Non-object records are counted and skipped. Cloudflare can return records outside the requested time bounds. The collector filters those records locally and counts them in its log; they cannot advance the checkpoint. Malformed API envelopes, repeated pages, or exhausted retries fail the poll without advancing the timestamp.

This is best-effort at-least-once collection, not exactly-once delivery. A crash after Splunk receives events but before checkpoint replacement can replay them. Event output flushes before checkpoint storage, but there is no indexer acknowledgement transaction. Cloudflare does not document snapshot isolation for page-based queries. Late events older than the 60-second overlap can be missed. A fixed upper bound reduces moving-page risk but cannot eliminate it. For investigations requiring unique records, use `| dedup ray_id` after filtering to records with a ray ID.

Polling stops with an error after 10000 non-empty pages or more than 50000 boundary ray IDs, without advancing the checkpoint. These guards prevent an endpoint ignoring pagination or an unexpectedly dense boundary from consuming unlimited resources. Split collection operationally or adjust reviewed limits for sustained volumes beyond those safeguards.

## Development and packaging

Source lives in `package/`; UCC's generated output is disposable. Edit `globalConfig.json`, `package/bin/cloudflare_access.py`, and `package/bin/cloudflare_access_auth_helper.py`. The input uses the current UCC `inputHelperModule` API and `solnlib` credential retrieval. The Splunk SDK is used only for the supported modular-input protocol; no legacy generated-helper HTTP or checkpoint API is used. No PyOpenSSL dependency is added.

With [uv](https://docs.astral.sh/uv/) installed, run from the project root:

```sh
uv sync --locked
uv run pytest -q
uv run ruff check package/bin tests scripts
uv run python scripts/build.py
```

The build exports locked runtime dependencies, creates the pure-Python Splunk SDK wheel, and asks UCC 6.6.0 to install portable wheels targeting Python 3.9 before generating UI, REST handlers, configuration, and the modular-input entry point. The packaged archive is created in the project root and ignored by Git. GitHub Actions runs tests, lint, and packaging on every push to `main`, then creates or updates the `v<version>` release using `meta.version` in `globalConfig.json`. Repeated pushes with the same version move that release tag to the built commit and replace its package asset; a version bump creates a new release. Generated runtime dependencies include only pure Python wheels; no platform-specific `.so` libraries are shipped. When changing dependencies, use `uv add`/`uv remove` and regenerate `package/lib/requirements.txt` with `uv export --no-dev --no-hashes --no-emit-project --output-file package/lib/requirements.txt`.

Tests cover fixed-window pagination, timestamp boundaries, deduplication, checkpoint isolation, atomic state replacement and locking, retries, secret-safe errors, malformed records, UCC configuration defaults, and Splunk event XML output. Live Cloudflare collection, Splunk UI behavior, and AppInspect certification still require deployment validation. The local Docker installation smoke test can run without Cloudflare credentials.

## Automated local Splunk install and live test

The Docker workflow follows the local-test pattern in TA-pushover. It uses a dedicated Compose project, Splunk 9.3 on `linux/amd64`, and loopback-only ports: Splunk Web at `http://127.0.0.1:18001` and the management API at `https://127.0.0.1:18090`. It does not use or modify another Splunk instance. Starting the container accepts Splunk's license terms through the image's documented startup flags.

From the project root, prepare and install:

```sh
uv sync --locked
uv run python scripts/build.py
uv run python app_test.py --init
uv run python app_test.py --install
```

`--init` creates `.live/config.json` with a random Splunk admin password and blank `account_id`/`api_token` fields. This file is ignored by Git and must have mode `0600`. Initialization refuses to overwrite an existing file. The install command starts the dedicated container, waits for its API, installs/upgrades the package through Splunk's management API, restarts the container, and checks the package version and UCC endpoints. It also creates temporary placeholder credentials and a disabled input to exercise encrypted storage and input creation, then deletes them. Cloudflare credentials are unnecessary for installation.

When ready, fill the `account_id` and `api_token` fields in `.live/config.json` locally. Use an account-scoped Cloudflare token with **Access: Audit Logs Read**. Keep credentials out of chat, shell arguments and source control. Then run:

```sh
uv run python app_test.py --test
```

The live test first reads a fixed window of real Cloudflare authentication records. It then creates or updates the test account through UCC's encrypted credential handler, checks that the underlying configuration contains only the secret placeholder, creates the dedicated test index if necessary, and enables a 60-second input. For a new checkpoint, its initial lookback covers the saved preflight window, time spent preparing the test, and at least one extra hour for collector startup (or the configured timeout if longer). The full padded window must fit within the collector’s 30-day lookback limit. It searches specifically for up to 100 reference ray IDs and collapses identical raw events before limiting results, then checks structurally identical JSON and collector completion without collection errors. Existing account/input names with incompatible account or destination settings are rejected. The test disables its input after success or failure; account credentials, indexed events, and checkpoints remain available for inspection. It never creates a Cloudflare login or modifies Cloudflare configuration.

A successful installation is separate from a successful live ingestion test. If no usable authentication records are available within `lookback` (default 3600 seconds), the live test exits with code 2; it does not report success. Authenticate to a protected Access application or choose a suitable lookback inside your account's retention, then rerun. Other failures return code 1. Successful checks return code 0. `--timeout` controls the readiness/ingestion wait (default 600 seconds). Use `--test --lookback 86400` to test a 24-hour window without editing the credential file; the collector still resumes an existing checkpoint.

To rebuild, reinstall and test in one run after credentials are configured:

```sh
uv run python scripts/build.py
uv run python app_test.py --install --test
```

The harness uses HTTPS with the dedicated loopback container's self-signed certificate exception; production Cloudflare certificate verification remains enabled. Secrets are passed to Docker through its environment and to APIs in request bodies/headers, never printed or included in command arguments. Docker administrators can inspect the container's startup password.

Remove only this workflow's container and network when finished:

```sh
uv run python app_test.py --cleanup
```

Cleanup discards the container's installed app, credentials, checkpoints, and indexed events. The ignored local credential file remains. Do not change its Splunk password while a container exists; remove the container and recreate it if changing the startup password. Docker must be running and able to mount the project directory.

## References

- [UCC documentation](https://splunk.github.io/addonfactory-ucc-generator/)
- [UCC input helper modules](https://splunk.github.io/addonfactory-ucc-generator/inputs/helper/)
- [Cloudflare authentication-log API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/logs/subresources/access_requests/methods/list/)
- [Cloudflare Access authentication logs](https://developers.cloudflare.com/cloudflare-one/insights/logs/dashboard-logs/access-authentication-logs/)
