# Repository guidance

This repository builds `TA_cloudflare_logs`, a Splunk UCC add-on for Cloudflare Access authentication audit logs. Collection uses `cloudflare:access:auth`; these are authentication events, not every request to a protected application.

## Source and packaging

- Edit source in `package/` and UCC configuration in `globalConfig.json`. Do not hand-edit generated files in `output/`, dependency lockfiles, or the packaged archive.
- Keep polling and checkpoint logic in `package/bin/cloudflare_access.py`, Splunk integration in `package/bin/cloudflare_access_auth_helper.py`, and local deployment/testing in `scripts/live_testing.py`. `app_test.py` is only the CLI entry point.
- Keep production code compatible with Splunk Python 3.9 and newer. Use `uv` to manage Python dependencies; do not add OpenSSL or PyOpenSSL dependencies.
- `scripts/build.py` exports locked runtime requirements, builds the portable Splunk SDK wheel, and generates/packages the app with UCC. Ship pure-Python dependencies, not platform-specific binaries.
- Never commit generated `.tar.gz` or `.tgz` packages. `.github/workflows/release.yml` tests and builds on pushes to `main`, then creates or refreshes the versioned GitHub release and its package asset. The build and release use `globalConfig.json` metadata; keep project and manifest versions consistent when bumping the app version.
- Keep `README.md` and `package/README.txt` synchronized. Use project-relative paths in documentation and comments.
- Dashboard source is `package/default/data/ui/views/access_authentication.xml`; navigation is `package/default/data/ui/nav/default.xml`. Keep configuration and input views accessible when changing navigation.

## Collector invariants

- Preserve Cloudflare JSON field names and unknown fields. Do not log event contents or secrets.
- Use typed error categories such as `ErrorKind` and `FailureKind`. Match enum variants for behavior; never inspect exception messages or serialized strings to decide what to do.
- Freeze `until` for each poll, request ascending pages, and filter valid timestamps against the requested bounds locally. Continue to an empty page; a short page is not proof of completion.
- Persist the initial collection window before the first request. Advance the maximum timestamp and boundary ray IDs only after every page and event write succeeds.
- Preserve the 60-second overlap, boundary deduplication, checkpoint identity based on stanza/account ID/index, advisory locking, and atomic state replacement. Token rotation must not reset collection history.
- Preserve malformed objects without an explicit event time; skip non-object records. Neither may advance the checkpoint.
- Keep pagination and boundary-capacity guards. Fail without advancing collection progress on malformed envelopes, repeated pages, exhausted retries, or event-output failure.

## Dashboard searches

- Use `user_email` for usernames, `allowed` for Allowed/Denied status, and `ip_address` for IP filtering. Retain an Unknown status for missing or unexpected values.
- Deduplicate usable `ray_id` values before filtering and aggregation. Retain records without usable ray IDs separately rather than collapsing them together.
- All aggregate panels must share the filtered, deduplicated results. Use a transforming base search and sum its event counts in post-process searches; counting aggregate rows would undercount authentications.
- Escape user-supplied search tokens with Simple XML string filters (`|s`). Keep time bounds connected to the time picker.

## HTTP and logging

HTTPS certificate verification stays enabled. Requests have a 10-second connect timeout and 60-second read timeout; redirects are rejected. The add-on retries connection failures, timeouts, HTTP 408, HTTP 429, and HTTP 5xx up to five attempts with exponential backoff and jitter. Numeric and HTTP-date `Retry-After` headers are honored. Waits over 300 seconds stop the poll and persist a cooldown without advancing the timestamp; scheduled runs defer until that cooldown expires. Exhausted HTTP 429 retries also persist the final retry delay. HTTP 401/403 fail immediately and require fixing the account token/permission. Other HTTP errors and invalid successful responses fail immediately.

Use the Configuration logging tab to adjust logging. The collector writes to `$SPLUNK_HOME/var/log/splunk/ta_cloudflare_logs_access_auth.log`. Search `index=_internal source=*ta_cloudflare_logs_access_auth.log`. Logs contain typed error categories, HTTP status, retries and counts; request headers, API tokens, response bodies, record contents, and exception text are omitted. The event payload naturally contains Cloudflare authentication data such as email addresses and IP addresses.

## Validation and local Splunk

Run the relevant checks from the project root:

```sh
uv sync --locked
uv run pytest -q
uv run ruff check package/bin tests scripts
uv run python scripts/build.py
```

- Add focused regressions for collection or harness behavior changes. For dashboard changes, parse the XML and verify that the packaged dashboard and navigation match the source. Documentation-only changes need consistency checks, not new tests.
- Report unit tests, package generation, installation checks, live ingestion, and AppInspect certification separately. A successful build or install does not prove live collection.
- Use `mise run app:init`, `mise run app:install`, `mise run app:test`, and `mise run app:cleanup` for the dedicated Compose workflow. Inspect the existing container and context before operating on a local instance; preserve its data when upgrading.
- The Compose project is `ta-cloudflare-logs-live`, with Web on `127.0.0.1:18001` and management on `127.0.0.1:18090`. Do not target another Splunk instance or discard its volumes without explicit authorization.
- Keep `.live/config.json` ignored and mode `0600`. Never print credentials, pass them in command arguments, overwrite existing credential files, or expose Docker environment contents.
- The self-signed certificate exception belongs only to the dedicated loopback test API. Keep production Cloudflare certificate verification enabled.
- Live tests must validate Cloudflare access before changing Splunk configuration, reject incompatible account/input settings, and disable the test input in a `finally` path.
- Derive a new input's lookback from the saved preflight start through current setup time, with at least one hour of startup allowance (or the configured timeout if longer), within the collector's 30-day limit. Search for expected ray IDs and collapse identical replayed records before imposing result limits.
- No usable reference events means unavailable validation (exit code 2), not a successful ingestion test. Do not create Cloudflare logins or change Cloudflare configuration to generate test data.
