"""Cloudflare polling and durable file state, independent of Splunk APIs."""

import json
import math
import os
import random
import re
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from pathlib import Path

import requests

UTC = timezone.utc
OVERLAP = timedelta(seconds=60)
MAX_RECENT_IDS = 50000


class ErrorKind(Enum):
    CONFIGURATION = "configuration"
    AUTHORIZATION = "authorization"
    HTTP = "http"
    RATE_LIMIT = "rate_limit"
    TRANSPORT = "transport"
    TLS = "tls"
    RESPONSE = "response"
    PAGINATION = "pagination"
    CHECKPOINT = "checkpoint"
    CAPACITY = "capacity"


class CollectionError(Exception):
    def __init__(self, kind, status=None, retry_at=None):
        self.kind = kind
        self.status = status
        self.retry_at = retry_at
        super().__init__(kind.value)


def parse_time(value):
    if not isinstance(value, str):
        raise TypeError("Timestamp must be a string")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Timestamp must contain a timezone")
    return stamp.astimezone(UTC)


def format_time(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def integer_option(value, default, minimum, maximum):
    try:
        number = int(default if value in (None, "") else value)
        if isinstance(value, bool) or not minimum <= number <= maximum:
            raise ValueError
        return number
    except (ValueError, TypeError):
        raise CollectionError(ErrorKind.CONFIGURATION) from None


def validate_account(account):
    account_id = account.get("account_id")
    token = account.get("api_token")
    if (
        not isinstance(account_id, str)
        or re.fullmatch(r"[a-fA-F0-9]{32}", account_id) is None
        or not isinstance(token, str)
        or not token.strip()
        or token == "******"
        or "\n" in token
        or "\r" in token
    ):
        raise CollectionError(ErrorKind.CONFIGURATION)
    return account_id, token


@dataclass
class Checkpoint:
    initial_since: datetime
    max_created_at: object = None
    recent_ids: dict = field(default_factory=dict)
    retry_not_before: object = None

    def encode(self):
        return {
            "version": 1,
            "initial_since": format_time(self.initial_since),
            "max_created_at": format_time(self.max_created_at)
            if self.max_created_at
            else None,
            "recent_ids": {
                key: format_time(stamp) for key, stamp in self.recent_ids.items()
            },
            "retry_not_before": format_time(self.retry_not_before)
            if self.retry_not_before
            else None,
        }

    @classmethod
    def decode(cls, value):
        try:
            if value["version"] != 1 or not isinstance(value["recent_ids"], dict):
                raise ValueError
            initial = parse_time(value["initial_since"])
            maximum = (
                parse_time(value["max_created_at"]) if value["max_created_at"] else None
            )
            recent = {
                key: parse_time(stamp) for key, stamp in value["recent_ids"].items()
            }
            if len(recent) > MAX_RECENT_IDS or any(not key for key in recent):
                raise ValueError
            if recent and (
                maximum is None or any(stamp > maximum for stamp in recent.values())
            ):
                raise ValueError
            retry_at = (
                parse_time(value["retry_not_before"])
                if value.get("retry_not_before")
                else None
            )
            return cls(initial, maximum, recent, retry_at)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise CollectionError(ErrorKind.CHECKPOINT) from None


class FileState:
    """Atomic JSON checkpoints with an advisory lock; Linux and macOS collectors."""

    def __init__(self, directory, key):
        self.directory = Path(directory)
        self.path = self.directory / (key + ".json")

    @contextmanager
    def locked(self):
        import fcntl

        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(self.path.with_suffix(".lock"), "a", encoding="utf-8") as lock:
            os.chmod(lock.name, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def load(self):
        try:
            return Checkpoint.decode(json.loads(self.path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise CollectionError(ErrorKind.CHECKPOINT) from None

    def save(self, state):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.directory, delete=False
            ) as handle:
                temporary = handle.name
                json.dump(state.encode(), handle, allow_nan=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = None
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (OSError, ValueError):
            raise CollectionError(ErrorKind.CHECKPOINT) from None
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)


class CloudflareClient:
    def __init__(self, session, account_id, token, logger, sleep=time.sleep):
        self.session = session
        self.url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/access/logs/access_requests"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "TA_cloudflare_logs/0.1.0",
        }
        self.logger = logger
        self.sleep = sleep

    def page(self, since, until, page, per_page):
        params = {
            "since": format_time(since),
            "until": format_time(until),
            "direction": "asc",
            "page": page,
            "per_page": per_page,
        }
        for attempt in range(5):
            retry_after = None
            try:
                response = self.session.get(
                    self.url,
                    params=params,
                    headers=self.headers,
                    timeout=(10, 60),
                    allow_redirects=False,
                )
            except requests.exceptions.SSLError:
                raise CollectionError(ErrorKind.TLS) from None
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                kind, status = ErrorKind.TRANSPORT, None
            except requests.exceptions.RequestException:
                raise CollectionError(ErrorKind.TRANSPORT) from None
            else:
                try:
                    status = response.status_code
                    if status == 429 or status == 408 or 500 <= status <= 599:
                        kind = ErrorKind.RATE_LIMIT if status == 429 else ErrorKind.HTTP
                        retry_after = response.headers.get("Retry-After")
                    elif status in (401, 403):
                        raise CollectionError(ErrorKind.AUTHORIZATION, status)
                    elif status != 200:
                        raise CollectionError(ErrorKind.HTTP, status)
                    else:
                        try:
                            body = response.json()
                        except ValueError:
                            raise CollectionError(ErrorKind.RESPONSE) from None
                        if (
                            not isinstance(body, dict)
                            or body.get("success") is not True
                            or not isinstance(body.get("result"), list)
                        ):
                            raise CollectionError(ErrorKind.RESPONSE)
                        return body["result"]
                finally:
                    response.close()
            delay = (2**attempt) + random.uniform(0, 1)
            if retry_after:
                try:
                    retry_delay = float(retry_after)
                except ValueError:
                    try:
                        retry_delay = (
                            parsedate_to_datetime(retry_after) - datetime.now(UTC)
                        ).total_seconds()
                    except (ValueError, TypeError, OverflowError):
                        retry_delay = 0
                if math.isfinite(retry_delay):
                    if retry_delay > 300:
                        raise CollectionError(
                            kind,
                            status,
                            datetime.now(UTC) + timedelta(seconds=retry_delay),
                        )
                    delay = max(delay, retry_delay)
            if attempt == 4:
                retry_at = (
                    datetime.now(UTC) + timedelta(seconds=delay)
                    if kind is ErrorKind.RATE_LIMIT
                    else None
                )
                raise CollectionError(kind, status, retry_at)
            self.logger.warning(
                "Retrying Cloudflare request kind=%s status=%s attempt=%d delay=%.1f",
                kind.value,
                status,
                attempt + 1,
                delay,
            )
            self.sleep(delay)
        raise CollectionError(ErrorKind.TRANSPORT)


def poll(client, checkpoint, until, per_page, emit, logger):
    """Return new state only after all pages and event writes succeed."""
    since = (
        checkpoint.max_created_at - OVERLAP
        if checkpoint.max_created_at
        else checkpoint.initial_since
    )
    if since > until:
        return checkpoint
    maximum = checkpoint.max_created_at
    recent = dict(checkpoint.recent_ids)
    previous = None
    emitted = malformed = duplicates = out_of_window = 0
    for page in range(1, 10001):
        records = client.page(since, until, page, per_page)
        if not records:
            break
        # Parsed equality detects an endpoint ignoring page without byte comparisons.
        if previous is not None and records == previous:
            raise CollectionError(ErrorKind.PAGINATION)
        previous = records
        for record in records:
            if not isinstance(record, dict):
                malformed += 1
                continue
            try:
                stamp = parse_time(record.get("created_at"))
            except (ValueError, TypeError, OverflowError):
                stamp = None
                malformed += 1
            if stamp is not None and not since <= stamp <= until:
                out_of_window += 1
                continue
            ray_id = record.get("ray_id")
            if not isinstance(ray_id, str) or not ray_id:
                ray_id = None
            if stamp is not None:
                maximum = max(maximum, stamp) if maximum else stamp
                if ray_id and ray_id in recent:
                    duplicates += 1
                    continue
            emit(record, stamp)
            emitted += 1
            if ray_id and stamp is not None:
                recent[ray_id] = stamp
        if maximum:
            recent = {
                key: value
                for key, value in recent.items()
                if value >= maximum - OVERLAP
            }
        if len(recent) > MAX_RECENT_IDS:
            raise CollectionError(ErrorKind.CAPACITY)
    else:
        raise CollectionError(ErrorKind.PAGINATION)
    logger.info(
        "Poll complete pages=%d events=%d duplicates=%d malformed=%d out_of_window=%d",
        page,
        emitted,
        duplicates,
        malformed,
        out_of_window,
    )
    if malformed:
        logger.warning(
            "Malformed records=%d; objects preserved, non-object records skipped",
            malformed,
        )
    return Checkpoint(checkpoint.initial_since, maximum, recent)
