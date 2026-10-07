"""Current UCC input-helper entry points and Splunk event integration."""

import hashlib
import json
from datetime import datetime, timedelta

import requests
from cloudflare_access import (
    UTC,
    Checkpoint,
    CloudflareClient,
    CollectionError,
    FileState,
    integer_option,
    poll,
    validate_account,
)
from solnlib import conf_manager, log
from splunklib import modularinput as smi

ADDON_NAME = "TA_cloudflare_logs"
SOURCETYPE = "cloudflare:access:auth"


def validate_parameters(parameters):
    integer_option(parameters.get("interval"), 300, 60, 86400)
    integer_option(parameters.get("initial_lookback"), 86400, 0, 2592000)
    integer_option(parameters.get("per_page"), 100, 1, 1000)
    if not parameters.get("account") or not parameters.get("index"):
        raise ValueError("Account and index are required")


def validate_input(definition):
    validate_parameters(definition.parameters)


def stream_events(inputs, event_writer):
    failed = False
    for stanza, parameters in inputs.inputs.items():
        if str(parameters.get("disabled", "0")).lower() in ("1", "true", "yes"):
            continue
        logger = log.Logs().get_logger("ta_cloudflare_logs_access_auth")
        try:
            validate_parameters(parameters)
            session_key = inputs.metadata["session_key"]
            logger.setLevel(
                conf_manager.get_log_level(
                    logger=logger,
                    session_key=session_key,
                    app_name=ADDON_NAME,
                    conf_name="ta_cloudflare_logs_settings",
                )
            )
            manager = conf_manager.ConfManager(
                session_key,
                ADDON_NAME,
                realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_cloudflare_logs_account",
            )
            account = manager.get_conf("ta_cloudflare_logs_account").get(
                parameters["account"]
            )
            account_id, token = validate_account(account)
            # Hash is deliberately a storage identity, not a structured-data comparison.
            identity = json.dumps(
                [stanza, account_id, parameters["index"]], separators=(",", ":")
            )
            key = hashlib.sha256(identity.encode()).hexdigest()
            store = FileState(inputs.metadata["checkpoint_dir"], key)
            with store.locked() as acquired:
                if not acquired:
                    logger.warning(
                        "Poll skipped because collector already holds checkpoint lock"
                    )
                    continue
                until = datetime.now(UTC)
                checkpoint = store.load()
                if (
                    checkpoint is not None
                    and checkpoint.retry_not_before is not None
                    and until < checkpoint.retry_not_before
                ):
                    logger.warning(
                        "Poll deferred until Cloudflare Retry-After cooldown expires"
                    )
                    continue
                if checkpoint is None:
                    lookback = integer_option(
                        parameters.get("initial_lookback"), 86400, 0, 2592000
                    )
                    checkpoint = Checkpoint(until - timedelta(seconds=lookback))
                    store.save(checkpoint)

                def emit(
                    record,
                    stamp,
                    stanza=stanza,
                    index=parameters["index"],
                    account_id=account_id,
                ):
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(
                                record, ensure_ascii=False, allow_nan=False
                            ),
                            time=stamp.timestamp() if stamp else None,
                            stanza=stanza,
                            index=index,
                            sourcetype=SOURCETYPE,
                            source=f"cloudflare:access:auth:{account_id}",
                        )
                    )

                with requests.Session() as session:
                    client = CloudflareClient(session, account_id, token, logger)
                    try:
                        state = poll(
                            client,
                            checkpoint,
                            until,
                            integer_option(parameters.get("per_page"), 100, 1, 1000),
                            emit,
                            logger,
                        )
                    except CollectionError as error:
                        if error.retry_at is not None:
                            checkpoint.retry_not_before = error.retry_at
                            store.save(checkpoint)
                        raise
                store.save(state)
        except CollectionError as error:
            failed = True
            logger.error(
                "Collection failed kind=%s status=%s; checkpoint not advanced",
                error.kind.value,
                error.status,
            )
        except Exception:  # noqa: BLE001 -- suppress potentially secret exception details at boundary
            # Exception text, tracebacks, response bodies and request headers can contain secrets.
            failed = True
            logger.error(
                "Collection failed during configuration, event output or state storage; checkpoint not advanced"
            )
    if failed:
        raise RuntimeError(
            "Cloudflare collection failed; inspect the add-on log"
        ) from None
