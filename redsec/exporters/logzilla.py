"""LogZilla HTTP Event Receiver exporter for RedSEC.

Converts RedSecEvent / AttackChain objects into LogZilla's HTTP Receiver
JSON format, and can either write them to a JSON-lines file or push them
directly to a LogZilla instance over HTTP.

LogZilla HTTP Event Receiver reference: https://docs.logzilla.net/
"""

import json
import os
import time
from typing import Optional

import requests

from redsec.models.chain import AttackChain
from redsec.models.event import RedSecEvent

# Application name reported to LogZilla for every event.
_APP_NAME = "redsec"

# Detection-risk score thresholds mapped to LogZilla severities.
_SEVERITY_LOW = 0.3
_SEVERITY_HIGH = 0.7

# Redacted placeholder used whenever a token would otherwise leak into
# an error message.
_REDACTED = "***REDACTED***"


class LogzillaExporter:
    """Export RedSecEvent lists and AttackChains to LogZilla.

    Two delivery modes are supported:

    * :meth:`export_to_file` — write newline-delimited JSON records to a
      file, one per event, suitable for LogZilla's file-based ingestion
      or manual review.
    * :meth:`push_to_logzilla` — POST records directly to a LogZilla
      HTTP Event Receiver endpoint (``<url>/incoming``), batching where
      possible and retrying individual events on failure.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def format_event(self, event: RedSecEvent, chain_id: Optional[str] = None) -> dict:
        """Convert a RedSecEvent into LogZilla's HTTP Receiver JSON format.

        Args:
            event: The event to convert.
            chain_id: ID of the AttackChain this event belongs to, if any.
                Included in ``structured-data`` only when provided.

        Returns:
            A dict matching LogZilla's expected HTTP Receiver schema.
        """
        structured_data: dict = {
            "mitre_technique": event.mitre_technique,
            "mitre_tactic": event.mitre_tactic,
            "detection_score": event.detection_risk,
        }
        if chain_id is not None:
            structured_data["chain_id"] = chain_id

        return {
            "host": event.target,
            "app-name": _APP_NAME,
            "msg": event.description,
            "severity": self._map_severity(event.detection_risk),
            "structured-data": structured_data,
        }

    def export_to_file(
        self,
        events: list[RedSecEvent],
        path: str,
        chains: Optional[list[AttackChain]] = None,
    ) -> str:
        """Write events to a JSON-lines file in LogZilla HTTP Receiver format.

        Args:
            events: Events to export.
            path: Destination file path.
            chains: Optional attack chains, used to tag each event's
                ``structured-data.chain_id`` when it belongs to a chain.

        Returns:
            The absolute path of the written file.

        Raises:
            OSError: If the output file cannot be written.
        """
        chain_id_map = self._build_chain_id_map(chains) if chains else {}

        abs_path = os.path.abspath(path)
        parent = os.path.dirname(abs_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(abs_path, "w", encoding="utf-8") as fh:
            for event in events:
                record = self.format_event(event, chain_id=chain_id_map.get(event.id))
                fh.write(json.dumps(record) + "\n")

        return abs_path

    def push_to_logzilla(
        self,
        events: list[RedSecEvent],
        url: str,
        token: str,
        chains: Optional[list[AttackChain]] = None,
        batch_size: int = 100,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 10.0,
    ) -> dict:
        """Push events to a LogZilla HTTP Event Receiver.

        Events are grouped into batches of ``batch_size`` and posted as a
        single bulk request per batch. If a batch request fails, the
        exporter falls back to posting the events in that batch one at a
        time, retrying each individual POST up to ``max_retries`` times.
        Network and HTTP errors are handled gracefully — this method never
        raises for per-event failures; it reports them in the returned
        summary instead.

        Args:
            events: Events to push.
            url: Base URL of the LogZilla instance (e.g. ``https://logzilla.example.com``).
                The ``/incoming`` path is appended automatically.
            token: LogZilla API token, sent as ``Authorization: token <token>``.
            chains: Optional attack chains, used to tag chain_id on events.
            batch_size: Maximum number of events per bulk request.
            max_retries: Maximum POST attempts per batch/event before giving up.
            retry_delay: Seconds to wait between retry attempts.
            timeout: Per-request timeout in seconds.

        Returns:
            A summary dict: ``{"sent": int, "failed": int, "errors": list[str]}``.
            Error messages never contain the token.
        """
        endpoint = f"{url.rstrip('/')}/incoming"
        headers = {
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        }
        chain_id_map = self._build_chain_id_map(chains) if chains else {}
        formatted = [
            self.format_event(event, chain_id=chain_id_map.get(event.id)) for event in events
        ]

        sent = 0
        failed = 0
        errors: list[str] = []

        for i in range(0, len(formatted), batch_size):
            batch = formatted[i : i + batch_size]

            bulk_ok = False
            try:
                bulk_ok = self._post_with_retry(
                    endpoint, headers, batch, max_retries, retry_delay, timeout, token
                )
            except Exception:
                # Bulk request failed — fall through to the per-event fallback
                # below, which records its own errors per event.
                pass

            if bulk_ok:
                sent += len(batch)
                continue

            # Bulk request failed — fall back to sequential per-event POSTs.
            for item in batch:
                try:
                    if self._post_with_retry(
                        endpoint, headers, item, max_retries, retry_delay, timeout, token
                    ):
                        sent += 1
                    else:
                        failed += 1
                        errors.append("Failed to push event to LogZilla after retries.")
                except Exception as exc:
                    failed += 1
                    errors.append(self._sanitize_error(exc, token))

        return {"sent": sent, "failed": failed, "errors": errors}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _map_severity(self, score: Optional[float]) -> str:
        """Map a detection_risk score (0.0-1.0) to a LogZilla severity string.

        Args:
            score: Detection risk score, or None if not scored.

        Returns:
            One of ``"info"``, ``"warning"``, or ``"critical"``.
        """
        value = score if score is not None else 0.0
        if value < _SEVERITY_LOW:
            return "info"
        if value < _SEVERITY_HIGH:
            return "warning"
        return "critical"

    def _build_chain_id_map(self, chains: list[AttackChain]) -> dict[str, str]:
        """Build a mapping of event id -> chain id for chain membership lookup.

        Args:
            chains: Attack chains to index.

        Returns:
            Dict mapping RedSecEvent.id to the AttackChain.id it belongs to.
        """
        return {event.id: chain.id for chain in chains for event in chain.events}

    def _post_with_retry(
        self,
        endpoint: str,
        headers: dict,
        payload,
        max_retries: int,
        retry_delay: float,
        timeout: float,
        token: str,
    ) -> bool:
        """POST a payload to LogZilla, retrying on network/server errors.

        Args:
            endpoint: Full URL to POST to.
            headers: Request headers, including the Authorization token.
            payload: JSON-serializable body (single event dict or a batch list).
            max_retries: Maximum number of attempts.
            retry_delay: Seconds to sleep between attempts.
            timeout: Per-request timeout in seconds.
            token: LogZilla token, used only to sanitize re-raised exceptions.

        Returns:
            True if the request succeeded (HTTP status < 300), False if it
            failed with a non-retryable client error (status 400-499).

        Raises:
            requests.RequestException: If all retry attempts are exhausted
                due to network errors or server errors (5xx). The token is
                stripped from the exception message before re-raising.
        """
        last_exc: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
            except requests.RequestException as exc:
                last_exc = exc
            else:
                if response.status_code < 300:
                    return True
                if response.status_code < 500:
                    # Client error — retrying will not help.
                    return False
                last_exc = requests.RequestException(
                    f"LogZilla returned HTTP {response.status_code}"
                )

            if attempt < max_retries:
                time.sleep(retry_delay)

        if last_exc is not None:
            raise type(last_exc)(self._sanitize_error(last_exc, token))
        return False

    def _sanitize_error(self, exc: Exception, token: str) -> str:
        """Return an error message with the LogZilla token stripped out.

        Args:
            exc: The exception to render.
            token: The token to redact if present in the message.

        Returns:
            A safe error message string containing no token material.
        """
        msg = str(exc)
        if token:
            msg = msg.replace(token, _REDACTED)
        return msg
