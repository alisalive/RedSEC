"""LogZilla HTTP Event Receiver exporter for RedSEC.

Converts RedSecEvent / AttackChain objects into LogZilla's HTTP Receiver
JSON format, and can either write them to a JSON-lines file or push them
directly to a LogZilla instance over HTTP.

LogZilla HTTP Event Receiver reference:
https://logzilla.ai/docs/receiving-data/http-event-receiver
"""

import json
import os
import time
from typing import Optional

import requests

from redsec.models.chain import AttackChain
from redsec.models.event import RedSecEvent

# Program name reported to LogZilla for every event.
_PROGRAM_NAME = "redsec"

# RFC-3164 facility used for all RedSEC events (1 = user-level messages).
_FACILITY_USER = 1

# Detection-risk score thresholds mapped to syslog severity levels.
_SEVERITY_LOW = 0.3
_SEVERITY_HIGH = 0.7

# RFC-3164 syslog severity levels.
_SYSLOG_CRITICAL = 2
_SYSLOG_WARNING = 4
_SYSLOG_INFO = 6

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

    def format_event(
        self,
        event: RedSecEvent,
        chain_id: Optional[str] = None,
        use_current_time: bool = False,
    ) -> dict:
        """Convert a RedSecEvent into LogZilla's HTTP Receiver JSON format.

        Args:
            event: The event to convert.
            chain_id: ID of the AttackChain this event belongs to, if any.
                Included in ``extra_fields`` only when provided.
            use_current_time: If True, always use the current time for the
                ``ts`` field instead of ``event.timestamp``. Useful when
                pushing historical/archival events to LogZilla as if they
                were live, since LogZilla may reject events with stale
                timestamps as "outdated".

        Returns:
            A dict matching LogZilla's HTTP Event Receiver schema
            (ts, host, program, message, priority, user_tags, extra_fields, json).
        """
        extra_fields: dict = {
            "mitre_technique": str(event.mitre_technique),
            "mitre_tactic": str(event.mitre_tactic),
            "detection_score": str(event.detection_risk),
        }
        if chain_id is not None:
            extra_fields["chain_id"] = str(chain_id)

        if use_current_time:
            timestamp = time.time()
        else:
            timestamp = event.timestamp.timestamp() if event.timestamp is not None else time.time()

        return {
            "ts": timestamp,
            "host": event.target,
            "program": _PROGRAM_NAME,
            "message": event.description,
            "priority": self._map_syslog_severity(event.detection_risk),
            "user_tags": {f"tag_{i}": tag for i, tag in enumerate(event.tags)} if event.tags else {},
            "extra_fields": extra_fields,
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
                ``extra_fields.chain_id`` when it belongs to a chain.

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
                fh.write(json.dumps({"events": [record]}) + "\n")

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
        use_current_time: bool = False,
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
            use_current_time: If True, always use the current time for each
                event's ``ts`` field instead of ``event.timestamp``, so
                historical/archival events are treated as live by LogZilla.

        Returns:
            A summary dict: ``{"sent": int, "failed": int, "errors": list[str],
            "status_code": Optional[int]}``. ``status_code`` is the most
            recent HTTP status code observed (from either a successful or
            failed request), or ``None`` if no response was ever received
            (pure network failure). Error messages never contain the token.

        Raises:
            ValueError: If ``url`` or ``token`` is empty or None.
        """
        if not url:
            raise ValueError("LogZilla push failed: 'url' is required and cannot be empty.")
        if not token:
            raise ValueError("LogZilla push failed: 'token' is required and cannot be empty.")

        endpoint = f"{url.rstrip('/')}/incoming"
        headers = {
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        }
        chain_id_map = self._build_chain_id_map(chains) if chains else {}
        formatted = [
            self.format_event(
                event, chain_id=chain_id_map.get(event.id), use_current_time=use_current_time
            )
            for event in events
        ]

        sent = 0
        failed = 0
        errors: list[str] = []
        last_status: Optional[int] = None

        for i in range(0, len(formatted), batch_size):
            batch = formatted[i : i + batch_size]

            bulk_ok, status, _detail = self._post_with_retry(
                endpoint, headers, {"events": batch}, max_retries, retry_delay, timeout, token
            )
            if status is not None:
                last_status = status

            if bulk_ok:
                sent += len(batch)
                continue

            # Bulk request failed — fall back to sequential per-event POSTs.
            for item in batch:
                ok, status, detail = self._post_with_retry(
                    endpoint, headers, {"events": [item]}, max_retries, retry_delay, timeout, token
                )
                if status is not None:
                    last_status = status
                if ok:
                    sent += 1
                else:
                    failed += 1
                    errors.append(detail or "Failed to push event to LogZilla after retries.")

        return {"sent": sent, "failed": failed, "errors": errors, "status_code": last_status}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _map_syslog_severity(self, score: Optional[float]) -> int:
        """Map a detection_risk score (0.0-1.0) to an RFC-3164 priority value.

        Priority is computed as ``facility * 8 + severity``, using the
        user-level facility (1) and a syslog severity level derived from
        the detection risk score: >=0.7 -> 2 (critical), 0.3-0.7 -> 4
        (warning), <0.3 -> 6 (info).

        Args:
            score: Detection risk score, or None if not scored.

        Returns:
            The combined RFC-3164 priority integer.
        """
        value = score if score is not None else 0.0
        if value >= _SEVERITY_HIGH:
            severity = _SYSLOG_CRITICAL
        elif value >= _SEVERITY_LOW:
            severity = _SYSLOG_WARNING
        else:
            severity = _SYSLOG_INFO
        return _FACILITY_USER * 8 + severity

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
    ) -> tuple[bool, Optional[int], str]:
        """POST a payload to LogZilla, retrying on network/server errors.

        Distinguishes authentication failures, client-side rejections,
        server errors, and network-level failures (unreachable host,
        timeout) so callers can surface a clear, actionable message.

        Args:
            endpoint: Full URL to POST to.
            headers: Request headers, including the Authorization token.
            payload: JSON-serializable body, i.e. ``{"events": [...]}``.
            max_retries: Maximum number of attempts.
            retry_delay: Seconds to sleep between attempts.
            timeout: Per-request timeout in seconds.
            token: LogZilla token, used only to sanitize error messages.

        Returns:
            A ``(success, status_code, detail)`` tuple. ``success`` is True
            when the request returned a status < 300. ``status_code`` is the
            last HTTP status observed, or None if no response was ever
            received. ``detail`` is empty on success, otherwise a sanitized,
            categorized failure description (never contains the token).
            Client errors (4xx) and successes return immediately without
            retrying; network errors and 5xx responses are retried up to
            ``max_retries`` times.
        """
        last_status: Optional[int] = None
        last_detail = ""

        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
            except requests.exceptions.Timeout as exc:
                last_status = None
                last_detail = f"Network error (timeout): {self._sanitize_error(exc, token)}"
            except requests.exceptions.ConnectionError as exc:
                last_status = None
                last_detail = f"Network error (host unreachable): {self._sanitize_error(exc, token)}"
            except requests.RequestException as exc:
                last_status = None
                last_detail = f"Network error: {self._sanitize_error(exc, token)}"
            else:
                last_status = response.status_code
                if response.status_code < 300:
                    return True, response.status_code, ""
                if response.status_code in (401, 403):
                    body = self._response_body(response, token)
                    return (
                        False,
                        response.status_code,
                        f"Authentication failed (HTTP {response.status_code}): {body}",
                    )
                if response.status_code < 500:
                    body = self._response_body(response, token)
                    return (
                        False,
                        response.status_code,
                        f"LogZilla rejected the request (HTTP {response.status_code}): {body}",
                    )
                last_detail = f"LogZilla server error (HTTP {response.status_code})"

            if attempt < max_retries:
                time.sleep(retry_delay)

        return False, last_status, last_detail or "Failed after retries"

    def _response_body(self, response: "requests.Response", token: str) -> str:
        """Return a sanitized, truncated response body for error messages.

        Args:
            response: The HTTP response whose body should be read.
            token: The token to redact if present in the body.

        Returns:
            The response text truncated to 500 characters with the token
            redacted, or a placeholder if the body could not be read.
        """
        try:
            text = response.text
        except Exception:
            return "<unreadable response body>"
        text = self._sanitize_error(Exception(text), token)
        return text[:500]

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
