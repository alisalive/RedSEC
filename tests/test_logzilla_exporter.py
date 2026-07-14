"""Tests for redsec.exporters.logzilla.LogzillaExporter."""

import json
from unittest.mock import Mock, patch

import pytest
import requests

from redsec.exporters.logzilla import LogzillaExporter
from redsec.models.chain import AttackChain
from redsec.models.event import RedSecEvent


def _make_event(
    tool="nmap",
    event_type="port_scan",
    target="10.0.0.1",
    severity="low",
    mitre_technique="T1046",
    mitre_tactic="Discovery",
    detection_risk=None,
    description=None,
):
    return RedSecEvent(
        tool=tool,
        event_type=event_type,
        target=target,
        severity=severity,
        description=description or f"{tool} {event_type} on {target}",
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        detection_risk=detection_risk,
    )


def _make_chain(events, name="Test Chain", severity="high"):
    return AttackChain(name=name, events=events, severity=severity)


# ---------------------------------------------------------------------------
# format_event
# ---------------------------------------------------------------------------

class TestFormatEvent:
    def test_basic_fields(self):
        event = _make_event(target="192.168.1.5")
        record = LogzillaExporter().format_event(event)
        assert record["host"] == "192.168.1.5"
        assert record["program"] == "redsec"
        assert record["message"] == event.description

    def test_has_ts_field(self):
        event = _make_event()
        record = LogzillaExporter().format_event(event)
        assert isinstance(record["ts"], float)
        assert record["ts"] == event.timestamp.timestamp()

    def test_no_old_fields(self):
        event = _make_event()
        record = LogzillaExporter().format_event(event)
        for old_key in ("msg", "app-name", "severity", "structured-data"):
            assert old_key not in record

    def test_extra_fields_contains_mitre_fields(self):
        event = _make_event(mitre_technique="T1595", mitre_tactic="Reconnaissance")
        record = LogzillaExporter().format_event(event)
        ef = record["extra_fields"]
        assert ef["mitre_technique"] == "T1595"
        assert ef["mitre_tactic"] == "Reconnaissance"

    def test_extra_fields_contains_detection_score(self):
        event = _make_event(detection_risk=0.42)
        record = LogzillaExporter().format_event(event)
        assert record["extra_fields"]["detection_score"] == "0.42"

    def test_extra_fields_values_are_strings(self):
        event = _make_event(detection_risk=0.42)
        record = LogzillaExporter().format_event(event, chain_id="chain-123")
        for value in record["extra_fields"].values():
            assert isinstance(value, str)

    def test_chain_id_included_when_provided(self):
        event = _make_event()
        record = LogzillaExporter().format_event(event, chain_id="chain-123")
        assert record["extra_fields"]["chain_id"] == "chain-123"

    def test_chain_id_absent_when_not_provided(self):
        event = _make_event()
        record = LogzillaExporter().format_event(event)
        assert "chain_id" not in record["extra_fields"]

    @pytest.mark.parametrize(
        "score,expected_priority",
        [
            (0.0, 1 * 8 + 6),
            (0.1, 1 * 8 + 6),
            (0.29, 1 * 8 + 6),
            (0.3, 1 * 8 + 4),
            (0.5, 1 * 8 + 4),
            (0.69, 1 * 8 + 4),
            (0.7, 1 * 8 + 2),
            (0.9, 1 * 8 + 2),
            (1.0, 1 * 8 + 2),
        ],
    )
    def test_priority_mapping(self, score, expected_priority):
        event = _make_event(detection_risk=score)
        record = LogzillaExporter().format_event(event)
        assert record["priority"] == expected_priority

    def test_priority_defaults_to_info_when_score_missing(self):
        event = _make_event(detection_risk=None)
        record = LogzillaExporter().format_event(event)
        assert record["priority"] == 1 * 8 + 6


# ---------------------------------------------------------------------------
# export_to_file
# ---------------------------------------------------------------------------

class TestExportToFile:
    def test_writes_one_json_line_per_event(self, tmp_path):
        events = [_make_event(), _make_event(tool="nuclei", event_type="vuln_found")]
        path = str(tmp_path / "out.jsonl")
        LogzillaExporter().export_to_file(events, path)
        lines = open(path).read().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # must be valid JSON

    def test_lines_wrapped_in_events_key(self, tmp_path):
        events = [_make_event()]
        path = str(tmp_path / "out.jsonl")
        LogzillaExporter().export_to_file(events, path)
        line = json.loads(open(path).read().strip())
        assert "events" in line
        assert isinstance(line["events"], list)
        assert line["events"][0]["host"] == events[0].target

    def test_tags_events_with_chain_id(self, tmp_path):
        e1 = _make_event()
        e2 = _make_event(tool="nuclei", event_type="vuln_found")
        chain = _make_chain([e1])
        path = str(tmp_path / "out.jsonl")
        LogzillaExporter().export_to_file([e1, e2], path, chains=[chain])
        lines = [json.loads(l) for l in open(path).read().strip().split("\n")]
        assert lines[0]["events"][0]["extra_fields"]["chain_id"] == chain.id
        assert "chain_id" not in lines[1]["events"][0]["extra_fields"]

    def test_returns_absolute_path(self, tmp_path):
        events = [_make_event()]
        path = str(tmp_path / "out.jsonl")
        result = LogzillaExporter().export_to_file(events, path)
        assert result == str(tmp_path / "out.jsonl")

    def test_no_token_in_file(self, tmp_path):
        events = [_make_event()]
        path = str(tmp_path / "out.jsonl")
        LogzillaExporter().export_to_file(events, path)
        content = open(path).read()
        assert "secret-token" not in content


# ---------------------------------------------------------------------------
# push_to_logzilla
# ---------------------------------------------------------------------------

class TestPushToLogzillaValidation:
    @pytest.mark.parametrize("url,token", [("", "secret-token"), (None, "secret-token")])
    def test_raises_value_error_on_empty_url(self, url, token):
        events = [_make_event()]
        with pytest.raises(ValueError):
            LogzillaExporter().push_to_logzilla(events, url, token)

    @pytest.mark.parametrize("token", ["", None])
    def test_raises_value_error_on_empty_token(self, token):
        events = [_make_event()]
        with pytest.raises(ValueError):
            LogzillaExporter().push_to_logzilla(events, "https://logzilla.example.com", token)

    def test_no_request_sent_when_url_missing(self):
        events = [_make_event()]
        with patch("redsec.exporters.logzilla.requests.post") as mock_post:
            with pytest.raises(ValueError):
                LogzillaExporter().push_to_logzilla(events, "", "secret-token")
        mock_post.assert_not_called()


class TestPushToLogzilla:
    def test_successful_bulk_push(self):
        events = [_make_event(), _make_event(tool="nuclei", event_type="vuln_found")]
        mock_response = Mock(status_code=202)
        with patch("redsec.exporters.logzilla.requests.post", return_value=mock_response) as mock_post:
            result = LogzillaExporter().push_to_logzilla(events, "https://logzilla.example.com", "secret-token")
        assert result["sent"] == 2
        assert result["failed"] == 0
        assert result["errors"] == []
        mock_post.assert_called_once()
        called_url = mock_post.call_args.args[0] if mock_post.call_args.args else mock_post.call_args.kwargs.get("url")
        assert called_url == "https://logzilla.example.com/incoming"

    def test_bulk_push_wraps_batch_in_events_key(self):
        events = [_make_event(), _make_event(tool="nuclei", event_type="vuln_found")]
        mock_response = Mock(status_code=202)
        with patch("redsec.exporters.logzilla.requests.post", return_value=mock_response) as mock_post:
            LogzillaExporter().push_to_logzilla(events, "https://logzilla.example.com", "secret-token")
        body = mock_post.call_args.kwargs["json"]
        assert list(body.keys()) == ["events"]
        assert len(body["events"]) == 2

    def test_sends_authorization_header(self):
        events = [_make_event()]
        mock_response = Mock(status_code=202)
        with patch("redsec.exporters.logzilla.requests.post", return_value=mock_response) as mock_post:
            LogzillaExporter().push_to_logzilla(events, "https://logzilla.example.com", "secret-token")
        headers = mock_post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "token secret-token"

    def test_network_error_falls_back_to_sequential_and_reports_failure(self):
        events = [_make_event(), _make_event(tool="nuclei", event_type="vuln_found")]
        with patch(
            "redsec.exporters.logzilla.requests.post",
            side_effect=requests.exceptions.ConnectionError("connection refused"),
        ):
            result = LogzillaExporter().push_to_logzilla(
                events, "https://logzilla.example.com", "secret-token",
                max_retries=1, retry_delay=0,
            )
        assert result["sent"] == 0
        assert result["failed"] == 2
        assert len(result["errors"]) == 2

    def test_token_never_appears_in_error_messages(self):
        events = [_make_event()]
        token = "super-secret-token-value"
        with patch(
            "redsec.exporters.logzilla.requests.post",
            side_effect=requests.exceptions.ConnectionError(f"failed to reach host with token {token}"),
        ):
            result = LogzillaExporter().push_to_logzilla(
                events, "https://logzilla.example.com", token,
                max_retries=1, retry_delay=0,
            )
        for err in result["errors"]:
            assert token not in err

    def test_bulk_failure_falls_back_and_individual_success_counts(self):
        events = [_make_event(), _make_event(tool="nuclei", event_type="vuln_found")]
        bulk_fail = Mock(status_code=500)
        individual_ok = Mock(status_code=202)
        with patch(
            "redsec.exporters.logzilla.requests.post",
            side_effect=[bulk_fail, bulk_fail, individual_ok, individual_ok],
        ):
            result = LogzillaExporter().push_to_logzilla(
                events, "https://logzilla.example.com", "secret-token",
                max_retries=2, retry_delay=0,
            )
        assert result["sent"] == 2
        assert result["failed"] == 0

    def test_client_error_does_not_retry(self):
        events = [_make_event()]
        mock_response = Mock(status_code=400)
        with patch("redsec.exporters.logzilla.requests.post", return_value=mock_response) as mock_post:
            result = LogzillaExporter().push_to_logzilla(
                events, "https://logzilla.example.com", "secret-token",
                max_retries=3, retry_delay=0,
            )
        assert result["failed"] == 1
        # One call for the bulk attempt, one for the sequential fallback — no retries within either.
        assert mock_post.call_count == 2
