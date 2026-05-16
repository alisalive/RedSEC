"""Tests for redsec.exporters.sec.SecExporter."""

from datetime import datetime, timezone

import pytest

from redsec.exporters.sec import SecExporter
from redsec.models.chain import AttackChain
from redsec.models.event import RedSecEvent


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_event(tool="nmap", event_type="port_scan", target="10.0.0.1",
                severity="low", mitre_technique="T1046"):
    return RedSecEvent(
        tool=tool,
        event_type=event_type,
        target=target,
        severity=severity,
        description=f"{tool} {event_type} on {target}",
        mitre_technique=mitre_technique,
    )


def _make_chain(events, name="Test Chain", severity="high"):
    now = datetime.now(timezone.utc)
    return AttackChain(
        name=name,
        events=events,
        severity=severity,
        mitre_techniques=[e.mitre_technique for e in events if e.mitre_technique],
        start_time=now,
        end_time=now,
    )


# ---------------------------------------------------------------------------
# export_events — Single rules
# ---------------------------------------------------------------------------

class TestExportEvents:
    def test_generates_single_rule_per_event(self, tmp_path):
        events = [_make_event(), _make_event(tool="nuclei", event_type="vuln_found", severity="high")]
        path = str(tmp_path / "out.conf")
        SecExporter().export_events(events, path)
        content = open(path).read()
        assert content.count("type=Single") == 2

    def test_single_rule_has_ptype_regexp(self, tmp_path):
        events = [_make_event()]
        path = str(tmp_path / "out.conf")
        SecExporter().export_events(events, path)
        content = open(path).read()
        assert "ptype=RegExp" in content

    def test_single_rule_pattern_contains_target(self, tmp_path):
        events = [_make_event(target="172.16.0.5")]
        path = str(tmp_path / "out.conf")
        SecExporter().export_events(events, path)
        content = open(path).read()
        assert "172\\.16\\.0\\.5" in content

    def test_pattern_includes_port_suffix_when_port_set(self, tmp_path):
        event = RedSecEvent(
            tool="nmap", event_type="port_scan", target="10.0.0.1",
            severity="low", description="Open port 22/tcp on 10.0.0.1",
            mitre_technique="T1046", port=22, protocol="tcp",
        )
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([event], path)
        content = open(path).read()
        assert ".*port 22" in content

    def test_pattern_has_no_port_suffix_without_port(self, tmp_path):
        event = _make_event(target="10.0.0.2")  # port not set
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([event], path)
        content = open(path).read()
        assert ".*port" not in content

    def test_pattern_uses_url_from_description_when_present(self, tmp_path):
        event = RedSecEvent(
            tool="ffuf", event_type="dir_found", target="scanme.nmap.org",
            severity="low",
            description="[403] http://scanme.nmap.org/.svn trailing",
            mitre_technique="T1083",
        )
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([event], path)
        content = open(path).read()
        # URL is used, not the last word ("trailing")
        assert r".*http://scanme\.nmap\.org/\.svn" in content
        assert "trailing" not in content.split("pattern=")[1].split("\n")[0]

    def test_pattern_falls_back_to_last_word_when_no_url(self, tmp_path):
        event = RedSecEvent(
            tool="nuclei", event_type="vuln_found", target="10.0.0.1",
            severity="high",
            description="Reflected XSS via search param",
            mitre_technique="T1190",
        )
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([event], path)
        content = open(path).read()
        assert r".*param" in content

    def test_port_takes_priority_over_description(self, tmp_path):
        event = RedSecEvent(
            tool="nmap", event_type="port_scan", target="10.0.0.1",
            severity="low", description="Open port 22/tcp on 10.0.0.1",
            mitre_technique="T1046", port=22, protocol="tcp",
        )
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([event], path)
        content = open(path).read()
        assert ".*port 22" in content
        assert r"10\.0\.0\.1" not in content.split(".*port 22")[1].split("\n")[0]

    def test_two_events_same_host_different_ports_have_distinct_patterns(self, tmp_path):
        e1 = RedSecEvent(
            tool="nmap", event_type="port_scan", target="10.0.0.1",
            severity="low", description="Open port 22/tcp", mitre_technique="T1046",
            port=22, protocol="tcp",
        )
        e2 = RedSecEvent(
            tool="nmap", event_type="port_scan", target="10.0.0.1",
            severity="low", description="Open port 80/tcp", mitre_technique="T1046",
            port=80, protocol="tcp",
        )
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([e1, e2], path)
        content = open(path).read()
        assert ".*port 22" in content
        assert ".*port 80" in content

    def test_action_uses_write_not_pipe_echo(self, tmp_path):
        events = [_make_event()]
        path = str(tmp_path / "out.conf")
        SecExporter().export_events(events, path)
        content = open(path).read()
        assert "action=write -" in content
        assert "pipe echo" not in content

    def test_action_uses_percent_s_variable(self, tmp_path):
        events = [_make_event()]
        path = str(tmp_path / "out.conf")
        SecExporter().export_events(events, path)
        content = open(path).read()
        assert "%s" in content
        assert "%0" not in content

    def test_action_contains_event_metadata(self, tmp_path):
        events = [_make_event(event_type="port_scan", target="10.0.0.1", mitre_technique="T1046")]
        path = str(tmp_path / "out.conf")
        SecExporter().export_events(events, path)
        content = open(path).read()
        assert "EVENT: port_scan" in content
        assert "TARGET: 10.0.0.1" in content
        assert "MITRE: T1046" in content

    def test_empty_events_writes_header_only(self, tmp_path):
        path = str(tmp_path / "out.conf")
        SecExporter().export_events([], path)
        content = open(path).read()
        assert "type=Single" not in content
        assert "RedSEC" in content


# ---------------------------------------------------------------------------
# export_chain — completion rule
# ---------------------------------------------------------------------------

class TestExportChain:
    def test_completion_rule_is_single_with_threshold(self, tmp_path):
        chain = _make_chain([_make_event(), _make_event(tool="metasploit", event_type="exploit_success", severity="critical")])
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "type=SingleWithThreshold" in content

    def test_thresh_equals_number_of_events(self, tmp_path):
        events = [
            _make_event(),
            _make_event(tool="metasploit", event_type="exploit_success", severity="critical"),
            _make_event(tool="impacket", event_type="credential_dumped", severity="critical"),
        ]
        chain = _make_chain(events)
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "thresh=3" in content

    def test_thresh_single_event_chain(self, tmp_path):
        chain = _make_chain([_make_event()])
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "thresh=1" in content

    def test_completion_pattern_contains_chain_name(self, tmp_path):
        chain = _make_chain([_make_event()], name="Recon Chain")
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "pattern=CHAIN: Recon Chain" in content

    def test_completion_action_contains_chain_complete(self, tmp_path):
        chain = _make_chain([_make_event()], name="My Chain")
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "REDSEC CHAIN COMPLETE: My Chain" in content

    def test_completion_action_contains_severity(self, tmp_path):
        chain = _make_chain([_make_event()], severity="critical")
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "severity=critical" in content

    def test_completion_rule_has_window(self, tmp_path):
        chain = _make_chain([_make_event()])
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "window=86400" in content

    def test_single_rules_precede_completion_rule(self, tmp_path):
        chain = _make_chain([_make_event()], name="Ordered Chain")
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        single_pos = content.index("type=Single")
        threshold_pos = content.index("type=SingleWithThreshold")
        assert single_pos < threshold_pos

    def test_no_sub_lines_generated(self, tmp_path):
        chain = _make_chain([_make_event(), _make_event(tool="metasploit", event_type="exploit_success", severity="high")])
        path = str(tmp_path / "chain.conf")
        SecExporter().export_chain(chain, path)
        content = open(path).read()
        assert "\nsub=" not in content
