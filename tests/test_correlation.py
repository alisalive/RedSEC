"""Basic tests for CorrelationEngine using the default rules."""

import pathlib
import textwrap
import tempfile
import os
from datetime import datetime, timedelta, timezone

import pytest

from redsec.correlation.engine import CorrelationEngine, _ContextRule, _PairRule, _SyntheticRule
from redsec.models.event import EventType, RedSecEvent, Severity, ToolName

RULES_DIR = str(pathlib.Path(__file__).parent.parent / "redsec" / "correlation" / "rules")


def make_event(event_type: EventType, offset_seconds: int = 0) -> RedSecEvent:
    """Return a minimal RedSecEvent with the given type and timestamp offset."""
    base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return RedSecEvent(
        tool=ToolName.nmap,
        event_type=event_type,
        severity=Severity.info,
        timestamp=base + timedelta(seconds=offset_seconds),
        target="192.168.1.1",
        description="test event",
    )


class TestCorrelationEngine:
    def test_loads_default_rules(self):
        engine = CorrelationEngine(RULES_DIR)
        assert len(engine._rules) > 0

    def test_empty_event_list_returns_no_chains(self):
        engine = CorrelationEngine(RULES_DIR)
        assert engine.correlate([]) == []

    def test_single_event_returns_no_chains(self):
        # subdomain_found is not the first condition of any sequence or pair rule.
        engine = CorrelationEngine(RULES_DIR)
        events = [make_event(EventType.subdomain_found)]
        assert engine.correlate(events) == []

    def test_recon_chain_matched(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.port_scan, offset_seconds=0),
            make_event(EventType.dir_found, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Recon Chain" in names

    def test_web_attack_chain_matched(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.dir_found, offset_seconds=0),
            make_event(EventType.vuln_found, offset_seconds=120),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Web Attack Chain" in names

    def test_credential_attack_chain_matched(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.login_failed, offset_seconds=0),
            make_event(EventType.login_success, offset_seconds=30),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Credential Attack" in names

    def test_events_outside_window_no_match(self):
        engine = CorrelationEngine(RULES_DIR)
        # Default window is 86400s; place events 2 days apart.
        events = [
            make_event(EventType.port_scan, offset_seconds=0),
            make_event(EventType.dir_found, offset_seconds=86400 * 2),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Recon Chain" not in names

    def test_chain_contains_matched_events(self):
        engine = CorrelationEngine(RULES_DIR)
        e1 = make_event(EventType.port_scan, offset_seconds=0)
        e2 = make_event(EventType.dir_found, offset_seconds=60)
        chains = engine.correlate([e1, e2])
        recon = next(c for c in chains if c.name == "Recon Chain")
        assert len(recon.events) == 2

    def test_chain_severity_set(self):
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_event(EventType.port_scan, offset_seconds=0),
            make_event(EventType.dir_found, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        recon = next(c for c in chains if c.name == "Recon Chain")
        assert recon.severity == Severity.low.value

    def test_invalid_rules_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            CorrelationEngine("/nonexistent/rules/dir")


# ---------------------------------------------------------------------------
# Helpers for PairWithWindow tests
# ---------------------------------------------------------------------------

PAIR_YAML = textwrap.dedent("""\
    rules:
      - name: "Test Recon Pair"
        description: "Test pair rule."
        type: pair_with_window
        first: port_scan
        second: exploit_success
        window_seconds: 300
        chain_name: "Test Recon Pair"
        severity: critical
        on_match: "MATCH: attack confirmed"
        on_timeout: "TIMEOUT: recon only"
""")


@pytest.fixture()
def pair_rules_dir(tmp_path):
    """Temporary rules directory containing only the PAIR_YAML rule."""
    (tmp_path / "pair.yaml").write_text(PAIR_YAML, encoding="utf-8")
    return str(tmp_path)


def make_pair_event(event_type: EventType, offset_seconds: int = 0) -> RedSecEvent:
    """Return a minimal RedSecEvent with the given type and timestamp offset."""
    base = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    return RedSecEvent(
        tool=ToolName.nmap,
        event_type=event_type,
        severity=Severity.info,
        timestamp=base + timedelta(seconds=offset_seconds),
        target="10.0.0.1",
        description="pair test event",
    )


class TestPairWithWindow:
    """Tests for type=pair_with_window correlation rules."""

    def test_pair_rules_loaded_from_yaml(self, pair_rules_dir):
        """Pair rules are parsed and stored in _rules alongside sequence rules."""
        engine = CorrelationEngine(pair_rules_dir)
        assert len(engine._rules) == 1
        assert isinstance(engine._rules[0], _PairRule)

    def test_default_rules_include_pair_rules(self):
        """Default YAML file contains at least the three new PairWithWindow rules."""
        engine = CorrelationEngine(RULES_DIR)
        pair_rules = [r for r in engine._rules if isinstance(r, _PairRule)]
        pair_names = {r.name for r in pair_rules}
        assert "Recon to Exploit Pair" in pair_names
        assert "Credential Attack Pair" in pair_names
        assert "Lateral Movement Pair" in pair_names

    def test_pair_match_creates_chain_with_two_events(self, pair_rules_dir):
        """Second event within window → chain contains both events."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.exploit_success, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        assert len(chains) == 1
        assert len(chains[0].events) == 2

    def test_pair_match_chain_name(self, pair_rules_dir):
        """Matched pair chain uses the rule's chain_name."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.exploit_success, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        assert chains[0].name == "Test Recon Pair"

    def test_pair_match_severity_is_critical(self, pair_rules_dir):
        """A matched pair always has critical severity."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.exploit_success, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        assert chains[0].severity == Severity.critical.value

    def test_pair_match_pair_type_field(self, pair_rules_dir):
        """Matched pair chain has pair_type='pair_with_window'."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.exploit_success, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        assert chains[0].pair_type == "pair_with_window"

    def test_pair_match_on_match_stored(self, pair_rules_dir):
        """Matched pair chain stores the on_match message."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.exploit_success, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        assert chains[0].pair_on_match == "MATCH: attack confirmed"

    def test_pair_timeout_creates_chain_with_one_event(self, pair_rules_dir):
        """Second event outside window → timeout chain contains only first event."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.exploit_success, offset_seconds=400),  # > 300s window
        ]
        chains = engine.correlate(events)
        # Two first-events from a scan that times out, plus second scan uses the exploit
        # Actually: one port_scan at t=0 → timeout (exploit at t=400 is outside window)
        #           one port_scan — wait, there's only one port_scan, so one chain (timeout)
        #           Then the exploit at t=400 has no anchor, so just the one timeout chain.
        timeout_chains = [c for c in chains if len(c.events) == 1]
        assert len(timeout_chains) >= 1
        assert timeout_chains[0].pair_on_timeout == "TIMEOUT: recon only"

    def test_pair_timeout_no_second_event(self, pair_rules_dir):
        """First event with no second event at all → timeout chain."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [make_pair_event(EventType.port_scan, offset_seconds=0)]
        chains = engine.correlate(events)
        assert len(chains) == 1
        assert len(chains[0].events) == 1
        assert chains[0].pair_on_timeout == "TIMEOUT: recon only"

    def test_pair_timeout_pair_type_set(self, pair_rules_dir):
        """Timeout chain also has pair_type='pair_with_window'."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [make_pair_event(EventType.port_scan, offset_seconds=0)]
        chains = engine.correlate(events)
        assert chains[0].pair_type == "pair_with_window"

    def test_pair_second_type_stored(self, pair_rules_dir):
        """pair_second_type is set on the chain from the rule's second field."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [make_pair_event(EventType.port_scan, offset_seconds=0)]
        chains = engine.correlate(events)
        assert chains[0].pair_second_type == "exploit_success"

    def test_pair_window_seconds_stored(self, pair_rules_dir):
        """pair_window_seconds is stored on the chain."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [make_pair_event(EventType.port_scan, offset_seconds=0)]
        chains = engine.correlate(events)
        assert chains[0].pair_window_seconds == 300

    def test_pair_no_first_event_returns_empty(self, pair_rules_dir):
        """Events with no first-type event produce no chains."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [make_pair_event(EventType.dir_found, offset_seconds=0)]
        chains = engine.correlate(events)
        assert chains == []

    def test_pair_multiple_first_events(self, pair_rules_dir):
        """Each first event independently produces a chain (match or timeout)."""
        engine = CorrelationEngine(pair_rules_dir)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.port_scan, offset_seconds=100),
            make_pair_event(EventType.exploit_success, offset_seconds=120),
        ]
        chains = engine.correlate(events)
        # First port_scan at t=0: exploit at t=120 is within 300s → match
        # Second port_scan at t=100: exploit at t=120 is within 300s → match
        assert len(chains) == 2

    def test_sequence_rules_still_work_alongside_pair_rules(self):
        """Existing sequence rules continue to match correctly after pair rules added."""
        engine = CorrelationEngine(RULES_DIR)
        events = [
            make_pair_event(EventType.port_scan, offset_seconds=0),
            make_pair_event(EventType.dir_found, offset_seconds=60),
        ]
        chains = engine.correlate(events)
        names = [c.name for c in chains]
        assert "Recon Chain" in names

    def test_pair_rule_missing_field_raises(self, tmp_path):
        """A pair rule missing 'on_match' raises ValueError during load."""
        bad_yaml = textwrap.dedent("""\
            rules:
              - name: "Bad Pair"
                type: pair_with_window
                first: port_scan
                second: exploit_success
                window_seconds: 60
                chain_name: "Bad Pair"
                severity: critical
                on_timeout: "timeout message"
        """)
        (tmp_path / "bad.yaml").write_text(bad_yaml, encoding="utf-8")
        engine = CorrelationEngine(str(tmp_path))
        # Bad rule is skipped with a warning; _rules should be empty.
        assert len(engine._rules) == 0

    def test_pair_rule_unknown_event_type_raises(self, tmp_path):
        """A pair rule with an invalid first event type is skipped."""
        bad_yaml = textwrap.dedent("""\
            rules:
              - name: "Bad Pair"
                type: pair_with_window
                first: nonexistent_type
                second: exploit_success
                window_seconds: 60
                chain_name: "Bad Pair"
                severity: critical
                on_match: "match"
                on_timeout: "timeout"
        """)
        (tmp_path / "bad.yaml").write_text(bad_yaml, encoding="utf-8")
        engine = CorrelationEngine(str(tmp_path))
        assert len(engine._rules) == 0


# ---------------------------------------------------------------------------
# Helpers for Context rule tests
# ---------------------------------------------------------------------------

CTX_YAML = textwrap.dedent("""\
    rules:
      - name: "Test Context Attack"
        description: "Trigger and match on same target."
        type: context
        trigger: port_scan
        context_field: target
        match: vuln_found
        window_seconds: 300
        chain_name: "Test Context Attack"
        severity: high
        on_match: "FOCUSED: same target"
        on_miss: "SCATTERED: different targets"
""")


@pytest.fixture()
def ctx_rules_dir(tmp_path):
    """Temporary rules directory containing only the CTX_YAML rule."""
    (tmp_path / "ctx.yaml").write_text(CTX_YAML, encoding="utf-8")
    return str(tmp_path)


def make_ctx_event(
    event_type: EventType,
    offset_seconds: int = 0,
    target: str = "10.0.0.1",
) -> RedSecEvent:
    """Return a minimal RedSecEvent with configurable type, offset, and target."""
    base = datetime(2024, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    return RedSecEvent(
        tool=ToolName.nmap,
        event_type=event_type,
        severity=Severity.info,
        timestamp=base + timedelta(seconds=offset_seconds),
        target=target,
        description="ctx test event",
    )


class TestContextRule:
    """Tests for type=context correlation rules."""

    def test_context_rules_loaded_from_yaml(self, ctx_rules_dir):
        """Context rules are parsed and stored as _ContextRule instances."""
        engine = CorrelationEngine(ctx_rules_dir)
        assert len(engine._rules) == 1
        assert isinstance(engine._rules[0], _ContextRule)

    def test_default_rules_include_context_rules(self):
        """Default YAML contains the two context rules."""
        engine = CorrelationEngine(RULES_DIR)
        ctx_names = {r.name for r in engine._rules if isinstance(r, _ContextRule)}
        assert "Same Target Attack" in ctx_names
        assert "Same Target Credential Attack" in ctx_names

    def test_context_same_target_produces_on_match_chain(self, ctx_rules_dir):
        """Trigger and match on same target → on_match chain with 2 events."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0, target="10.0.0.1"),
            make_ctx_event(EventType.vuln_found, offset_seconds=60, target="10.0.0.1"),
        ]
        chains = engine.correlate(events)
        assert len(chains) == 1
        chain = chains[0]
        assert len(chain.events) == 2
        assert chain.pair_on_match == "FOCUSED: same target"

    def test_context_different_target_produces_on_miss_chain(self, ctx_rules_dir):
        """Trigger and match on different targets → on_miss chain with 2 events."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0, target="10.0.0.1"),
            make_ctx_event(EventType.vuln_found, offset_seconds=60, target="10.0.0.2"),
        ]
        chains = engine.correlate(events)
        assert len(chains) == 1
        chain = chains[0]
        assert len(chain.events) == 2
        assert chain.pair_on_timeout == "SCATTERED: different targets"

    def test_context_no_match_event_produces_no_chain(self, ctx_rules_dir):
        """Trigger with no following match event → no chain produced."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [make_ctx_event(EventType.port_scan, offset_seconds=0)]
        chains = engine.correlate(events)
        assert chains == []

    def test_context_match_outside_window_produces_no_chain(self, ctx_rules_dir):
        """Match event after window expires → no chain produced."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0, target="10.0.0.1"),
            make_ctx_event(EventType.vuln_found, offset_seconds=400, target="10.0.0.1"),
        ]
        chains = engine.correlate(events)
        assert chains == []

    def test_context_pair_type_is_context(self, ctx_rules_dir):
        """Chain produced by context rule has pair_type='context'."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0),
            make_ctx_event(EventType.vuln_found, offset_seconds=10),
        ]
        chains = engine.correlate(events)
        assert chains[0].pair_type == "context"

    def test_context_chain_name_from_rule(self, ctx_rules_dir):
        """Context chain uses the rule's chain_name."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0),
            make_ctx_event(EventType.vuln_found, offset_seconds=10),
        ]
        chains = engine.correlate(events)
        assert chains[0].name == "Test Context Attack"

    def test_context_window_seconds_stored(self, ctx_rules_dir):
        """pair_window_seconds is populated from the rule."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0),
            make_ctx_event(EventType.vuln_found, offset_seconds=10),
        ]
        chains = engine.correlate(events)
        assert chains[0].pair_window_seconds == 300

    def test_context_second_type_stored(self, ctx_rules_dir):
        """pair_second_type reflects the rule's match field."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0),
            make_ctx_event(EventType.vuln_found, offset_seconds=10),
        ]
        chains = engine.correlate(events)
        assert chains[0].pair_second_type == "vuln_found"

    def test_context_multiple_triggers_each_produces_chain(self, ctx_rules_dir):
        """Each trigger event independently seeks a match event."""
        engine = CorrelationEngine(ctx_rules_dir)
        events = [
            make_ctx_event(EventType.port_scan, offset_seconds=0, target="10.0.0.1"),
            make_ctx_event(EventType.port_scan, offset_seconds=50, target="10.0.0.2"),
            make_ctx_event(EventType.vuln_found, offset_seconds=100, target="10.0.0.2"),
        ]
        chains = engine.correlate(events)
        # First port_scan (10.0.0.1) → vuln at 10.0.0.2 (different) → on_miss chain
        # Second port_scan (10.0.0.2) → vuln at 10.0.0.2 (same) → on_match chain
        assert len(chains) == 2

    def test_context_missing_field_raises(self, tmp_path):
        """A context rule missing 'on_miss' is skipped with a warning."""
        bad_yaml = textwrap.dedent("""\
            rules:
              - name: "Bad Context"
                type: context
                trigger: port_scan
                context_field: target
                match: vuln_found
                window_seconds: 60
                chain_name: "Bad Context"
                severity: high
                on_match: "match"
        """)
        (tmp_path / "bad.yaml").write_text(bad_yaml, encoding="utf-8")
        engine = CorrelationEngine(str(tmp_path))
        assert len(engine._rules) == 0

    def test_context_invalid_context_field_raises(self, tmp_path):
        """A context rule with an unsupported context_field is skipped."""
        bad_yaml = textwrap.dedent("""\
            rules:
              - name: "Bad Context"
                type: context
                trigger: port_scan
                context_field: nonexistent_field
                match: vuln_found
                window_seconds: 60
                chain_name: "Bad Context"
                severity: high
                on_match: "match"
                on_miss: "miss"
        """)
        (tmp_path / "bad.yaml").write_text(bad_yaml, encoding="utf-8")
        engine = CorrelationEngine(str(tmp_path))
        assert len(engine._rules) == 0


# ---------------------------------------------------------------------------
# Helpers for Synthetic rule tests
# ---------------------------------------------------------------------------

SYNTH_YAML = textwrap.dedent("""\
    rules:
      - name: "Test Mass Scan"
        description: "Three port scans in 60s triggers a synthetic event."
        type: synthetic
        trigger: port_scan
        threshold: 3
        window_seconds: 60
        synthetic_event_type: vuln_found
        synthetic_severity: high
        chain_name: "Test Mass Scan"
        severity: high
        message: "SYNTHETIC: mass scan detected"
""")


@pytest.fixture()
def synth_rules_dir(tmp_path):
    """Temporary rules directory containing only the SYNTH_YAML rule."""
    (tmp_path / "synth.yaml").write_text(SYNTH_YAML, encoding="utf-8")
    return str(tmp_path)


def make_synth_event(
    event_type: EventType,
    offset_seconds: int = 0,
    target: str = "10.0.0.1",
) -> RedSecEvent:
    """Return a minimal RedSecEvent for synthetic rule tests."""
    base = datetime(2024, 10, 1, 0, 0, 0, tzinfo=timezone.utc)
    return RedSecEvent(
        tool=ToolName.nmap,
        event_type=event_type,
        severity=Severity.info,
        timestamp=base + timedelta(seconds=offset_seconds),
        target=target,
        description="synth test event",
    )


class TestSyntheticRule:
    """Tests for type=synthetic correlation rules."""

    def test_synthetic_rules_loaded_from_yaml(self, synth_rules_dir):
        """Synthetic rules are parsed and stored as _SyntheticRule instances."""
        engine = CorrelationEngine(synth_rules_dir)
        assert len(engine._rules) == 1
        assert isinstance(engine._rules[0], _SyntheticRule)

    def test_default_rules_include_synthetic_rules(self):
        """Default YAML contains the two synthetic rules."""
        engine = CorrelationEngine(RULES_DIR)
        synth_names = {r.name for r in engine._rules if isinstance(r, _SyntheticRule)}
        assert "Mass Port Scan Detected" in synth_names
        assert "Brute Force Storm" in synth_names

    def test_threshold_reached_creates_chain(self, synth_rules_dir):
        """Exactly threshold events in window → one synthetic chain."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [
            make_synth_event(EventType.port_scan, offset_seconds=0),
            make_synth_event(EventType.port_scan, offset_seconds=10),
            make_synth_event(EventType.port_scan, offset_seconds=20),
        ]
        chains = engine.correlate(events)
        assert len(chains) == 1

    def test_below_threshold_produces_no_chain(self, synth_rules_dir):
        """Fewer than threshold events → no chain."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [
            make_synth_event(EventType.port_scan, offset_seconds=0),
            make_synth_event(EventType.port_scan, offset_seconds=10),
        ]
        chains = engine.correlate(events)
        assert chains == []

    def test_synthetic_chain_contains_trigger_plus_synthetic_event(self, synth_rules_dir):
        """Chain has threshold trigger events + 1 synthetic event."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [
            make_synth_event(EventType.port_scan, offset_seconds=0),
            make_synth_event(EventType.port_scan, offset_seconds=10),
            make_synth_event(EventType.port_scan, offset_seconds=20),
        ]
        chains = engine.correlate(events)
        assert len(chains[0].events) == 4  # 3 triggers + 1 synthetic

    def test_synthetic_event_tool_is_redsec(self, synth_rules_dir):
        """The generated synthetic event has tool='redsec'."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [
            make_synth_event(EventType.port_scan, offset_seconds=i * 10)
            for i in range(3)
        ]
        chains = engine.correlate(events)
        synthetic_event = chains[0].events[-1]
        assert synthetic_event.tool == ToolName.redsec.value

    def test_synthetic_event_type_matches_rule(self, synth_rules_dir):
        """The generated event has the event_type from the rule."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [make_synth_event(EventType.port_scan, offset_seconds=i * 5) for i in range(3)]
        chains = engine.correlate(events)
        synthetic_event = chains[0].events[-1]
        assert synthetic_event.event_type == EventType.vuln_found.value

    def test_synthetic_event_description_matches_message(self, synth_rules_dir):
        """The synthetic event description equals the rule's message field."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [make_synth_event(EventType.port_scan, offset_seconds=i * 5) for i in range(3)]
        chains = engine.correlate(events)
        assert chains[0].events[-1].description == "SYNTHETIC: mass scan detected"

    def test_synthetic_chain_is_synthetic_flag(self, synth_rules_dir):
        """Synthetic chain has is_synthetic=True."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [make_synth_event(EventType.port_scan, offset_seconds=i * 5) for i in range(3)]
        chains = engine.correlate(events)
        assert chains[0].is_synthetic is True

    def test_synthetic_chain_name_from_rule(self, synth_rules_dir):
        """Chain uses the rule's chain_name."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [make_synth_event(EventType.port_scan, offset_seconds=i * 5) for i in range(3)]
        chains = engine.correlate(events)
        assert chains[0].name == "Test Mass Scan"

    def test_synthetic_target_most_common(self, synth_rules_dir):
        """Synthetic event target is set to the most common trigger target."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [
            make_synth_event(EventType.port_scan, offset_seconds=0, target="10.0.0.5"),
            make_synth_event(EventType.port_scan, offset_seconds=5, target="10.0.0.5"),
            make_synth_event(EventType.port_scan, offset_seconds=10, target="10.0.0.9"),
        ]
        chains = engine.correlate(events)
        assert chains[0].events[-1].target == "10.0.0.5"

    def test_events_outside_window_not_grouped(self, synth_rules_dir):
        """Events beyond window_seconds are not grouped into the same chain."""
        engine = CorrelationEngine(synth_rules_dir)
        events = [
            make_synth_event(EventType.port_scan, offset_seconds=0),
            make_synth_event(EventType.port_scan, offset_seconds=10),
            make_synth_event(EventType.port_scan, offset_seconds=120),  # outside 60s window
        ]
        chains = engine.correlate(events)
        # First two events don't meet threshold; third is in its own window (still only 1 event)
        assert chains == []

    def test_synthetic_rule_missing_field_skipped(self, tmp_path):
        """A synthetic rule missing 'message' is skipped."""
        bad_yaml = textwrap.dedent("""\
            rules:
              - name: "Bad Synth"
                type: synthetic
                trigger: port_scan
                threshold: 3
                window_seconds: 60
                synthetic_event_type: vuln_found
                synthetic_severity: high
                chain_name: "Bad Synth"
                severity: high
        """)
        (tmp_path / "bad.yaml").write_text(bad_yaml, encoding="utf-8")
        engine = CorrelationEngine(str(tmp_path))
        assert len(engine._rules) == 0

    def test_synthetic_rule_threshold_below_two_skipped(self, tmp_path):
        """A synthetic rule with threshold < 2 is skipped."""
        bad_yaml = textwrap.dedent("""\
            rules:
              - name: "Bad Threshold"
                type: synthetic
                trigger: port_scan
                threshold: 1
                window_seconds: 60
                synthetic_event_type: vuln_found
                synthetic_severity: high
                chain_name: "Bad Threshold"
                severity: high
                message: "too low"
        """)
        (tmp_path / "bad.yaml").write_text(bad_yaml, encoding="utf-8")
        engine = CorrelationEngine(str(tmp_path))
        assert len(engine._rules) == 0
