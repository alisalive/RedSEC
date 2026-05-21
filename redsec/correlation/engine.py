"""Correlation engine for RedSEC.

Loads YAML rule files and matches sequences of RedSecEvent instances
into AttackChain objects based on event_type ordering and time windows.
"""

import os
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Optional, Union

import yaml

from redsec.mitre.mapper import MitreMapper
from redsec.models.chain import AttackChain
from redsec.models.event import EventType, RedSecEvent, Severity


# Severity string → enum, used when converting rule YAML values.
_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}


@dataclass
class _Rule:
    """Internal representation of a parsed sequence correlation rule."""

    name: str
    description: str
    conditions: list[str]       # Ordered event_type values
    window_seconds: int
    chain_name: str
    severity: Severity


@dataclass
class _PairRule:
    """Internal representation of a parsed PairWithWindow correlation rule.

    A PairWithWindow rule monitors for a *first* event type followed by a
    *second* event type within ``window_seconds``.  If the second event
    arrives in time the ``on_match`` message is recorded; otherwise the
    ``on_timeout`` message is used.
    """

    name: str
    description: str
    first: str          # event_type value for the triggering event
    second: str         # event_type value for the confirming event
    window_seconds: int
    chain_name: str
    severity: Severity
    on_match: str       # Message when second event arrives within window
    on_timeout: str     # Message when second event does not arrive in time


class CorrelationEngine:
    """Correlate RedSecEvent sequences into AttackChain objects using YAML rules.

    On initialisation the engine loads all ``*.yaml`` files from the given
    rules directory.  Each file may contain a top-level ``rules`` list.
    ``correlate()`` then scans a flat event list and returns one AttackChain
    per rule match found.

    Matching logic:
        For each rule the engine walks the sorted event list and tries to
        build a complete sequence that satisfies the condition order within
        the configured time window.  A greedy left-to-right scan is used:
        the first event matching condition[0] anchors the window; subsequent
        conditions must each be satisfied by an event that (a) has the
        required event_type and (b) falls within ``window_seconds`` of the
        anchor event.  Once all conditions are satisfied the matching events
        are grouped into an AttackChain and enriched via MitreMapper.
        Overlapping matches (reusing events) are allowed so that a single
        event can participate in multiple chains.
    """

    def __init__(self, rules_dir: str) -> None:
        """Initialise the engine and load rules from a directory.

        Args:
            rules_dir: Path to the directory containing ``*.yaml`` rule files.

        Raises:
            FileNotFoundError: If ``rules_dir`` does not exist.
        """
        self._rules: list[Union[_Rule, _PairRule]] = []
        self._mapper = MitreMapper()
        self.load_rules(rules_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_rules(self, rules_dir: str) -> None:
        """Load all ``*.yaml`` rule files from a directory.

        Existing rules are replaced on each call.  Files that fail to
        parse are skipped with a printed warning rather than raising so
        that one bad file does not block the others.

        Args:
            rules_dir: Path to the directory containing rule YAML files.

        Raises:
            FileNotFoundError: If ``rules_dir`` does not exist or is not a
                directory.
        """
        if not os.path.isdir(rules_dir):
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        self._rules: list[Union[_Rule, _PairRule]] = []
        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith(".yaml") and not fname.endswith(".yml"):
                continue
            file_path = os.path.join(rules_dir, fname)
            try:
                self._load_yaml_file(file_path)
            except Exception as exc:  # noqa: BLE001
                print(f"[CorrelationEngine] Warning: skipping {fname}: {exc}")

    def correlate(self, events: list[RedSecEvent]) -> list[AttackChain]:
        """Match correlation rules against an event list and return chains.

        Events are sorted by timestamp before matching.  Each rule is
        evaluated independently against the full sorted list; a single event
        may appear in multiple chains if it satisfies multiple rules.

        Args:
            events: Flat list of RedSecEvent instances from one or more parsers.

        Returns:
            List of AttackChain objects, one per rule match found.  Empty if
            no rules match or the event list is empty.
        """
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        chains: list[AttackChain] = []

        for rule in self._rules:
            if isinstance(rule, _PairRule):
                matched = self._match_pair_rule(rule, sorted_events)
            else:
                matched = self._match_rule(rule, sorted_events)
            chains.extend(matched)

        return chains

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_yaml_file(self, file_path: str) -> None:
        """Parse a single YAML file and append its rules to the engine.

        Args:
            file_path: Absolute path to the YAML rule file.

        Raises:
            ValueError: If the file structure is invalid.
            yaml.YAMLError: If the file cannot be parsed.
        """
        with open(file_path, "r", encoding="utf-8") as fh:
            data: Any = yaml.safe_load(fh)

        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError(f"Missing top-level 'rules' key in {file_path}")

        for entry in data["rules"]:
            rule: Union[_Rule, _PairRule] = self._parse_rule_entry(entry, file_path)
            self._rules.append(rule)

    def _parse_rule_entry(self, entry: dict, source: str) -> Union[_Rule, _PairRule]:
        """Validate and convert a raw YAML rule dict into a typed rule dataclass.

        Dispatches to ``_parse_sequence_rule`` for standard ``type=sequence``
        rules (the default) and to ``_parse_pair_rule`` for
        ``type=pair_with_window`` rules.

        Args:
            entry: Dict loaded from a single YAML rule entry.
            source: File path used in error messages only.

        Returns:
            A validated ``_Rule`` or ``_PairRule`` instance.

        Raises:
            ValueError: If required fields are missing or values are invalid.
        """
        rule_type = entry.get("type", "sequence")
        if rule_type == "pair_with_window":
            return self._parse_pair_rule(entry, source)
        return self._parse_sequence_rule(entry, source)

    def _parse_sequence_rule(self, entry: dict, source: str) -> _Rule:
        """Validate and convert a raw YAML entry into a ``_Rule`` dataclass.

        Args:
            entry: Dict loaded from a single YAML sequence rule entry.
            source: File path used in error messages only.

        Returns:
            A validated ``_Rule`` instance.

        Raises:
            ValueError: If required fields are missing or values are invalid.
        """
        required = ("name", "conditions", "window_seconds", "chain_name", "severity")
        for field in required:
            if field not in entry:
                raise ValueError(
                    f"Rule in {source} is missing required field '{field}': {entry}"
                )

        conditions: list[str] = entry["conditions"]
        if not conditions or len(conditions) < 2:
            raise ValueError(
                f"Rule '{entry['name']}' in {source} must have at least 2 conditions."
            )

        valid_types = {e.value for e in EventType}
        for cond in conditions:
            if cond not in valid_types:
                raise ValueError(
                    f"Rule '{entry['name']}' in {source}: unknown event_type '{cond}'. "
                    f"Valid values: {sorted(valid_types)}"
                )

        severity_str = str(entry["severity"]).lower()
        severity = _SEVERITY_MAP.get(severity_str)
        if severity is None:
            raise ValueError(
                f"Rule '{entry['name']}' in {source}: unknown severity '{severity_str}'."
            )

        return _Rule(
            name=entry["name"],
            description=entry.get("description", ""),
            conditions=conditions,
            window_seconds=int(entry["window_seconds"]),
            chain_name=entry["chain_name"],
            severity=severity,
        )

    def _parse_pair_rule(self, entry: dict, source: str) -> _PairRule:
        """Validate and convert a raw YAML entry into a ``_PairRule`` dataclass.

        Args:
            entry: Dict loaded from a single YAML pair_with_window rule entry.
            source: File path used in error messages only.

        Returns:
            A validated ``_PairRule`` instance.

        Raises:
            ValueError: If required fields are missing or event types are unknown.
        """
        required = ("name", "first", "second", "window_seconds", "chain_name",
                    "severity", "on_match", "on_timeout")
        for field in required:
            if field not in entry:
                raise ValueError(
                    f"PairWithWindow rule in {source} is missing required field '{field}': {entry}"
                )

        valid_types = {e.value for e in EventType}
        for key in ("first", "second"):
            val = entry[key]
            if val not in valid_types:
                raise ValueError(
                    f"Rule '{entry['name']}' in {source}: unknown event_type '{val}' "
                    f"for field '{key}'. Valid values: {sorted(valid_types)}"
                )

        severity_str = str(entry["severity"]).lower()
        severity = _SEVERITY_MAP.get(severity_str)
        if severity is None:
            raise ValueError(
                f"Rule '{entry['name']}' in {source}: unknown severity '{severity_str}'."
            )

        return _PairRule(
            name=entry["name"],
            description=entry.get("description", ""),
            first=entry["first"],
            second=entry["second"],
            window_seconds=int(entry["window_seconds"]),
            chain_name=entry["chain_name"],
            severity=severity,
            on_match=entry["on_match"],
            on_timeout=entry["on_timeout"],
        )

    def _match_rule(self, rule: _Rule, sorted_events: list[RedSecEvent]) -> list[AttackChain]:
        """Find all non-overlapping-anchor sequences matching a single rule.

        The anchor is the first condition.  Each anchor event is tried once;
        if a complete sequence is found the anchor advances past the last
        matched event index to avoid producing the same chain twice from the
        same anchor.

        Args:
            rule: The correlation rule to match.
            sorted_events: Events sorted ascending by timestamp.

        Returns:
            List of AttackChain instances produced by this rule (may be empty).
        """
        chains: list[AttackChain] = []
        window = timedelta(seconds=rule.window_seconds)
        n = len(sorted_events)
        anchor_idx = 0

        while anchor_idx < n:
            # Find next event matching the first condition.
            while anchor_idx < n and sorted_events[anchor_idx].event_type != rule.conditions[0]:
                anchor_idx += 1
            if anchor_idx >= n:
                break

            anchor = sorted_events[anchor_idx]
            deadline = anchor.timestamp + window

            # Greedily satisfy remaining conditions in order.
            matched: list[RedSecEvent] = [anchor]
            cond_idx = 1
            search_from = anchor_idx + 1

            while cond_idx < len(rule.conditions) and search_from < n:
                candidate = sorted_events[search_from]
                if candidate.timestamp > deadline:
                    break
                if candidate.event_type == rule.conditions[cond_idx]:
                    matched.append(candidate)
                    cond_idx += 1
                search_from += 1

            if cond_idx == len(rule.conditions):
                # All conditions satisfied — build chain.
                chain = self._build_chain(rule, matched)
                chains.append(chain)
                # Advance anchor past the last matched event's position.
                anchor_idx = sorted_events.index(matched[-1]) + 1
            else:
                anchor_idx += 1

        return chains

    def _match_pair_rule(
        self, rule: _PairRule, sorted_events: list[RedSecEvent]
    ) -> list[AttackChain]:
        """Find all PairWithWindow matches for a single pair rule.

        For every occurrence of the *first* event type a chain is produced:
        if the *second* event type is found within ``window_seconds`` of the
        first event the chain carries the ``on_match`` outcome; otherwise it
        carries the ``on_timeout`` outcome.  The anchor advances by one after
        each first-event occurrence so all occurrences are processed.

        Args:
            rule: The ``_PairRule`` to evaluate.
            sorted_events: Events sorted ascending by timestamp.

        Returns:
            List of ``AttackChain`` instances, one per first-event occurrence.
            Empty if no first event is found.
        """
        chains: list[AttackChain] = []
        window = timedelta(seconds=rule.window_seconds)
        n = len(sorted_events)
        anchor_idx = 0

        while anchor_idx < n:
            # Advance to the next event matching the first type.
            while anchor_idx < n and sorted_events[anchor_idx].event_type != rule.first:
                anchor_idx += 1
            if anchor_idx >= n:
                break

            first_event = sorted_events[anchor_idx]
            deadline = first_event.timestamp + window

            # Search for the second event type within the window.
            second_event: Optional[RedSecEvent] = None
            for i in range(anchor_idx + 1, n):
                candidate = sorted_events[i]
                if candidate.timestamp > deadline:
                    break
                if candidate.event_type == rule.second:
                    second_event = candidate
                    break

            chain = self._build_pair_chain(rule, first_event, second_event)
            chains.append(chain)
            anchor_idx += 1

        return chains

    def _build_pair_chain(
        self,
        rule: _PairRule,
        first_event: RedSecEvent,
        second_event: Optional[RedSecEvent],
    ) -> AttackChain:
        """Construct an AttackChain from a PairWithWindow evaluation result.

        Sets ``pair_type``, ``pair_on_match``, ``pair_on_timeout``,
        ``pair_window_seconds``, and ``pair_second_type`` on the returned
        chain so that exporters can generate the correct SEC output.

        Args:
            rule: The ``_PairRule`` that produced this result.
            first_event: The event matching ``rule.first``.
            second_event: The event matching ``rule.second`` if found within
                the window; ``None`` for a timeout outcome.

        Returns:
            An ``AttackChain`` enriched with MITRE ATT&CK data.
        """
        severity = Severity.critical if second_event is not None else rule.severity
        end_time = second_event.timestamp if second_event is not None else first_event.timestamp

        chain = AttackChain(
            name=rule.chain_name,
            start_time=first_event.timestamp,
            end_time=end_time,
            severity=severity,
            pair_type="pair_with_window",
            pair_on_match=rule.on_match,
            pair_on_timeout=rule.on_timeout,
            pair_window_seconds=rule.window_seconds,
            pair_second_type=rule.second,
        )
        chain.add_event(first_event)
        if second_event is not None:
            chain.add_event(second_event)

        self._mapper.enrich_chain(chain)
        return chain

    def _build_chain(self, rule: _Rule, events: list[RedSecEvent]) -> AttackChain:
        """Construct and enrich an AttackChain from a matched event sequence.

        Args:
            rule: The rule that produced this match.
            events: Ordered list of matching RedSecEvent instances.

        Returns:
            An AttackChain enriched with MITRE ATT&CK data.
        """
        chain = AttackChain(
            name=rule.chain_name,
            start_time=events[0].timestamp,
            end_time=events[-1].timestamp,
            severity=rule.severity,
        )
        for event in events:
            chain.add_event(event)

        self._mapper.enrich_chain(chain)
        return chain
