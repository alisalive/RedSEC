"""Detection risk heuristic scorer for RedSEC.

Assigns a detection risk score (0.0 – 1.0) to each RedSecEvent based
on the event type, tool, and contextual modifiers such as port number.
Higher scores indicate a higher likelihood that a real SOC would detect
the activity.
"""

from redsec.models.chain import AttackChain
from redsec.models.event import EventType, RedSecEvent, ToolName

# ---------------------------------------------------------------------------
# Base scores per event type
# ---------------------------------------------------------------------------

_BASE: dict[str, float] = {
    EventType.port_scan.value:          0.85,
    EventType.subdomain_found.value:    0.20,
    EventType.dir_found.value:          0.60,
    EventType.vuln_found.value:         0.50,
    EventType.sqli_found.value:         0.70,
    EventType.login_failed.value:       0.75,
    EventType.login_success.value:      0.40,
    EventType.exploit_success.value:    0.90,
    EventType.lateral_movement.value:   0.95,
    EventType.credential_dumped.value:  0.98,
}

# ---------------------------------------------------------------------------
# Tool modifiers (additive delta applied to base score)
# ---------------------------------------------------------------------------

_TOOL_MODIFIER: dict[str, float] = {
    ToolName.nmap.value:        +0.10,   # Well-known nmap signatures
    ToolName.hydra.value:       +0.10,   # Brute-force pattern obvious
    ToolName.metasploit.value:  +0.15,   # MSF signatures in every IDS
    ToolName.nuclei.value:      -0.05,   # Can be stealthy
    ToolName.subfinder.value:   -0.20,   # Passive recon
}

# ---------------------------------------------------------------------------
# High-value port modifier
# ---------------------------------------------------------------------------

_SENSITIVE_PORTS: frozenset[int] = frozenset({22, 445, 3389, 1433, 3306})
_PORT_MODIFIER: float = +0.10

# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------

_RISK_LEVELS: list[tuple[float, str]] = [
    (0.30, "LOW"),
    (0.60, "MEDIUM"),
    (0.85, "HIGH"),
    (1.01, "CRITICAL"),
]


def _risk_level(score: float) -> str:
    """Map a numeric risk score to a human-readable risk level string.

    Args:
        score: Float in [0.0, 1.0].

    Returns:
        One of ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, or ``"CRITICAL"``.
    """
    for threshold, label in _RISK_LEVELS:
        if score < threshold:
            return label
    return "CRITICAL"


class DetectionScorer:
    """Compute detection risk heuristics for RedSecEvent instances.

    The scorer calculates a value in [0.0, 1.0] where:

    * **0.0** — activity is essentially invisible to a SOC.
    * **1.0** — activity would almost certainly trigger an alert.

    Scores are derived from a base score for the event type, adjusted by
    tool-specific modifiers and port-based modifiers, then clamped to
    [0.0, 1.0].  The computed score is written back to
    ``event.detection_risk`` so downstream exporters can use it directly.
    """

    def score(self, event: RedSecEvent) -> float:
        """Score a single event and write the result to ``event.detection_risk``.

        Scoring formula::

            score = base(event_type) + modifier(tool) + modifier(port)
            score = clamp(score, 0.0, 1.0)

        Args:
            event: The RedSecEvent to score.  ``detection_risk`` is set
                   in-place as a side effect.

        Returns:
            Detection risk score in [0.0, 1.0].
        """
        event_type_val = (
            event.event_type
            if isinstance(event.event_type, str)
            else event.event_type.value
        )
        tool_val = (
            event.tool
            if isinstance(event.tool, str)
            else event.tool.value
        )

        base = _BASE.get(event_type_val, 0.50)
        delta = _TOOL_MODIFIER.get(tool_val, 0.0)

        if event.port is not None and event.port in _SENSITIVE_PORTS:
            delta += _PORT_MODIFIER

        raw = base + delta
        final = max(0.0, min(1.0, raw))

        event.detection_risk = round(final, 4)
        return event.detection_risk

    def score_chain(self, chain: AttackChain) -> dict:
        """Score all events in a chain and return aggregate risk statistics.

        Each event in the chain is scored via ``score()`` (setting
        ``detection_risk`` on each event as a side effect).

        Args:
            chain: The AttackChain whose events are to be scored.

        Returns:
            Dict containing:

            * ``average_risk`` (float) — mean detection risk across events.
            * ``max_risk`` (float) — highest individual event risk.
            * ``min_risk`` (float) — lowest individual event risk.
            * ``highest_risk_event`` (str) — description of the riskiest event.
            * ``risk_level`` (str) — ``"LOW"`` / ``"MEDIUM"`` / ``"HIGH"`` /
              ``"CRITICAL"`` derived from ``average_risk``.
        """
        if not chain.events:
            return {
                "average_risk": 0.0,
                "max_risk": 0.0,
                "min_risk": 0.0,
                "highest_risk_event": "",
                "risk_level": "LOW",
            }

        scores: list[float] = [self.score(e) for e in chain.events]

        avg = round(sum(scores) / len(scores), 4)
        max_score = max(scores)
        min_score = min(scores)

        riskiest = chain.events[scores.index(max_score)]

        return {
            "average_risk": avg,
            "max_risk": round(max_score, 4),
            "min_risk": round(min_score, 4),
            "highest_risk_event": riskiest.description,
            "risk_level": _risk_level(avg),
        }

    def enrich_events(self, events: list[RedSecEvent]) -> list[RedSecEvent]:
        """Score every event in the list and return the enriched list.

        Each event's ``detection_risk`` field is set in-place.

        Args:
            events: List of RedSecEvent instances to enrich.

        Returns:
            The same list with ``detection_risk`` populated on all events.
        """
        for event in events:
            self.score(event)
        return events
