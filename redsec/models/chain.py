"""Attack chain model for RedSEC.

An AttackChain groups a sequence of correlated RedSecEvents that together
represent a logical attack path, enabling timeline analysis and MITRE mapping.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from redsec.models.event import RedSecEvent, Severity


# Severity rank used for finding the maximum severity across events.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class AttackChain(BaseModel):
    """A correlated sequence of events forming a single attack path.

    Built by the correlation engine from individual RedSecEvent instances.
    The chain tracks the full timeline, unique MITRE techniques, and the
    overall severity (highest severity among member events).
    """

    model_config = {
        "json_encoders": {datetime: lambda dt: dt.isoformat()},
        "use_enum_values": True,
    }

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Auto-generated UUID uniquely identifying this attack chain.",
    )
    name: str = Field(
        description="Human-readable name describing the attack chain (e.g. 'Recon → Exploitation').",
    )
    events: list[RedSecEvent] = Field(
        default_factory=list,
        description="Ordered list of events that make up this attack chain.",
    )
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC datetime of the earliest event in the chain.",
    )
    end_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC datetime of the latest event in the chain.",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Deduplicated list of MITRE ATT&CK technique IDs observed in this chain.",
    )
    severity: Severity = Field(
        default=Severity.info,
        description="Highest severity level among all events in this chain.",
    )
    pair_type: Optional[str] = Field(
        default=None,
        description="Set to 'pair_with_window' for chains produced by PairWithWindow rules; None for sequence chains.",
    )
    pair_on_match: Optional[str] = Field(
        default=None,
        description="Message emitted when both events of a PairWithWindow rule are matched.",
    )
    pair_on_timeout: Optional[str] = Field(
        default=None,
        description="Message emitted when the first event matches but the second does not arrive in time.",
    )
    pair_window_seconds: Optional[int] = Field(
        default=None,
        description="Time window in seconds for PairWithWindow rules.",
    )
    pair_second_type: Optional[str] = Field(
        default=None,
        description="Event type string for the second event in a PairWithWindow rule; used when generating SEC patterns for timeout chains.",
    )
    is_synthetic: bool = Field(
        default=False,
        description="True when this chain was produced by a Synthetic rule and includes an engine-generated RedSecEvent.",
    )

    def add_event(self, event: RedSecEvent) -> None:
        """Add an event to the chain and update derived fields.

        Updates start_time, end_time, mitre_techniques, and severity
        automatically based on the new event's attributes.

        Args:
            event: The RedSecEvent to append to this chain.
        """
        self.events.append(event)

        # Update time bounds.
        event_time = event.timestamp
        if event_time < self.start_time:
            self.start_time = event_time
        if event_time > self.end_time:
            self.end_time = event_time

        # Accumulate unique MITRE techniques.
        if event.mitre_technique and event.mitre_technique not in self.mitre_techniques:
            self.mitre_techniques.append(event.mitre_technique)

        # Promote severity to the highest seen.
        event_severity = event.severity if isinstance(event.severity, str) else event.severity.value
        chain_severity = self.severity if isinstance(self.severity, str) else self.severity.value
        if _SEVERITY_RANK.get(event_severity, 0) > _SEVERITY_RANK.get(chain_severity, 0):
            self.severity = event.severity

    def summary(self) -> dict:
        """Return a concise summary of the attack chain.

        Useful for report generation and logging without serializing all events.

        Returns:
            A dict with id, name, event_count, start_time, end_time,
            duration_seconds, mitre_techniques, severity, and targets.
        """
        targets: list[str] = list({e.target for e in self.events})
        duration = (self.end_time - self.start_time).total_seconds()

        return {
            "id": self.id,
            "name": self.name,
            "event_count": len(self.events),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": duration,
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity if isinstance(self.severity, str) else self.severity.value,
            "targets": targets,
        }
