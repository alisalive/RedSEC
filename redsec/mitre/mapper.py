"""MITRE ATT&CK technique mapper for RedSEC.

Enriches RedSecEvent and AttackChain instances with MITRE ATT&CK
technique IDs and tactic names, either by validating an already-set
technique or inferring one from the event type.
"""

from typing import Optional

from redsec.models.chain import AttackChain
from redsec.models.event import EventType, RedSecEvent


# Internal MITRE ATT&CK technique registry.
# Each entry: technique_id → {tactic, name}
_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1046": {
        "tactic": "Discovery",
        "name": "Network Service Discovery",
    },
    "T1190": {
        "tactic": "Initial Access",
        "name": "Exploit Public-Facing Application",
    },
    "T1110": {
        "tactic": "Credential Access",
        "name": "Brute Force",
    },
    "T1078": {
        "tactic": "Defense Evasion",
        "name": "Valid Accounts",
    },
    "T1083": {
        "tactic": "Discovery",
        "name": "File and Directory Discovery",
    },
    "T1018": {
        "tactic": "Discovery",
        "name": "Remote System Discovery",
    },
    "T1059": {
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter",
    },
    "T1021": {
        "tactic": "Lateral Movement",
        "name": "Remote Services",
    },
    "T1003": {
        "tactic": "Credential Access",
        "name": "OS Credential Dumping",
    },
    "T1595": {
        "tactic": "Reconnaissance",
        "name": "Active Scanning",
    },
    "T1133": {
        "tactic": "Initial Access",
        "name": "External Remote Services",
    },
}

# Inferred technique per event_type when no technique is already set.
_INFERRED: dict[str, str] = {
    EventType.port_scan.value:          "T1046",
    EventType.subdomain_found.value:    "T1595",
    EventType.dir_found.value:          "T1083",
    EventType.vuln_found.value:         "T1190",
    EventType.sqli_found.value:         "T1190",
    EventType.login_failed.value:       "T1110",
    EventType.login_success.value:      "T1078",
    EventType.exploit_success.value:    "T1190",
    EventType.lateral_movement.value:   "T1021",
    EventType.credential_dumped.value:  "T1003",
}


class MitreMapper:
    """Maps RedSecEvent and AttackChain instances to MITRE ATT&CK techniques.

    Enrichment follows this precedence:
    1. If the event already carries a ``mitre_technique`` that exists in the
       internal registry, it is kept and ``mitre_tactic`` is (re-)set from
       the registry to ensure consistency.
    2. If the technique is set but unknown, it is left untouched (forward
       compatibility with techniques not yet in the registry).
    3. If no technique is set, one is inferred from ``event_type`` using the
       ``_INFERRED`` mapping and written to both ``mitre_technique`` and
       ``mitre_tactic``.
    """

    def get_technique(self, technique_id: str) -> Optional[dict[str, str]]:
        """Look up a MITRE ATT&CK technique by its ID.

        Args:
            technique_id: Technique identifier string, e.g. ``"T1046"``.

        Returns:
            Dict with ``"tactic"`` and ``"name"`` keys, or ``None`` if the
            technique is not in the internal registry.
        """
        return _TECHNIQUES.get(technique_id)

    def enrich(self, event: RedSecEvent) -> RedSecEvent:
        """Enrich a single event with MITRE ATT&CK technique and tactic.

        If the event already has a ``mitre_technique`` that is present in the
        registry, ``mitre_tactic`` is updated to match the registry value.
        If the technique is absent, it is inferred from ``event_type``.
        Unknown pre-set techniques are left unchanged.

        Args:
            event: The RedSecEvent to enrich. The event is modified in-place
                   and also returned for convenience.

        Returns:
            The same RedSecEvent instance with ``mitre_technique`` and
            ``mitre_tactic`` populated where possible.
        """
        existing = event.mitre_technique

        if existing:
            # Validate and sync tactic for known techniques.
            entry = _TECHNIQUES.get(existing)
            if entry:
                event.mitre_tactic = entry["tactic"]
            # Unknown technique: leave both fields as-is.
            return event

        # Infer from event_type.
        event_type_val = (
            event.event_type
            if isinstance(event.event_type, str)
            else event.event_type.value
        )
        technique_id = _INFERRED.get(event_type_val)
        if technique_id:
            entry = _TECHNIQUES[technique_id]
            event.mitre_technique = technique_id
            event.mitre_tactic = entry["tactic"]

        return event

    def enrich_chain(self, chain: AttackChain) -> AttackChain:
        """Enrich every event in an AttackChain and refresh chain-level metadata.

        Calls ``enrich()`` on each event, then rebuilds ``chain.mitre_techniques``
        as the deduplicated ordered list of all techniques present after
        enrichment.

        Args:
            chain: The AttackChain to enrich. Modified in-place and returned.

        Returns:
            The same AttackChain instance with all events enriched and
            ``mitre_techniques`` updated.
        """
        seen: list[str] = []
        for event in chain.events:
            self.enrich(event)
            if event.mitre_technique and event.mitre_technique not in seen:
                seen.append(event.mitre_technique)

        chain.mitre_techniques = seen
        return chain
