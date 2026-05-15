"""Nuclei JSON output parser for RedSEC.

Parses files produced by nuclei's -json / -jsonl flag and emits one
RedSecEvent per finding.

Nuclei output is JSONL — one JSON object per line. Each object
represents a single template match against a target.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser

# Map nuclei severity strings to RedSEC Severity enum values.
_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
    "unknown": Severity.info,
}

# MITRE ATT&CK mapping by nuclei protocol/type field.
# Fallback is T1190 (Exploit Public-Facing Application).
_MITRE_BY_TYPE: dict[str, tuple[str, str]] = {
    "http": ("T1190", "Initial Access"),
    "https": ("T1190", "Initial Access"),
    "tcp": ("T1046", "Discovery"),
    "udp": ("T1046", "Discovery"),
    "network": ("T1046", "Discovery"),
    "dns": ("T1018", "Discovery"),
    "ssl": ("T1046", "Discovery"),
    "websocket": ("T1190", "Initial Access"),
    "headless": ("T1190", "Initial Access"),
    "file": ("T1083", "Discovery"),
    "code": ("T1059", "Execution"),
    "javascript": ("T1059", "Execution"),
}

_DEFAULT_MITRE: tuple[str, str] = ("T1190", "Initial Access")


class NucleiParser(AbstractParser):
    """Parse nuclei JSONL output (-json / -jsonl) into RedSecEvent instances.

    Each line in the file that contains a valid nuclei finding JSON object
    produces one RedSecEvent. Lines that are empty, comments, or malformed
    JSON are skipped with a warning rather than raising an exception, since
    nuclei can intermix status lines with finding lines.

    MITRE ATT&CK mapping is derived from the nuclei protocol type:
        http/https  → T1190 — Exploit Public-Facing Application (Initial Access)
        tcp/udp     → T1046 — Network Service Discovery (Discovery)
        dns         → T1018 — Remote System Discovery (Discovery)
        file        → T1083 — File and Directory Discovery (Discovery)
        code/js     → T1059 — Command and Scripting Interpreter (Execution)
    """

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a nuclei JSONL output file and return one event per finding.

        Args:
            file_path: Path to the nuclei -json / -jsonl output file.

        Returns:
            List of RedSecEvent instances, one per valid finding line.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file contains no parseable nuclei findings.
        """
        self.validate_file(file_path)

        events: list[RedSecEvent] = []
        abs_path = os.path.abspath(file_path)

        with open(file_path, "r", encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    # Nuclei sometimes emits non-JSON status/progress lines.
                    continue

                if not isinstance(finding, dict):
                    continue

                event = self._finding_to_event(finding, abs_path, line_num)
                if event is not None:
                    events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _finding_to_event(
        self,
        finding: dict,
        source_file: str,
        line_num: int,
    ) -> Optional[RedSecEvent]:
        """Convert a single nuclei finding dict into a RedSecEvent.

        Args:
            finding: Parsed JSON object representing one nuclei match.
            source_file: Absolute path to the source file, stored in raw.
            line_num: Line number in the file, stored in raw for traceability.

        Returns:
            A RedSecEvent, or None if the finding lacks required fields.
        """
        # Require at minimum a matched-at or host field to build a target.
        target = self._extract_target(finding)
        if not target:
            return None

        info: dict = finding.get("info", {})
        template_id: str = finding.get("template-id", finding.get("templateID", "unknown"))
        nuclei_severity: str = info.get("severity", "info").lower()
        severity = _SEVERITY_MAP.get(nuclei_severity, Severity.info)

        protocol: str = finding.get("type", finding.get("protocol", "http")).lower()
        mitre_technique, mitre_tactic = _MITRE_BY_TYPE.get(protocol, _DEFAULT_MITRE)

        timestamp = self._parse_timestamp(finding.get("timestamp"))
        port = self._extract_port(finding)
        description = self._build_description(finding, info, template_id, target)
        tags = self._build_tags(info, template_id, nuclei_severity)

        raw: dict = {
            "template_id": template_id,
            "matched_at": finding.get("matched-at"),
            "host": finding.get("host"),
            "ip": finding.get("ip"),
            "protocol": protocol,
            "severity": nuclei_severity,
            "name": info.get("name"),
            "description": info.get("description"),
            "tags": info.get("tags", []),
            "classification": info.get("classification", {}),
            "matcher_name": finding.get("matcher-name"),
            "extracted_results": finding.get("extracted-results"),
            "source_file": source_file,
            "source_line": line_num,
        }

        return RedSecEvent(
            tool=ToolName.nuclei,
            event_type=EventType.vuln_found,
            severity=severity,
            timestamp=timestamp,
            target=target,
            port=port,
            protocol=protocol,
            description=description,
            raw=raw,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            tags=tags,
        )

    def _extract_target(self, finding: dict) -> Optional[str]:
        """Resolve the best target string from a nuclei finding.

        Prefers the bare host field, then falls back to stripping the
        scheme from matched-at to get a clean IP or hostname.

        Args:
            finding: Parsed nuclei finding dict.

        Returns:
            Host string, or None if no usable target is found.
        """
        host = finding.get("host")
        if host:
            # Strip scheme if present (e.g. "http://example.com" → "example.com").
            for scheme in ("https://", "http://"):
                if host.startswith(scheme):
                    host = host[len(scheme):]
            # Strip path component.
            host = host.split("/")[0]
            # Strip port — we capture that separately.
            host = host.split(":")[0]
            if host:
                return host

        matched_at = finding.get("matched-at", "")
        if matched_at:
            for scheme in ("https://", "http://"):
                if matched_at.startswith(scheme):
                    matched_at = matched_at[len(scheme):]
            return matched_at.split("/")[0].split(":")[0] or None

        return None

    def _extract_port(self, finding: dict) -> Optional[int]:
        """Extract the port number from a nuclei finding.

        Attempts to read from the host field (e.g. 'example.com:8080')
        and from the matched-at URL.

        Args:
            finding: Parsed nuclei finding dict.

        Returns:
            Integer port number, or None if not determinable.
        """
        for field in ("host", "matched-at"):
            value = finding.get(field, "")
            if not value:
                continue
            # Strip scheme.
            for scheme in ("https://", "http://"):
                if value.startswith(scheme):
                    value = value[len(scheme):]
            # Extract host:port portion before any path.
            host_part = value.split("/")[0]
            if ":" in host_part:
                port_str = host_part.split(":")[-1]
                if port_str.isdigit():
                    return int(port_str)
        return None

    def _parse_timestamp(self, raw_ts: Optional[str]) -> datetime:
        """Parse a nuclei ISO-8601 timestamp string into a UTC datetime.

        Falls back to the current UTC time if the string is absent or
        cannot be parsed.

        Args:
            raw_ts: ISO-8601 timestamp string from the nuclei finding.

        Returns:
            Timezone-aware UTC datetime.
        """
        if not raw_ts:
            return datetime.now(timezone.utc)
        try:
            # Python 3.11+ handles 'Z' natively; for 3.9/3.10 replace manually.
            normalized = raw_ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return datetime.now(timezone.utc)

    def _build_description(
        self,
        finding: dict,
        info: dict,
        template_id: str,
        target: str,
    ) -> str:
        """Build a human-readable description for a nuclei finding.

        Args:
            finding: Full parsed nuclei finding dict.
            info: The info sub-object from the finding.
            template_id: Nuclei template identifier string.
            target: Resolved target host string.

        Returns:
            A concise single-line description.
        """
        name = info.get("name") or template_id
        matched_at = finding.get("matched-at", target)
        matcher = finding.get("matcher-name")

        desc = f"[{template_id}] {name} detected on {matched_at}"
        if matcher:
            desc += f" (matcher: {matcher})"
        return desc

    def _build_tags(
        self,
        info: dict,
        template_id: str,
        severity: str,
    ) -> list[str]:
        """Build a tag list from nuclei template metadata.

        Args:
            info: The info sub-object from the nuclei finding.
            template_id: Nuclei template identifier string.
            severity: Nuclei severity string (e.g. 'high').

        Returns:
            List of string tags for the RedSecEvent.
        """
        tags: list[str] = ["vuln-scan", "nuclei", severity]

        # Nuclei tags from template metadata (list or comma-separated string).
        nuclei_tags = info.get("tags", [])
        if isinstance(nuclei_tags, str):
            nuclei_tags = [t.strip() for t in nuclei_tags.split(",") if t.strip()]
        tags.extend(nuclei_tags)

        # Add CVE tag if classification data is present.
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        for cve in cve_ids:
            if cve and cve not in tags:
                tags.append(cve.upper())

        return tags
