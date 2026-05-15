"""Nmap XML output parser for RedSEC.

Parses files produced by nmap's -oX flag and emits one RedSecEvent
per open port per host.
"""

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.base import AbstractParser


class NmapParser(AbstractParser):
    """Parse nmap XML output (-oX) into RedSecEvent instances.

    Each open port on each scanned host produces one event.
    Service name and version are extracted when available and
    included in the description and raw fields.

    MITRE ATT&CK mapping:
        Technique: T1046 — Network Service Discovery
        Tactic:    Discovery
    """

    MITRE_TECHNIQUE = "T1046"
    MITRE_TACTIC = "Discovery"

    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse an nmap XML file and return one event per open port.

        Args:
            file_path: Path to the nmap -oX output file.

        Returns:
            List of RedSecEvent instances, one per open port found.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the XML is malformed or not nmap output.
        """
        self.validate_file(file_path)

        try:
            tree = ET.parse(file_path)
        except ET.ParseError as exc:
            raise ValueError(f"Malformed XML in nmap output: {file_path}") from exc

        root = tree.getroot()
        if root.tag != "nmaprun":
            raise ValueError(
                f"Not a valid nmap XML file (root tag '{root.tag}', expected 'nmaprun'): {file_path}"
            )

        scan_timestamp = self._parse_scan_time(root)
        events: list[RedSecEvent] = []

        for host in root.findall("host"):
            target = self._extract_target(host)
            if target is None:
                continue

            for port_el in host.findall("./ports/port"):
                event = self._port_to_event(port_el, target, scan_timestamp, file_path)
                if event is not None:
                    events.append(event)

        return events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_scan_time(self, root: ET.Element) -> datetime:
        """Extract the scan start time from the nmaprun element.

        Falls back to the current UTC time if the attribute is absent.

        Args:
            root: The root <nmaprun> XML element.

        Returns:
            A timezone-aware UTC datetime representing the scan time.
        """
        start_attr = root.get("start")
        if start_attr and start_attr.isdigit():
            return datetime.fromtimestamp(int(start_attr), tz=timezone.utc)
        return datetime.now(timezone.utc)

    def _extract_target(self, host: ET.Element) -> Optional[str]:
        """Extract the best available address string for a host element.

        Prefers IPv4, then IPv6, then MAC address, then hostname.

        Args:
            host: A <host> XML element from the nmap output.

        Returns:
            Address string, or None if no usable address is found.
        """
        # Address preference order
        for addr_type in ("ipv4", "ipv6", "mac"):
            for addr_el in host.findall("address"):
                if addr_el.get("addrtype") == addr_type:
                    return addr_el.get("addr")

        # Fall back to first hostname
        hostname_el = host.find("./hostnames/hostname")
        if hostname_el is not None:
            return hostname_el.get("name")

        return None

    def _port_to_event(
        self,
        port_el: ET.Element,
        target: str,
        scan_timestamp: datetime,
        source_file: str,
    ) -> Optional[RedSecEvent]:
        """Convert a single <port> element into a RedSecEvent.

        Only ports whose state is 'open' produce an event.

        Args:
            port_el: A <port> XML element.
            target: The resolved address of the scanned host.
            scan_timestamp: UTC datetime of the nmap scan.
            source_file: Original file path, stored in raw for traceability.

        Returns:
            A RedSecEvent for open ports, or None for non-open states.
        """
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            return None

        port_num = int(port_el.get("portid", 0))
        protocol = port_el.get("protocol", "tcp").lower()

        service_name, service_version = self._extract_service(port_el)

        description = self._build_description(
            target, port_num, protocol, service_name, service_version
        )

        raw: dict = {
            "portid": port_num,
            "protocol": protocol,
            "state": "open",
            "service": service_name,
            "version": service_version,
            "source_file": os.path.abspath(source_file),
        }

        return RedSecEvent(
            tool=ToolName.nmap,
            event_type=EventType.port_scan,
            severity=Severity.info,
            timestamp=scan_timestamp,
            target=target,
            port=port_num,
            protocol=protocol,
            description=description,
            raw=raw,
            mitre_technique=self.MITRE_TECHNIQUE,
            mitre_tactic=self.MITRE_TACTIC,
            tags=["port-scan", "recon"],
        )

    def _extract_service(self, port_el: ET.Element) -> tuple[Optional[str], Optional[str]]:
        """Extract service name and version string from a <port> element.

        Args:
            port_el: A <port> XML element, optionally containing a <service> child.

        Returns:
            Tuple of (service_name, version_string), either may be None.
        """
        service_el = port_el.find("service")
        if service_el is None:
            return None, None

        name = service_el.get("name") or None

        # Build version string from available product/version/extrainfo fields.
        parts = [
            service_el.get("product"),
            service_el.get("version"),
            service_el.get("extrainfo"),
        ]
        version = " ".join(p for p in parts if p) or None

        return name, version

    def _build_description(
        self,
        target: str,
        port: int,
        protocol: str,
        service: Optional[str],
        version: Optional[str],
    ) -> str:
        """Build a human-readable description for an open port event.

        Args:
            target: Host IP or domain.
            port: Port number.
            protocol: Network protocol (tcp/udp).
            service: Service name if detected (e.g. 'http').
            version: Service version string if detected.

        Returns:
            A concise single-line description string.
        """
        base = f"Open {protocol.upper()} port {port} on {target}"
        if service:
            base += f" ({service}"
            if version:
                base += f" {version}"
            base += ")"
        return base
