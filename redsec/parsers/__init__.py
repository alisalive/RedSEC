"""RedSEC parsers package."""

from redsec.parsers.base import AbstractParser
from redsec.parsers.nmap import NmapParser

__all__ = [
    "AbstractParser",
    "NmapParser",
]
