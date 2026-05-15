"""Abstract base class for all RedSEC parsers."""

import os
from abc import ABC, abstractmethod

from redsec.models.event import RedSecEvent


class AbstractParser(ABC):
    """Base class that all tool-specific parsers must implement.

    Each parser is responsible for reading raw tool output from a file,
    normalizing it into RedSecEvent instances, and returning the list.
    """

    @abstractmethod
    def parse(self, file_path: str) -> list[RedSecEvent]:
        """Parse a tool output file and return normalized events.

        Args:
            file_path: Absolute or relative path to the tool output file.

        Returns:
            A list of RedSecEvent instances extracted from the file.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file content is invalid or unparseable.
        """

    def validate_file(self, file_path: str) -> None:
        """Check that a file exists and is readable before parsing.

        Args:
            file_path: Path to the file to validate.

        Raises:
            FileNotFoundError: If the path does not exist or is not a file.
            PermissionError: If the file exists but cannot be read.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Parser input not found: {file_path}")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Parser input is not readable: {file_path}")
