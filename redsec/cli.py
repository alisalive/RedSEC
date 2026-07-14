"""RedSEC command-line interface.

Entry point for the redsec tool.  Parses offensive tool output files,
correlates events into attack chains, scores detection risk, and exports
SEC .conf and HTML reports.
"""

import json
import os
import sys
from typing import Optional

import click

from redsec import __author__, __sec_reference__, __version__
from redsec.correlation.engine import CorrelationEngine
from redsec.exporters.html import HtmlExporter
from redsec.exporters.logzilla import LogzillaExporter
from redsec.exporters.sec import SecExporter
from redsec.mitre.mapper import MitreMapper
from redsec.models.chain import AttackChain
from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.parsers.feroxbuster import FeroxbusterParser
from redsec.parsers.ffuf import FfufParser
from redsec.parsers.hydra import HydraParser
from redsec.parsers.impacket import ImpacketParser
from redsec.parsers.metasploit import MetasploitParser
from redsec.parsers.nmap import NmapParser
from redsec.parsers.nuclei import NucleiParser
from redsec.parsers.sqlmap import SqlmapParser
from redsec.parsers.subfinder import SubfinderParser
from redsec.scoring.detection import DetectionScorer

# Default rules directory bundled with the package.
_DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "correlation", "rules")

# Severity rank for finding the highest across chains.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _ok(msg: str) -> None:
    """Print a success message in green.

    Args:
        msg: Message text to display.
    """
    click.echo(click.style(f"  [+] {msg}", fg="green"))


def _warn(msg: str) -> None:
    """Print a warning message in yellow.

    Args:
        msg: Message text to display.
    """
    click.echo(click.style(f"  [!] {msg}", fg="yellow"))


def _err(msg: str) -> None:
    """Print an error message in red to stderr.

    Args:
        msg: Message text to display.
    """
    click.echo(click.style(f"  [x] {msg}", fg="red"), err=True)


def _info(msg: str) -> None:
    """Print an informational message in cyan.

    Args:
        msg: Message text to display.
    """
    click.echo(click.style(f"  [*] {msg}", fg="cyan"))


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

@click.group()
def redsec() -> None:
    """RedSEC — red team log aggregation and correlation tool.

    Parses output from offensive security tools, correlates events into
    attack chains, maps them to MITRE ATT&CK techniques, scores detection
    risk, and exports SEC-compatible rules and HTML reports.
    """


@redsec.command()
def version() -> None:
    """Print RedSEC version and SEC tool reference."""
    click.echo(click.style(f"RedSEC v{__version__}", fg="cyan", bold=True))
    click.echo(f"Author    : {__author__}")
    click.echo(f"SEC tool  : {__sec_reference__}")
    click.echo("SEC (Simple Event Correlator) by Risto Vaarandi")


@redsec.command(name="logzilla-test")
@click.option("--url", required=True, help="Base URL of the LogZilla instance to test (e.g. https://logzilla.example.com).")
@click.option("--token", default=None, help="LogZilla API token. Falls back to the LOGZILLA_TOKEN env var if not provided.")
def logzilla_test(url: str, token: Optional[str]) -> None:
    """Send a single synthetic test event to LogZilla to validate connectivity.

    Use this before a real scan to confirm --push-logzilla / --logzilla-token
    are configured correctly. Distinguishes authentication failures from
    network/unreachable-host failures in its error output.
    """
    click.echo(click.style(f"\nRedSEC v{__version__} — LogZilla connectivity test\n", fg="cyan", bold=True))

    resolved_token = token or os.environ.get("LOGZILLA_TOKEN")
    if not resolved_token:
        _err("No LogZilla token provided. Use --token or set LOGZILLA_TOKEN.")
        sys.exit(1)

    test_event = RedSecEvent(
        tool=ToolName.redsec,
        event_type=EventType.port_scan,
        severity=Severity.info,
        target="redsec-cli",
        description="redsec_connectivity_check",
        tags=["redsec_connectivity_check"],
    )

    _info(f"Sending test event to {url}/incoming ...")
    try:
        exporter = LogzillaExporter()
        result = exporter.push_to_logzilla([test_event], url, resolved_token, max_retries=2, retry_delay=1.0)
    except ValueError as exc:
        _err(f"LogZilla connectivity test failed: {exc}")
        sys.exit(1)
    except Exception as exc:
        _err(f"LogZilla connectivity test failed: {exc}")
        sys.exit(1)

    if result["failed"] == 0 and result["sent"] == 1:
        status = result.get("status_code")
        status_str = f" (HTTP {status})" if status else ""
        _ok(f"LogZilla connectivity OK{status_str} — test event accepted.")
    else:
        detail = result["errors"][0] if result["errors"] else "Unknown error."
        _err(f"LogZilla connectivity test failed: {detail}")
        sys.exit(1)


@redsec.command()
@click.option("--nmap",         type=click.Path(exists=True), default=None, help="nmap XML output file (-oX).")
@click.option("--nuclei",       type=click.Path(exists=True), default=None, help="nuclei JSONL output file (-json).")
@click.option("--subfinder",    type=click.Path(exists=True), default=None, help="subfinder JSON output file (-oJ).")
@click.option("--ffuf",         type=click.Path(exists=True), default=None, help="ffuf JSON output file (-o/-of json).")
@click.option("--feroxbuster",  type=click.Path(exists=True), default=None, help="feroxbuster JSONL output file (--output).")
@click.option("--sqlmap",       type=click.Path(exists=True), default=None, help="sqlmap results.json file (--output-dir).")
@click.option("--hydra",        type=click.Path(exists=True), default=None, help="hydra plain-text output file (-o).")
@click.option("--metasploit",   type=click.Path(exists=True), default=None, help="Metasploit JSON export file.")
@click.option("--impacket",     type=click.Path(exists=True), default=None, help="Impacket secretsdump output file.")
@click.option("--rules-dir",    type=click.Path(exists=True), default=None, help="Custom correlation rules directory.")
@click.option("--out-html",     default="redsec_report.html",  show_default=True, help="Output HTML report path.")
@click.option("--out-sec",      default="redsec_rules.conf",   show_default=True, help="Output SEC .conf path.")
@click.option("--out-json",     default=None, help="Output JSON path (optional).")
@click.option("--out-log",      default=None, help="Write parsed events as SEC-compatible log lines to PATH (for use with: sec --input=PATH).")
@click.option("--out-logzilla-json", default=None, help="Write events in LogZilla HTTP Receiver JSON-lines format to PATH (optional).")
@click.option("--push-logzilla", default=None, help="Push events directly to a LogZilla HTTP Event Receiver at this base URL (optional).")
@click.option("--logzilla-token", default=None, help="LogZilla API token. Falls back to the LOGZILLA_TOKEN env var if not provided.")
def scan(
    nmap: Optional[str],
    nuclei: Optional[str],
    subfinder: Optional[str],
    ffuf: Optional[str],
    feroxbuster: Optional[str],
    sqlmap: Optional[str],
    hydra: Optional[str],
    metasploit: Optional[str],
    impacket: Optional[str],
    rules_dir: Optional[str],
    out_html: str,
    out_sec: str,
    out_json: Optional[str],
    out_log: Optional[str],
    out_logzilla_json: Optional[str],
    push_logzilla: Optional[str],
    logzilla_token: Optional[str],
) -> None:
    """Parse tool output files, correlate events, and generate reports.

    Runs the full RedSEC pipeline:

    \b
    1. Parse all provided input files
    2. Enrich events with MITRE ATT&CK mapping
    3. Score detection risk for each event
    4. Correlate events into attack chains
    5. Export SEC .conf rules file
    6. Export HTML report
    7. Optionally export JSON
    8. Optionally write SEC log file (--out-log)
    9. Optionally export LogZilla JSON (--out-logzilla-json)
    10. Optionally push events to LogZilla (--push-logzilla)
    11. Print summary table

    At least one input file must be provided.
    """
    click.echo(click.style(f"\nRedSEC v{__version__} — scan starting\n", fg="cyan", bold=True))

    # ------------------------------------------------------------------
    # Step 1: Parse input files
    # ------------------------------------------------------------------
    inputs: list[tuple[Optional[str], type, str]] = [
        (nmap,        NmapParser,        "nmap"),
        (nuclei,      NucleiParser,      "nuclei"),
        (subfinder,   SubfinderParser,   "subfinder"),
        (ffuf,        FfufParser,        "ffuf"),
        (feroxbuster, FeroxbusterParser, "feroxbuster"),
        (sqlmap,      SqlmapParser,      "sqlmap"),
        (hydra,       HydraParser,       "hydra"),
        (metasploit,  MetasploitParser,  "metasploit"),
        (impacket,    ImpacketParser,    "impacket"),
    ]

    provided = [(path, cls, label) for path, cls, label in inputs if path is not None]
    if not provided:
        _err("No input files provided. Use --nmap, --nuclei, etc. Run with --help for options.")
        sys.exit(1)

    _info("Parsing input files...")
    all_events: list[RedSecEvent] = []

    for path, parser_cls, label in provided:
        try:
            parser = parser_cls()
            events = parser.parse(path)
            all_events.extend(events)
            _ok(f"{label}: {len(events)} event(s) from {os.path.basename(path)}")
        except Exception as exc:
            _warn(f"{label}: failed to parse {os.path.basename(path)} — {exc}")

    if not all_events:
        _err("No events parsed from any input file. Check file formats.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 2: MITRE ATT&CK enrichment
    # ------------------------------------------------------------------
    _info("Enriching events with MITRE ATT&CK mapping...")
    mapper = MitreMapper()
    for event in all_events:
        mapper.enrich(event)
    _ok(f"MITRE enrichment complete ({len(all_events)} events)")

    # ------------------------------------------------------------------
    # Step 3: Detection risk scoring
    # ------------------------------------------------------------------
    _info("Scoring detection risk...")
    scorer = DetectionScorer()
    scorer.enrich_events(all_events)
    avg_risk = round(sum(e.detection_risk or 0.0 for e in all_events) / len(all_events), 3)
    _ok(f"Detection risk scored (average: {avg_risk:.3f})")

    # ------------------------------------------------------------------
    # Step 4: Correlation
    # ------------------------------------------------------------------
    _info("Running correlation engine...")
    effective_rules_dir = rules_dir if rules_dir else _DEFAULT_RULES_DIR
    try:
        engine = CorrelationEngine(effective_rules_dir)
        chains = engine.correlate(all_events)
        _ok(f"Correlation complete — {len(chains)} chain(s) found")
    except Exception as exc:
        _warn(f"Correlation failed: {exc}. Continuing without chains.")
        chains = []

    # ------------------------------------------------------------------
    # Step 5: SEC export
    # ------------------------------------------------------------------
    _info("Exporting SEC .conf file...")
    sec_exporter = SecExporter()
    try:
        if chains:
            sec_path = sec_exporter.export_all(chains, out_sec)
        else:
            sec_path = sec_exporter.export_events(all_events, out_sec)
        _ok(f"SEC rules written to: {sec_path}")
    except Exception as exc:
        _warn(f"SEC export failed: {exc}")
        sec_path = None

    # ------------------------------------------------------------------
    # Step 6: HTML report
    # ------------------------------------------------------------------
    _info("Generating HTML report...")
    html_exporter = HtmlExporter()
    try:
        if chains:
            html_path = html_exporter.export_all(chains, out_html)
        else:
            # Wrap all events in a single chain for display.
            fallback = _events_to_chain(all_events)
            html_path = html_exporter.export_chain(fallback, out_html)
        _ok(f"HTML report written to: {html_path}")
    except Exception as exc:
        _warn(f"HTML export failed: {exc}")
        html_path = None

    # ------------------------------------------------------------------
    # Step 7: JSON export (optional)
    # ------------------------------------------------------------------
    json_path: Optional[str] = None
    if out_json:
        _info("Exporting JSON...")
        try:
            json_path = _export_json(all_events, chains, out_json)
            _ok(f"JSON written to: {json_path}")
        except Exception as exc:
            _warn(f"JSON export failed: {exc}")

    # ------------------------------------------------------------------
    # Step 8: SEC log file (optional)
    # ------------------------------------------------------------------
    log_path: Optional[str] = None
    if out_log:
        _info("Writing SEC-compatible event log...")
        try:
            abs_log = os.path.abspath(out_log)
            parent = os.path.dirname(abs_log)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(abs_log, "w", encoding="utf-8") as fh:
                for event in all_events:
                    fh.write(event.to_sec_line() + "\n")
            log_path = abs_log
            _ok(f"SEC log written to: {log_path} ({len(all_events)} line(s))")
        except Exception as exc:
            _warn(f"SEC log export failed: {exc}")

    # ------------------------------------------------------------------
    # Step 9: LogZilla JSON export (optional)
    # ------------------------------------------------------------------
    logzilla_json_path: Optional[str] = None
    if out_logzilla_json:
        _info("Exporting LogZilla JSON lines...")
        try:
            logzilla_exporter = LogzillaExporter()
            logzilla_json_path = logzilla_exporter.export_to_file(
                all_events, out_logzilla_json, chains=chains
            )
            _ok(f"LogZilla JSON written to: {logzilla_json_path}")
        except Exception as exc:
            _warn(f"LogZilla JSON export failed: {exc}")

    # ------------------------------------------------------------------
    # Step 10: Push to LogZilla (optional)
    # ------------------------------------------------------------------
    if push_logzilla:
        _info("Pushing events to LogZilla...")
        token = logzilla_token or os.environ.get("LOGZILLA_TOKEN")
        if not token:
            _err("LogZilla push requested but no token provided. Use --logzilla-token or set LOGZILLA_TOKEN.")
        else:
            try:
                logzilla_exporter = LogzillaExporter()
                result = logzilla_exporter.push_to_logzilla(
                    all_events, push_logzilla, token, chains=chains
                )
                _ok(f"LogZilla push complete — sent={result['sent']} failed={result['failed']}")
                for err_msg in result["errors"]:
                    _warn(f"LogZilla: {err_msg}")
            except Exception as exc:
                _warn(f"LogZilla push failed: {exc}")

    # ------------------------------------------------------------------
    # Step 11: Summary table
    # ------------------------------------------------------------------
    _print_summary(all_events, chains, sec_path, html_path, json_path, log_path, logzilla_json_path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _events_to_chain(events: list[RedSecEvent]) -> AttackChain:
    """Wrap a flat event list into a single AttackChain for display purposes.

    Used as a fallback when the correlation engine produces no chains.

    Args:
        events: List of RedSecEvent instances.

    Returns:
        An AttackChain containing all events, named "All Events".
    """
    from redsec.models.chain import AttackChain
    chain = AttackChain(
        name="All Events",
        start_time=min(e.timestamp for e in events),
        end_time=max(e.timestamp for e in events),
    )
    for e in events:
        chain.add_event(e)
    return chain


def _export_json(
    events: list[RedSecEvent],
    chains: list[AttackChain],
    output_path: str,
) -> str:
    """Serialise events and chains to a JSON file.

    Args:
        events: All parsed and enriched events.
        chains: Correlated attack chains.
        output_path: Destination file path.

    Returns:
        Absolute path of the written file.
    """
    data = {
        "redsec_version": __version__,
        "total_events": len(events),
        "total_chains": len(chains),
        "events": [json.loads(e.model_dump_json()) for e in events],
        "chains": [json.loads(c.model_dump_json()) for c in chains],
    }
    abs_path = os.path.abspath(output_path)
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return abs_path


def _highest_severity(chains: list[AttackChain], events: list[RedSecEvent]) -> str:
    """Return the highest severity string across chains and events.

    Args:
        chains: Correlated attack chains.
        events: All events (used as fallback when no chains exist).

    Returns:
        Severity string (e.g. ``"critical"``).
    """
    best = "info"
    sources = (
        [c.severity if isinstance(c.severity, str) else c.severity.value for c in chains]
        if chains
        else [e.severity if isinstance(e.severity, str) else e.severity.value for e in events]
    )
    for sev in sources:
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best, 0):
            best = sev
    return best


def _severity_color(sev: str) -> str:
    """Map a severity string to a Click colour name.

    Args:
        sev: Severity string.

    Returns:
        Click colour name string.
    """
    return {
        "critical": "red",
        "high": "yellow",
        "medium": "yellow",
        "low": "green",
        "info": "cyan",
    }.get(sev, "white")


def _print_summary(
    events: list[RedSecEvent],
    chains: list[AttackChain],
    sec_path: Optional[str],
    html_path: Optional[str],
    json_path: Optional[str],
    log_path: Optional[str] = None,
    logzilla_json_path: Optional[str] = None,
) -> None:
    """Print a formatted summary table to the terminal.

    Args:
        events: All parsed and enriched events.
        chains: Correlated attack chains.
        sec_path: Path of the SEC .conf file, or None if export failed.
        html_path: Path of the HTML report, or None if export failed.
        json_path: Path of the JSON export, or None if not requested/failed.
        log_path: Path of the SEC log file, or None if not requested/failed.
        logzilla_json_path: Path of the LogZilla JSON export, or None if not requested/failed.
    """
    unique_targets = len({e.target for e in events})
    unique_techniques = len({e.mitre_technique for e in events if e.mitre_technique})
    highest = _highest_severity(chains, events)

    click.echo("")
    click.echo(click.style("  -- Summary ------------------------------------------", fg="cyan"))
    click.echo(f"  {'Events parsed':<28} {len(events)}")
    click.echo(f"  {'Chains found':<28} {len(chains)}")
    click.echo(f"  {'Unique targets':<28} {unique_targets}")
    click.echo(f"  {'Unique MITRE techniques':<28} {unique_techniques}")
    click.echo(
        f"  {'Highest severity':<28} "
        + click.style(highest.upper(), fg=_severity_color(highest), bold=True)
    )
    click.echo(click.style("  ----------------------------------------------------", fg="cyan"))
    click.echo(click.style("  Output files:", fg="cyan"))
    if sec_path:
        click.echo(click.style(f"    SEC  : {sec_path}", fg="green"))
    if html_path:
        click.echo(click.style(f"    HTML : {html_path}", fg="green"))
    if json_path:
        click.echo(click.style(f"    JSON : {json_path}", fg="green"))
    if log_path:
        click.echo(click.style(f"    LOG  : {log_path}", fg="green"))
    if logzilla_json_path:
        click.echo(click.style(f"    LOGZILLA JSON : {logzilla_json_path}", fg="green"))
    click.echo("")


if __name__ == "__main__":
    redsec()
