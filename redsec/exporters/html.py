"""HTML report exporter for RedSEC.

Generates dark-theme HTML reports with attack chain timelines,
MITRE technique badges, severity colour-coding, and SEC export hints.
Requires Jinja2 (already listed as a project dependency).
"""

import os
from datetime import datetime, timezone

from jinja2 import Environment

from redsec.models.chain import AttackChain

_REDSEC_VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Colour palettes
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#44aa44",
    "info":     "#4488ff",
}

TOOL_COLORS: dict[str, str] = {
    "nmap":        "#4488ff",
    "subfinder":   "#aa44ff",
    "ffuf":        "#ff8800",
    "feroxbuster": "#ff6644",
    "nuclei":      "#ff4444",
    "sqlmap":      "#ff44aa",
    "hydra":       "#ffcc00",
    "metasploit":  "#44ffaa",
    "impacket":    "#44ddff",
}

_DEFAULT_TOOL_COLOR = "#888888"
_DEFAULT_SEVERITY_COLOR = "#888888"

# ---------------------------------------------------------------------------
# Jinja2 template
# ---------------------------------------------------------------------------

_TEMPLATE_SOURCE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedSEC Report</title>
<style>
  :root {
    --bg:        #0d1117;
    --bg2:       #161b22;
    --bg3:       #21262d;
    --border:    #30363d;
    --text:      #c9d1d9;
    --text-dim:  #8b949e;
    --text-head: #f0f6fc;
    --accent:    #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, monospace; font-size: 14px; line-height: 1.6; }

  /* Layout */
  .container { max-width: 1200px; margin: 0 auto; padding: 24px 16px; }

  /* Header */
  .site-header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
  .logo { font-size: 28px; font-weight: 700; color: var(--text-head); letter-spacing: 2px; }
  .logo span { color: var(--accent); }
  .meta { color: var(--text-dim); font-size: 12px; margin-top: 6px; }
  .overall-severity { display: inline-block; margin-top: 10px; padding: 4px 14px; border-radius: 20px; font-weight: 700; font-size: 13px; }

  /* Summary cards */
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 40px; }
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .card-value { font-size: 32px; font-weight: 700; color: var(--text-head); }
  .card-label { color: var(--text-dim); font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }

  /* Chain block */
  .chain { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 32px; overflow: hidden; }
  .chain-header { padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
  .chain-name { font-size: 18px; font-weight: 700; color: var(--text-head); flex: 1; }
  .chain-meta { color: var(--text-dim); font-size: 12px; white-space: nowrap; }

  /* Badges */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; color: #fff; white-space: nowrap; }
  .badge-severity { font-size: 13px; padding: 4px 14px; }
  .mitre-list { padding: 10px 24px; border-bottom: 1px solid var(--border); display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .mitre-label { color: var(--text-dim); font-size: 12px; margin-right: 4px; }
  .mitre-badge { background: #1f3560; border: 1px solid #3b5ba5; color: #93c5fd; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }

  /* Timeline table */
  .timeline { width: 100%; border-collapse: collapse; }
  .timeline th { background: var(--bg3); color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  .timeline td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }
  .timeline tr:last-child td { border-bottom: none; }
  .timeline tr:hover td { background: var(--bg3); }
  .ts { font-family: monospace; color: var(--text-dim); white-space: nowrap; font-size: 12px; }
  .target { font-family: monospace; color: var(--accent); }
  .port { font-family: monospace; color: var(--text-dim); }
  .desc { color: var(--text); }
  .risk-bar-wrap { display: flex; align-items: center; gap: 6px; min-width: 80px; }
  .risk-bar-bg { background: var(--bg3); border-radius: 4px; height: 6px; flex: 1; overflow: hidden; }
  .risk-bar-fill { height: 100%; border-radius: 4px; }
  .risk-val { font-size: 11px; color: var(--text-dim); white-space: nowrap; }

  /* SEC hint */
  .sec-hint { padding: 14px 24px; background: var(--bg3); border-top: 1px solid var(--border); font-size: 12px; color: var(--text-dim); font-family: monospace; }
  .sec-hint strong { color: var(--accent); }

  /* Footer */
  .footer { text-align: center; color: var(--text-dim); font-size: 12px; padding: 32px 0 16px; border-top: 1px solid var(--border); margin-top: 40px; }
  .footer a { color: var(--accent); text-decoration: none; }

  /* Responsive */
  @media (max-width: 640px) {
    .chain-header { flex-direction: column; align-items: flex-start; }
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header class="site-header">
    <div class="logo"><span style="color:#ff4444">RED</span><span>SEC</span></div>
    <div class="meta">Generated {{ generated_at }} &nbsp;|&nbsp; RedSEC v{{ version }}</div>
    <div>
      <span class="badge badge-severity overall-severity"
            style="background:{{ severity_color(overall_severity) }}; color:{{ '#111' if overall_severity == 'medium' else '#fff' }}">
        {{ overall_severity | upper }}
      </span>
    </div>
  </header>

  <!-- Summary -->
  <section class="summary-grid">
    <div class="card"><div class="card-value">{{ total_chains }}</div><div class="card-label">Attack Chains</div></div>
    <div class="card"><div class="card-value">{{ total_events }}</div><div class="card-label">Total Events</div></div>
    <div class="card"><div class="card-value">{{ unique_targets }}</div><div class="card-label">Unique Targets</div></div>
    <div class="card"><div class="card-value">{{ unique_techniques }}</div><div class="card-label">MITRE Techniques</div></div>
  </section>

  <!-- Chains -->
  {% for chain in chains %}
  {% set sev = chain.severity if chain.severity is string else chain.severity.value %}
  {% set sev_color = severity_color(sev) %}
  {% set dark_text = sev == 'medium' %}
  <section class="chain">

    <div class="chain-header">
      <span class="chain-name">{{ chain.name }}</span>
      <span class="badge badge-severity"
            style="background:{{ sev_color }}; color:{{ '#111' if dark_text else '#fff' }}">
        {{ sev | upper }}
      </span>
      <span class="chain-meta">{{ chain.events | length }} events</span>
      <span class="chain-meta">{{ duration_str(chain) }}</span>
    </div>

    {% if chain.mitre_techniques %}
    <div class="mitre-list">
      <span class="mitre-label">MITRE ATT&CK</span>
      {% for tid in chain.mitre_techniques %}
      <span class="mitre-badge">{{ tid }}</span>
      {% endfor %}
    </div>
    {% endif %}

    <table class="timeline">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Tool</th>
          <th>Event Type</th>
          <th>Target</th>
          <th>Port</th>
          <th>Description</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {% for event in chain.events %}
        {% set tool_str = event.tool if event.tool is string else event.tool.value %}
        {% set et_str = event.event_type if event.event_type is string else event.event_type.value %}
        {% set ev_sev = event.severity if event.severity is string else event.severity.value %}
        <tr>
          <td class="ts">{{ event.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
          <td>
            <span class="badge" style="background:{{ tool_color(tool_str) }}">{{ tool_str }}</span>
          </td>
          <td>
            <span class="badge" style="background:{{ severity_color(ev_sev) }}; color:{{ '#111' if ev_sev == 'medium' else '#fff' }}">
              {{ et_str }}
            </span>
          </td>
          <td class="target">{{ event.target }}</td>
          <td class="port">{{ event.port if event.port else '&mdash;' }}</td>
          <td class="desc">{{ event.description }}</td>
          <td>
            {% if event.detection_risk is not none %}
            <div class="risk-bar-wrap">
              <div class="risk-bar-bg">
                <div class="risk-bar-fill"
                     style="width:{{ (event.detection_risk * 100) | int }}%;
                            background:{{ risk_color(event.detection_risk) }}">
                </div>
              </div>
              <span class="risk-val">{{ '%.2f' % event.detection_risk }}</span>
            </div>
            {% else %}
            <span style="color:var(--text-dim)">—</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <div class="sec-hint">
      <strong>SEC export hint:</strong>
      redsec export --format sec --chain "{{ chain.name }}" --output report.conf
      &nbsp;&nbsp;|&nbsp;&nbsp;
      then: sec --conf=report.conf --input=logfile.log
    </div>

  </section>
  {% endfor %}

  <footer class="footer">
    Generated by <strong>RedSEC v{{ version }}</strong> &mdash;
    SEC integration: <a href="https://github.com/simple-evcorr/sec" target="_blank">Risto Vaarandi's SEC</a>
  </footer>

</div>
</body>
</html>
"""


def _severity_color(sev: str) -> str:
    """Return the hex colour for a severity string.

    Args:
        sev: Severity string (``"critical"``, ``"high"``, etc.).

    Returns:
        Hex colour string, defaulting to grey for unknown values.
    """
    return SEVERITY_COLORS.get(sev.lower(), _DEFAULT_SEVERITY_COLOR)


def _tool_color(tool: str) -> str:
    """Return the hex colour for a tool name string.

    Args:
        tool: Tool name string (``"nmap"``, ``"nuclei"``, etc.).

    Returns:
        Hex colour string, defaulting to grey for unknown tools.
    """
    return TOOL_COLORS.get(tool.lower(), _DEFAULT_TOOL_COLOR)


def _risk_color(risk: float) -> str:
    """Return a colour interpolated from green to red for a risk score.

    Args:
        risk: Float in range [0.0, 1.0].

    Returns:
        Hex colour string.
    """
    if risk >= 0.75:
        return "#ff4444"
    if risk >= 0.5:
        return "#ff8800"
    if risk >= 0.25:
        return "#ffcc00"
    return "#44aa44"


def _duration_str(chain: AttackChain) -> str:
    """Format the duration of a chain as a human-readable string.

    Args:
        chain: The AttackChain whose start/end times are used.

    Returns:
        String like ``"3m 20s"`` or ``"45s"``.
    """
    total = int((chain.end_time - chain.start_time).total_seconds())
    if total >= 3600:
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s"
    if total >= 60:
        m, s = divmod(total, 60)
        return f"{m}m {s}s"
    return f"{total}s"


def _overall_severity(chains: list[AttackChain]) -> str:
    """Return the highest severity string across all chains.

    Args:
        chains: List of AttackChain instances.

    Returns:
        Severity string, or ``"info"`` if the list is empty.
    """
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    best = "info"
    for chain in chains:
        sev = chain.severity if isinstance(chain.severity, str) else chain.severity.value
        if rank.get(sev, 0) > rank.get(best, 0):
            best = sev
    return best


def _build_env() -> Environment:
    """Create a Jinja2 Environment with RedSEC helper functions registered.

    Returns:
        Configured Jinja2 Environment with the report template loaded.
    """
    env = Environment(autoescape=True)
    env.globals["severity_color"] = _severity_color
    env.globals["tool_color"] = _tool_color
    env.globals["risk_color"] = _risk_color
    env.globals["duration_str"] = _duration_str
    env.globals["version"] = _REDSEC_VERSION
    return env


class HtmlExporter:
    """Generate dark-theme HTML attack chain reports for RedSEC.

    Reports are self-contained single-file HTML — no external CDN or
    stylesheet dependencies — and can be opened directly in any browser.

    Jinja2 is used for templating.  All helper functions are registered
    as Jinja2 globals so the template stays logic-free.
    """

    def __init__(self) -> None:
        """Initialise the exporter and compile the Jinja2 template."""
        self._env = _build_env()
        self._template = self._env.from_string(_TEMPLATE_SOURCE)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_chain(self, chain: AttackChain, output_path: str) -> str:
        """Write an HTML report for a single AttackChain.

        Args:
            chain: The AttackChain to render.
            output_path: Destination file path for the HTML output.

        Returns:
            Absolute path of the written file.

        Raises:
            OSError: If the file cannot be written.
        """
        return self._render([chain], output_path)

    def export_all(self, chains: list[AttackChain], output_path: str) -> str:
        """Write an HTML report containing all AttackChains.

        Args:
            chains: List of AttackChain instances to render.
            output_path: Destination file path for the HTML output.

        Returns:
            Absolute path of the written file.

        Raises:
            OSError: If the file cannot be written.
        """
        return self._render(chains, output_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _render(self, chains: list[AttackChain], output_path: str) -> str:
        """Render the Jinja2 template with the given chains and write to disk.

        Args:
            chains: Chain list to pass to the template.
            output_path: Destination file path.

        Returns:
            Absolute path of the written file.
        """
        all_targets: set[str] = set()
        all_techniques: set[str] = set()
        total_events = 0

        for chain in chains:
            total_events += len(chain.events)
            for event in chain.events:
                all_targets.add(event.target)
            all_techniques.update(chain.mitre_techniques)

        overall = _overall_severity(chains)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        html = self._template.render(
            chains=chains,
            total_chains=len(chains),
            total_events=total_events,
            unique_targets=len(all_targets),
            unique_techniques=len(all_techniques),
            overall_severity=overall,
            generated_at=generated_at,
        )

        abs_path = os.path.abspath(output_path)
        parent = os.path.dirname(abs_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return abs_path
