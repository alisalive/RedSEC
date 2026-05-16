# RedSEC

![CI](https://github.com/alisalive/RedSEC/actions/workflows/ci.yml/badge.svg)

**Red team log aggregation, correlation, and SEC export tool.**

RedSEC collects output from offensive security tools, correlates events into
attack chains, maps them to MITRE ATT&CK techniques, scores detection risk,
and exports results to Risto Vaarandi's SEC (Simple Event Correlator) format
alongside a dark-theme HTML report.

SEC project: https://github.com/simple-evcorr/sec

---

## Features

- 9 tool parsers — nmap, subfinder, ffuf, feroxbuster, nuclei, sqlmap, hydra,
  metasploit, impacket
- YAML-based attack chain correlation — rules match event sequences within
  configurable time windows
- MITRE ATT&CK mapping — every event automatically enriched with technique ID
  and tactic name
- Detection risk heuristic — score (0.0 to 1.0) estimates SOC detection
  likelihood per event based on tool, event type, and port
- SEC export — generates .conf files with type=Single and type=SingleWithThreshold rules
  consumable directly by Vaarandi's SEC daemon
- HTML report — dark-theme timeline with severity badges, MITRE technique tags,
  and detection risk bars; no external dependencies
- Cross-platform — Windows, Linux, macOS

---

## Installation

    git clone https://github.com/alisalive/RedSEC
    cd redsec
    pip install -e .

---

## Usage

Basic scan with nmap and nuclei output:

    redsec scan --nmap scan.xml --nuclei findings.jsonl --out-log redsec.log

Full pipeline with multiple tools and all outputs:

    redsec scan \
      --nmap scan.xml \
      --subfinder subs.json \
      --ffuf dirs.json \
      --nuclei vulns.jsonl \
      --hydra creds.txt \
      --out-html report.html \
      --out-sec rules.conf \
      --out-log redsec.log

Print version and SEC tool reference:

    redsec version

---

## How It Works

    Tool output files
          |
          v
    Parsers (per-tool)          -- normalize to RedSecEvent
          |
          v
    MitreMapper                 -- enrich with T-ID and tactic
          |
          v
    DetectionScorer             -- assign risk score 0.0-1.0
          |
          v
    CorrelationEngine           -- match YAML rules -> AttackChains
          |
          v
    SecExporter                 -- write .conf (Single + SingleWithThreshold rules)
    HtmlExporter                -- write dark-theme HTML report
    JsonExporter                -- write raw JSON (optional)

---

## SEC Integration

RedSEC exports attack chains as .conf files for SEC (Simple Event Correlator)
by Risto Vaarandi. The full integration workflow:

**Step 1** — Run RedSEC scan and generate SEC rules + event log:

    redsec scan --nmap scan.xml --nuclei findings.jsonl \
      --out-sec rules.conf --out-log redsec.log

**Step 2** — Feed the event log to SEC:

    sec --conf=rules.conf --input=redsec.log --fromstart

SEC will fire alerts for each detected event and chain completion.
Use `--fromstart` to process existing log files. Without it, SEC only
monitors new lines appended to the file.

Each chain produces:

- `type=Single` rules per event — fires once per matching log line:

      type=Single
      ptype=RegExp
      pattern=\S+ nmap port_scan 10\.0\.0\.1 .*port 22
      desc=redsec_FULL_ATTACK_CHAIN_nmap_port_scan_a1b2c3d4
      action=write - CHAIN: %s | EVENT: port_scan | TARGET: 10.0.0.1 | MITRE: T1046

- `type=SingleWithThreshold` completion rule — fires when all events in the
  chain are seen within the time window:

      type=SingleWithThreshold
      ptype=RegExp
      pattern=CHAIN: Full Attack Chain
      desc=Chain Full Attack Chain detected
      action=write - REDSEC CHAIN COMPLETE: Full Attack Chain | severity=critical
      window=86400
      thresh=3

SEC patterns are URL-aware: ffuf/feroxbuster events use the full URL as the
pattern anchor to prevent duplicate matches across events sharing the same
tool, event_type, and target.

---

## Supported Tools

    Tool          Phase                    Output flag
    ------------- ------------------------ ------------------
    nmap          Port scan                -oX (XML)
    subfinder     Subdomain recon          -oJ (JSON)
    ffuf          Web fuzzing              -o -of json
    feroxbuster   Directory fuzzing        --output (JSONL)
    nuclei        Vulnerability scan       -json (JSONL)
    sqlmap        SQL injection            --output-dir (JSON)
    hydra         Brute force              -o (text)
    metasploit    Exploitation/Post-ex     JSON export
    impacket      AD/Post-exploitation     text (secretsdump)

Use `--out-log` to write parsed events as SEC-compatible log lines.
Feed this file directly to SEC with: `sec --conf=rules.conf --input=redsec.log`

---

## MITRE ATT&CK Coverage

    Technique   Tactic              Name
    ----------- ------------------- -----------------------------------
    T1046       Discovery           Network Service Discovery
    T1595       Reconnaissance      Active Scanning
    T1083       Discovery           File and Directory Discovery
    T1190       Initial Access      Exploit Public-Facing Application
    T1110       Credential Access   Brute Force
    T1078       Defense Evasion     Valid Accounts
    T1021       Lateral Movement    Remote Services
    T1003       Credential Access   OS Credential Dumping
    T1059       Execution           Command and Scripting Interpreter
    T1018       Discovery           Remote System Discovery
    T1133       Initial Access      External Remote Services

---

## Project Structure

    redsec/
    ├── redsec/
    │   ├── __init__.py
    │   ├── cli.py
    │   ├── parsers/
    │   │   ├── base.py
    │   │   ├── nmap.py
    │   │   ├── subfinder.py
    │   │   ├── ffuf.py
    │   │   ├── feroxbuster.py
    │   │   ├── nuclei.py
    │   │   ├── sqlmap.py
    │   │   ├── hydra.py
    │   │   ├── metasploit.py
    │   │   └── impacket.py
    │   ├── models/
    │   │   ├── event.py
    │   │   └── chain.py
    │   ├── correlation/
    │   │   ├── engine.py
    │   │   └── rules/
    │   │       └── default.yaml
    │   ├── mitre/
    │   │   └── mapper.py
    │   ├── scoring/
    │   │   └── detection.py
    │   └── exporters/
    │       ├── sec.py
    │       ├── html.py
    │       └── json.py
    ├── tests/
    ├── docs/
    │   └── THEORETICAL_BACKGROUND.md
    ├── CLAUDE.md
    ├── README.md
    └── pyproject.toml

---

## Author

alisalive — https://github.com/alisalive

---

## Acknowledgements

SEC (Simple Event Correlator) by Risto Vaarandi — https://ristov.github.io/

SEC is the core integration target of RedSEC. The EventGroup correlation
model and the Single/EventGroup rule format are Vaarandi's original design.
RedSEC would not exist without SEC.
