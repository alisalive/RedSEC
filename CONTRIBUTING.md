# Contributing to RedSEC

## Development Setup

Clone the repository and install in editable mode:

    git clone https://github.com/alisalive/redsec
    cd redsec
    pip install -e .

## Project Structure

redsec/parsers/     — one parser per tool
redsec/models/      — Pydantic event and chain schemas
redsec/correlation/ — YAML-based correlation engine
redsec/mitre/       — MITRE ATT&CK mapper
redsec/scoring/     — detection risk heuristic
redsec/exporters/   — SEC and HTML exporters
redsec/cli.py       — Click CLI entry point

## Adding a New Parser

1. Create redsec/parsers/yourtool.py
2. Inherit from AbstractParser
3. Implement parse(file_path: str) -> list[RedSecEvent]
4. Add fixture file to tests/
5. Export from redsec/parsers/__init__.py

## Adding Correlation Rules

Add a new YAML block to redsec/correlation/rules/default.yaml

## Dependencies

- pydantic — event schema
- pyyaml — YAML rules
- jinja2 — HTML report
- click — CLI

## Code Style

- Type hints on all functions
- Docstring on all functions and classes
- Use os.path — never hardcode path separators

## SEC Integration Reference

SEC (Simple Event Correlator) by Risto Vaarandi:
https://github.com/simple-evcorr/sec
