# Theoretical Background

This document outlines the theoretical foundations underlying RedSEC's
design — event correlation, the MITRE ATT&CK framework, detection risk
heuristics, and the role of bridging offensive and defensive tooling.

---

## Event Correlation

Event correlation is the process of identifying meaningful relationships
between individual log entries or security events that, taken in isolation,
may appear insignificant but together reveal a larger pattern of activity.
In the context of security operations, correlation reduces alert noise and
exposes multi-step attack sequences that no single event would surface.

The foundational work directly relevant to RedSEC is Risto Vaarandi's 2002
paper introducing the Simple Event Correlator:

> Vaarandi, R. (2002). SEC - a Lightweight Event Correlation Tool.
> IEEE Workshop on IP Operations and Management, 2002.
> https://ristov.github.io/publications/sec-ipom02-web.pdf

Vaarandi's SEC defines a rule-driven correlation model in which plain-text
log lines are matched against configurable rule types — most notably
`type=Single` for single-event pattern matching and `type=EventGroup` for
detecting that a set of sub-patterns have all fired within a time window.
This EventGroup primitive is the direct conceptual basis for RedSEC's
attack chain completion detection.

RedSEC's correlation engine reads YAML rule files that specify ordered
event-type sequences and time windows. When a matching sequence is found,
the engine constructs an `AttackChain` object and passes it to the
`SecExporter`, which translates each chain into a set of SEC rules: one
`type=Single` rule per event, and one `type=EventGroup` rule that fires
when all events in the chain have been observed. The resulting `.conf`
file can be consumed directly by the SEC daemon with no modification.

The SEC export format is the primary unique feature differentiating
RedSEC from generic log normalisation pipelines. Rather than producing
a proprietary output, RedSEC integrates into an established, peer-reviewed
open-source correlation infrastructure.

---

## MITRE ATT&CK Framework

The MITRE ATT&CK framework is a globally accessible knowledge base of
adversary tactics, techniques, and procedures based on real-world
observations. It provides a common taxonomy for describing attacker
behaviour across the full attack lifecycle.

> MITRE Corporation. (2020). ATT&CK: Design and Philosophy.
> https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf

RedSEC maps every parsed event to a MITRE ATT&CK technique ID and tactic
name via the `MitreMapper` class. The mapping uses two mechanisms:

1. **Parser-level mapping** — parsers with clear technique affinity set
   `mitre_technique` directly. For example, `NmapParser` always assigns
   T1046 (Network Service Discovery) and `ImpacketParser` assigns T1003
   (OS Credential Dumping).

2. **Engine-level inference** — events that arrive without a technique
   (e.g. from generic parsers or manual construction) are enriched by
   `MitreMapper.enrich()`, which infers the technique from `event_type`
   using a static mapping table.

This dual approach ensures that all events carry ATT&CK context regardless
of which parser produced them, enabling the HTML report and SEC export to
surface technique IDs and tactic names in every rule action and timeline row.

The techniques currently covered span six tactics: Reconnaissance,
Discovery, Initial Access, Credential Access, Lateral Movement, and
Execution — reflecting the attack phases represented by the nine supported
offensive tools.

---

## Detection Risk Heuristic

The detection risk score is a number in the range [0.0, 1.0] assigned to
each event by the `DetectionScorer` class. Higher values indicate a greater
likelihood that a real Security Operations Centre (SOC) would detect the
corresponding activity.

It is important to emphasise that this score is a **heuristic**, not a
probabilistic model. It does not derive from empirical detection rates
or Bayesian inference over incident data. Instead, it encodes practitioner
knowledge about which tool outputs are most likely to trigger existing
defensive controls:

- **High-noise tools** such as nmap and hydra are assigned positive modifiers
  because their behaviour is characterised by high-volume, repetitive network
  activity that matches well-known IDS signatures (e.g. nmap SYN scan
  detection in Snort, hydra brute-force pattern matching in fail2ban).

- **Passive recon tools** such as subfinder receive a negative modifier
  because passive DNS enumeration and certificate transparency lookups
  generate minimal network artefacts and are rarely logged at the target.

- **Post-exploitation tools** such as Metasploit and Impacket receive the
  highest base scores because their activity — opening reverse shells,
  dumping LSASS, performing lateral movement — is precisely the behaviour
  that modern EDR and SIEM products are tuned to detect and alert on.

- **Port modifiers** increase the score when sensitive, highly-monitored
  ports are involved (22 SSH, 445 SMB, 3389 RDP, 1433 MSSQL, 3306 MySQL),
  reflecting that traffic to these services is subject to heightened scrutiny
  in most enterprise environments.

The score is written back to `event.detection_risk` so that it is available
to both the HTML exporter (rendered as a visual risk bar per event) and to
any downstream scoring or prioritisation logic.

---

## Bridging Offensive and Defensive Tooling

A persistent operational gap exists between the output formats produced by
offensive security tools and the input formats consumed by defensive
correlation infrastructure. Tools like nmap, nuclei, and Metasploit produce
XML, JSONL, and proprietary text formats tuned for attacker workflows. SIEM
platforms and event correlators such as SEC operate on normalised, structured
log lines. Without a translation layer, the rich contextual data in offensive
tool output is inaccessible to defensive correlation.

This gap is not merely technical. It reflects a deeper conceptual separation
between offensive and defensive perspectives on the same cyber environment —
a point addressed in foundational cyber security theory:

> Ottis, R., & Lorents, P. (2010). Cyberspace: Definition and Implications.
> Proceedings of the 9th European Conference on Information Warfare and
> Security, Thessaloniki, Greece.

Ottis and Lorents frame cyberspace as a domain in which actions taken by
one actor produce artefacts that are observable — and potentially exploitable
— by others. RedSEC operationalises this framing by making offensive artefacts
(tool output logs) legible to defensive infrastructure (SEC correlation rules).

The RedSEC pipeline implements this bridge in four stages:

    Normalize    -- parse raw tool output into a uniform RedSecEvent schema
    Enrich       -- attach MITRE ATT&CK technique IDs and tactic names
    Correlate    -- apply YAML rules to group events into AttackChains
    Export       -- write SEC .conf rules and HTML reports

Each stage transforms the data without losing fidelity. The `raw` field of
every `RedSecEvent` preserves the complete original parsed data so that
downstream consumers can always recover the source context.

The practical implication for red team engagements is that RedSEC output can
be handed directly to a blue team for post-exercise correlation, or fed into
a live SEC instance during a purple team exercise to validate detection
coverage against the observed attack chain in real time.

---

## References

1. Vaarandi, R. (2002). SEC - a Lightweight Event Correlation Tool.
   IEEE Workshop on IP Operations and Management.
   https://ristov.github.io/publications/sec-ipom02-web.pdf

2. Vaarandi, R., Blumbergs, B., & Caliskan, E. (2015). Simple Event
   Correlator for Scalable Real-Time Processing of Security Logs.
   2015 International Conference on Military Communications and Information
   Systems (ICMCIS), IEEE. CogSIMA 2015.

3. MITRE Corporation. (2020). ATT&CK: Design and Philosophy.
   https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf

4. Ottis, R., & Lorents, P. (2010). Cyberspace: Definition and Implications.
   Proceedings of the 9th European Conference on Information Warfare and
   Security, Thessaloniki, Greece.

5. Vaarandi, R. SEC — Simple Event Correlator. GitHub repository.
   https://github.com/simple-evcorr/sec

6. Vaarandi, R. (2024). SEC Tutorial.
   https://simple-evcorr.github.io/SEC-tutorial.pdf
