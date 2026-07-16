"""Smart correlation subpackage for RedSEC.

Implements LLM-based unsupervised template detection for security scan
findings (Vaarandi & Bahsi, 2025) and the alert-volume reduction built on
top of it. This module is opt-in and runs before the rule-based
CorrelationEngine.
"""
