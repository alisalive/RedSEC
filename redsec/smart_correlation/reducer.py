"""Alert reduction for RedSEC smart correlation.

Collapses groups of near-duplicate findings (same LLM-detected template,
same target) into a single representative RedSecEvent, cutting down alert
volume before events are handed to the rule-based CorrelationEngine.
"""

from collections import defaultdict
from typing import Optional

from pydantic import BaseModel, Field

from redsec.models.event import RedSecEvent
from redsec.smart_correlation.detector import TemplateAssignment

# Severity rank used to pick the representative event for a collapsed group.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


class ReductionMetrics(BaseModel):
    """Summary of how much alert volume reduction was achieved."""

    raw_count: int = Field(description="Number of events before reduction.")
    reduced_count: int = Field(description="Number of representative events after reduction.")
    reduction_pct: float = Field(description="Percentage reduction in event count, 0-100.")
    template_coverage: dict[str, int] = Field(
        default_factory=dict,
        description="Template label -> number of distinct targets it was seen on. "
        "Singleton (unclustered) events are excluded, since they by definition "
        "have no cross-host spread to report.",
    )
    most_widespread_template: Optional[str] = Field(
        default=None,
        description="Template label with the highest distinct-target count in "
        "template_coverage, or None if no template spans more than one event.",
    )


class AlertReducer:
    """Collapse template-clustered events into representative alerts.

    Events sharing the same ``(template_id, target)`` pair are treated as
    duplicates of the same finding on the same host and collapsed into a
    single representative RedSecEvent: the highest-severity event in the
    group is kept as the base, tagged with ``template:<template_id>``, and
    annotated with the template label and occurrence count in ``raw``.
    """

    def reduce(
        self,
        events: list[RedSecEvent],
        assignments: dict[str, TemplateAssignment],
    ) -> tuple[list[RedSecEvent], "ReductionMetrics"]:
        """Collapse events into one representative per ``(template_id, target)`` group.

        Args:
            events: Flat list of RedSecEvent instances to reduce.
            assignments: Mapping of ``event.id`` -> ``TemplateAssignment``, as
                produced by ``TemplateDetector.detect()``. Events with no
                assignment fall back to their own singleton group so they are
                never dropped.

        Returns:
            Tuple of ``(reduced events list, ReductionMetrics)``.
        """
        raw_count = len(events)
        if raw_count == 0:
            return [], ReductionMetrics(raw_count=0, reduced_count=0, reduction_pct=0.0)

        groups: dict[tuple[str, str], list[RedSecEvent]] = defaultdict(list)
        for event in events:
            assignment = assignments.get(event.id)
            template_id = assignment.template_id if assignment else f"singleton_{event.id}"
            groups[(template_id, event.target)].append(event)

        reduced: list[RedSecEvent] = [
            self._collapse(template_id, group, assignments)
            for (template_id, _target), group in groups.items()
        ]

        reduced_count = len(reduced)
        reduction_pct = round((1 - reduced_count / raw_count) * 100, 2)

        template_coverage, most_widespread_template = self._template_coverage(events, assignments)

        metrics = ReductionMetrics(
            raw_count=raw_count,
            reduced_count=reduced_count,
            reduction_pct=reduction_pct,
            template_coverage=template_coverage,
            most_widespread_template=most_widespread_template,
        )
        return reduced, metrics

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _template_coverage(
        self,
        events: list[RedSecEvent],
        assignments: dict[str, TemplateAssignment],
    ) -> tuple[dict[str, int], "Optional[str]"]:
        """Compute cross-host spread per template, independent of the (template_id, target) collapse.

        This is purely additive reporting: it does not affect which events
        get collapsed by ``reduce()``, only what gets summarized about them.
        Singleton (unclustered) assignments are excluded, since a template
        that was never clustered has no meaningful "spread" to report.

        Args:
            events: Flat list of RedSecEvent instances that were reduced.
            assignments: Mapping of ``event.id`` -> ``TemplateAssignment``.

        Returns:
            Tuple of ``(template_coverage, most_widespread_template)`` where
            ``template_coverage`` maps template label -> distinct target
            count, and ``most_widespread_template`` is the label with the
            highest count (or ``None`` if ``template_coverage`` is empty).
        """
        targets_by_label: dict[str, set[str]] = defaultdict(set)
        for event in events:
            assignment = assignments.get(event.id)
            if assignment is None or assignment.template_id.startswith("singleton_"):
                continue
            targets_by_label[assignment.template_label].add(event.target)

        template_coverage = {label: len(targets) for label, targets in targets_by_label.items()}
        most_widespread_template = (
            max(template_coverage, key=template_coverage.get) if template_coverage else None
        )
        return template_coverage, most_widespread_template

    def _collapse(
        self,
        template_id: str,
        group: list[RedSecEvent],
        assignments: dict[str, TemplateAssignment],
    ) -> RedSecEvent:
        """Collapse one ``(template_id, target)`` group into a single representative event.

        The highest-severity event in the group is used as the base (deep
        copied so the original event objects are left untouched); its tags
        gain a ``template:<template_id>`` marker and its ``raw`` dict records
        the template label and how many events were collapsed.

        Args:
            template_id: The shared template identifier for this group.
            group: Events belonging to the same ``(template_id, target)`` pair.
            assignments: Full assignment map, used to look up the template label.

        Returns:
            A single representative RedSecEvent for the group.
        """
        best = max(
            group,
            key=lambda e: _SEVERITY_RANK.get(
                e.severity if isinstance(e.severity, str) else e.severity.value, 0
            ),
        )
        representative = best.model_copy(deep=True)

        label = template_id
        for event in group:
            assignment = assignments.get(event.id)
            if assignment is not None:
                label = assignment.template_label
                break

        representative.tags = [*representative.tags, f"template:{template_id}"]
        representative.raw = {
            **representative.raw,
            "template_label": label,
            "occurrence_count": len(group),
        }
        return representative
