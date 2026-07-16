"""LLM-based unsupervised template detection for RedSEC.

Implements the template-mining approach described in Vaarandi & Bahsi
(2025), "Using Large Language Models for Template Detection from Security
Event Logs": near-duplicate findings are clustered into templates and each
template is given a plain-English label by the LLM, without predefined
rules or training data.

Used by ``--smart-correlate`` as an optional pre-pass before the rule-based
CorrelationEngine: events sharing a template are collapsed by AlertReducer,
cutting alert volume before rules run. Cross-chunk label merging uses
difflib string similarity (order-sensitive; see README "Known limitation").
"""

import difflib
import json
import os
import time
from collections import defaultdict
from typing import Any, Optional

from pydantic import BaseModel, Field

from redsec.models.event import RedSecEvent

# Max tokens requested per clustering call. Batches are kept small (one
# tool + event_type combination at a time) so this comfortably covers the
# structured JSON response.
_DEFAULT_MAX_TOKENS = 2048

# (tool, event_type) groups larger than this are split into sub-batches
# before being sent to the LLM, to avoid oversized-payload errors (e.g.
# Groq's 413 Payload Too Large) on large scans.
_CHUNK_THRESHOLD = 30

# Sub-batch size used when chunking a large group.
_CHUNK_SIZE = 25

# Minimum normalized string similarity (difflib.SequenceMatcher ratio) required
# to merge two template labels produced by separate chunk-level LLM calls.
# Conservative on purpose: real-world label pairs for genuinely different
# findings have measured well below this (e.g. ~0.65-0.73), while true
# near-duplicates from re-clustering the same issue measure ~0.86+.
_LABEL_MERGE_THRESHOLD = 0.8

# Max retry attempts for a Groq call that hits HTTP 429 (rate limited).
# Chunked scans issue several sequential calls in a tight loop, which reliably
# exceeds Groq's free-tier requests-per-minute limit past the first few chunks
# without this - falling back to singletons for those chunks instead of
# waiting the short cooldown Groq asks for.
_GROQ_RATE_LIMIT_MAX_RETRIES = 3

# Fallback backoff (seconds) used when Groq's 429 response has no usable
# ``retry-after`` header.
_GROQ_RATE_LIMIT_FALLBACK_DELAY = 5.0

# Default model used when provider="anthropic" and no explicit model is given.
_DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"

# Groq's OpenAI-compatible chat completions API.
_GROQ_BASE_URL = "https://api.groq.com/openai/v1"

# JSON schema for the structured clustering response requested from the LLM.
_CLUSTER_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "clusters": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "confidence": {"type": "number"},
                    "member_indices": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                },
                "required": ["label", "confidence", "member_indices"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["clusters"],
    "additionalProperties": False,
}


class TemplateAssignment(BaseModel):
    """Result of LLM-based template clustering for a single event."""

    template_id: str = Field(
        description="Stable identifier for the detected template within its batch.",
    )
    template_label: str = Field(
        description="Plain-English name describing the template, as produced by the LLM.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Model confidence that this event belongs to the assigned template.",
    )


class TemplateDetector:
    """Cluster near-duplicate RedSecEvent findings into LLM-labelled templates.

    Events are grouped by ``(tool, event_type)`` to keep prompts small and
    topically focused, then each group's descriptions are sent to the LLM in
    a single request asking it to cluster near-duplicates and name each
    cluster in plain English. If a batch's LLM call fails for any reason
    (missing SDK, network error, malformed response, ...) that batch falls
    back to treating every event as its own singleton template, so a failed
    API call never crashes the pipeline.
    """

    def __init__(self, provider: str = "anthropic", model: Optional[str] = None) -> None:
        """Configure the LLM provider and model used for template detection.

        Args:
            provider: LLM provider name. ``"anthropic"`` or ``"groq"``.
            model: Model identifier to use for clustering requests. If not
                given, defaults to a known-good Anthropic model for
                ``provider="anthropic"``, or is discovered dynamically from
                Groq's ``/models`` endpoint on first use for ``provider="groq"``.
        """
        self.provider = provider
        self.model = model or (_DEFAULT_ANTHROPIC_MODEL if provider == "anthropic" else None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, events: list[RedSecEvent]) -> dict[str, TemplateAssignment]:
        """Cluster events into templates and return one assignment per event.

        Args:
            events: Flat list of RedSecEvent instances to cluster.

        Returns:
            Dict mapping ``event.id`` -> ``TemplateAssignment``, with exactly
            one entry per input event.
        """
        assignments: dict[str, TemplateAssignment] = {}
        if not events:
            return assignments

        for (tool, event_type), batch in self._group_events(events).items():
            chunks = self._chunk_batch(batch)
            group_assignments: dict[str, TemplateAssignment] = {}
            for chunk_idx, chunk in enumerate(chunks):
                # When a group is split into multiple sub-batches, tag the
                # event_type used for template-id generation with a chunk
                # suffix so template IDs from different sub-batches never
                # collide. Single-chunk groups (the common case) are
                # unaffected and behave exactly as before.
                batch_key = event_type if len(chunks) == 1 else f"{event_type}_chunk{chunk_idx}"
                try:
                    group_assignments.update(self._detect_batch(tool, batch_key, chunk))
                except Exception:  # noqa: BLE001 - any LLM/SDK failure must not crash the pipeline
                    group_assignments.update(self._fallback_assignments(chunk))

            if len(chunks) > 1:
                # Each sub-batch was clustered independently, so the same
                # underlying issue can surface under slightly different
                # labels across chunks. Merge those without another LLM call.
                group_assignments = self._merge_similar_templates(group_assignments)

            assignments.update(group_assignments)

        return assignments

    def _merge_similar_templates(
        self, assignments: dict[str, TemplateAssignment]
    ) -> dict[str, TemplateAssignment]:
        """Merge near-duplicate template labels produced by separate chunk-level LLM calls.

        Cheap, LLM-free second pass: normalized string similarity
        (``difflib.SequenceMatcher``) is used to detect template labels that
        describe the same underlying issue but were worded slightly
        differently by independent clustering calls (e.g. "Weak SSL/TLS
        Cipher Suite" vs "Weak SSL/TLS Cipher Suite Enabled"). Matching
        templates are remapped onto a single canonical ``template_id`` /
        ``template_label`` so their host coverage combines into one entry.

        Singleton (unclustered) assignments are never merge candidates —
        only genuinely clustered templates are compared — to avoid falsely
        collapsing distinct one-off findings that happen to share wording.

        Args:
            assignments: Assignments for a single (tool, event_type) group,
                accumulated across all of its sub-batches.

        Returns:
            A new assignments dict with near-duplicate template_ids remapped
            onto shared canonical template_id/template_label pairs. Returned
            unchanged (same object) if no merge candidates were found.
        """
        # One (template_id -> template_label) pair per distinct non-singleton
        # template, in first-seen order.
        labels_by_template_id: dict[str, str] = {}
        for assignment in assignments.values():
            if assignment.template_id.startswith("singleton_"):
                continue
            labels_by_template_id.setdefault(assignment.template_id, assignment.template_label)

        canonical_of: dict[str, str] = {}
        canonicals: list[str] = []
        for template_id, label in labels_by_template_id.items():
            match = next(
                (
                    canonical_id
                    for canonical_id in canonicals
                    if difflib.SequenceMatcher(
                        None, label.lower(), labels_by_template_id[canonical_id].lower()
                    ).ratio()
                    >= _LABEL_MERGE_THRESHOLD
                ),
                None,
            )
            if match is not None:
                canonical_of[template_id] = match
            else:
                canonical_of[template_id] = template_id
                canonicals.append(template_id)

        if all(template_id == canonical_id for template_id, canonical_id in canonical_of.items()):
            return assignments  # No near-duplicates found — nothing to merge.

        merged: dict[str, TemplateAssignment] = {}
        for event_id, assignment in assignments.items():
            canonical_id = canonical_of.get(assignment.template_id)
            if canonical_id is None:
                merged[event_id] = assignment
                continue
            merged[event_id] = TemplateAssignment(
                template_id=canonical_id,
                template_label=labels_by_template_id[canonical_id],
                confidence=assignment.confidence,
            )
        return merged

    def _chunk_batch(self, batch: list[RedSecEvent]) -> list[list[RedSecEvent]]:
        """Split a batch into LLM-sized sub-batches if it exceeds the chunk threshold.

        Args:
            batch: Events sharing the same ``(tool, event_type)`` key.

        Returns:
            A list of sub-batches. Groups at or below ``_CHUNK_THRESHOLD``
            are returned unchanged as a single-element list.
        """
        if len(batch) <= _CHUNK_THRESHOLD:
            return [batch]
        return [batch[i : i + _CHUNK_SIZE] for i in range(0, len(batch), _CHUNK_SIZE)]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _group_events(
        self, events: list[RedSecEvent]
    ) -> dict[tuple[str, str], list[RedSecEvent]]:
        """Group events by ``(tool, event_type)`` to keep LLM prompts small.

        Args:
            events: Flat list of RedSecEvent instances.

        Returns:
            Dict mapping ``(tool, event_type)`` -> events sharing that key,
            in first-seen order.
        """
        groups: dict[tuple[str, str], list[RedSecEvent]] = defaultdict(list)
        for event in events:
            tool = event.tool if isinstance(event.tool, str) else event.tool.value
            event_type = (
                event.event_type if isinstance(event.event_type, str) else event.event_type.value
            )
            groups[(tool, event_type)].append(event)
        return groups

    def _fallback_assignments(self, batch: list[RedSecEvent]) -> dict[str, TemplateAssignment]:
        """Assign each event in a batch to its own singleton template.

        Used both as the graceful-failure path (LLM call errored) and for
        batches of size 1, where clustering is meaningless.

        Args:
            batch: Events to assign singleton templates to.

        Returns:
            Dict mapping ``event.id`` -> singleton ``TemplateAssignment``.
        """
        return {
            event.id: TemplateAssignment(
                template_id=f"singleton_{event.id}",
                template_label=event.description[:120],
                confidence=1.0,
            )
            for event in batch
        }

    def _detect_batch(
        self, tool: str, event_type: str, batch: list[RedSecEvent]
    ) -> dict[str, TemplateAssignment]:
        """Send one ``(tool, event_type)`` batch of descriptions to the LLM for clustering.

        Args:
            tool: Tool name shared by every event in the batch.
            event_type: Event type shared by every event in the batch.
            batch: Events to cluster.

        Returns:
            Dict mapping ``event.id`` -> ``TemplateAssignment`` for every
            event in the batch.

        Raises:
            Exception: Any error from the SDK import, API call, or response
                parsing propagates to the caller (``detect()``), which
                applies the singleton fallback for the whole batch.
        """
        if len(batch) == 1:
            # Nothing to cluster - a single event is trivially its own template.
            return self._fallback_assignments(batch)

        prompt = self._build_prompt(batch)

        if self.provider == "anthropic":
            text = self._call_anthropic(prompt)
        elif self.provider == "groq":
            text = self._call_groq(prompt)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

        parsed = json.loads(text)

        return self._clusters_to_assignments(tool, event_type, batch, parsed["clusters"])

    def _get_client(self) -> Any:
        """Instantiate the Anthropic SDK client.

        Returns:
            An ``anthropic.Anthropic`` client instance.

        Raises:
            ValueError: If ``self.provider`` is not ``"anthropic"``.
            ImportError: If the ``anthropic`` package is not installed.
        """
        if self.provider != "anthropic":
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

        import anthropic  # Lazy import: anthropic is an optional dependency.

        return anthropic.Anthropic()

    def _call_anthropic(self, prompt: str) -> str:
        """Send one clustering prompt to the Anthropic Messages API.

        Args:
            prompt: The clustering prompt built by ``_build_prompt``.

        Returns:
            The raw JSON text returned by the model.
        """
        client = self._get_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=_DEFAULT_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
            output_config={"format": {"type": "json_schema", "schema": _CLUSTER_JSON_SCHEMA}},
        )
        return next(block.text for block in response.content if block.type == "text")

    def _call_groq(self, prompt: str) -> str:
        """Send one clustering prompt to Groq's OpenAI-compatible chat completions API.

        Uses JSON mode (``response_format: {"type": "json_object"}``) to request
        a parseable response. The model is resolved dynamically from Groq's
        ``/models`` endpoint on first use if not explicitly configured.

        Args:
            prompt: The clustering prompt built by ``_build_prompt``.

        Returns:
            The raw JSON text returned by the model.

        Raises:
            RuntimeError: If ``GROQ_API_KEY`` is not set.
            requests.HTTPError: If the Groq API request fails after retries
                are exhausted (or for any non-429 error).
        """
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not set")

        import requests  # Lazy import, same pattern as the anthropic client.

        model = self.model or self._resolve_groq_model(api_key)

        for attempt in range(_GROQ_RATE_LIMIT_MAX_RETRIES + 1):
            response = requests.post(
                f"{_GROQ_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"},
                    "max_tokens": _DEFAULT_MAX_TOKENS,
                },
                timeout=30,
            )
            if response.status_code == 429 and attempt < _GROQ_RATE_LIMIT_MAX_RETRIES:
                delay = _GROQ_RATE_LIMIT_FALLBACK_DELAY
                retry_after = response.headers.get("retry-after")
                if retry_after is not None:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        pass
                time.sleep(delay)
                continue
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    def _resolve_groq_model(self, api_key: str) -> str:
        """Discover a fast/cheap current Groq model via the live ``/models`` endpoint.

        Never assumes a hardcoded model name, since Groq's available model
        lineup changes over time. Prefers a model whose id suggests a small,
        fast ("instant") variant; falls back to the first model returned.
        The resolved model is cached on ``self.model`` so subsequent calls on
        this detector instance don't re-query the endpoint.

        Args:
            api_key: Groq API key, used to authenticate the ``/models`` call.

        Returns:
            A Groq model id string.

        Raises:
            requests.HTTPError: If the Groq API request fails.
            RuntimeError: If Groq returns no models.
        """
        import requests  # Lazy import, same pattern as the anthropic client.

        response = requests.get(
            f"{_GROQ_BASE_URL}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15,
        )
        response.raise_for_status()
        model_ids = [m["id"] for m in response.json().get("data", [])]
        if not model_ids:
            raise RuntimeError("Groq /models returned no available models")

        resolved = next((m for m in model_ids if "instant" in m.lower()), model_ids[0])
        self.model = resolved
        return resolved

    def _build_prompt(self, batch: list[RedSecEvent]) -> str:
        """Build the clustering prompt for one batch of same-tool/type events.

        Follows the unsupervised template-detection approach of Vaarandi &
        Bahsi (2025): the model is asked to group near-duplicate findings
        (ignoring variable fields such as hostnames, IPs, ports, and paths)
        into templates and give each template a short plain-English label.

        Args:
            batch: Events sharing the same tool and event_type.

        Returns:
            The prompt string to send to the LLM.
        """
        lines = [
            "You are performing unsupervised template detection on security scan "
            "findings, following the approach of clustering near-duplicate log "
            "lines into templates (masking variable fields such as hostnames, "
            "IPs, ports, and paths) and naming each template in plain English.",
            "",
            "Group the following findings into templates. Findings in the same "
            "template should describe the same underlying issue, differing only "
            "in target-specific details.",
            "",
        ]
        for idx, event in enumerate(batch):
            lines.append(f"{idx}: {event.description}")
        lines.append("")
        lines.append(
            'Return a JSON object with a "clusters" array. Each cluster has '
            '"label" (short plain-English template name), "confidence" '
            '(0.0-1.0), and "member_indices" (the indices above belonging to '
            "this template). Every index must appear in exactly one cluster."
        )
        return "\n".join(lines)

    def _clusters_to_assignments(
        self,
        tool: str,
        event_type: str,
        batch: list[RedSecEvent],
        clusters: list[dict[str, Any]],
    ) -> dict[str, TemplateAssignment]:
        """Convert parsed LLM cluster output into per-event TemplateAssignments.

        Args:
            tool: Tool name shared by the batch (used to build stable template IDs).
            event_type: Event type shared by the batch.
            batch: The original event batch, indexed positionally to match
                the ``member_indices`` referenced by the LLM response.
            clusters: Parsed ``clusters`` list from the LLM response.

        Returns:
            Dict mapping ``event.id`` -> ``TemplateAssignment``. Any event not
            referenced by the LLM response falls back to a singleton template
            so no event is ever dropped.
        """
        assignments: dict[str, TemplateAssignment] = {}
        for cluster_idx, cluster in enumerate(clusters):
            template_id = f"{tool}_{event_type}_c{cluster_idx}"
            label = cluster["label"]
            confidence = float(cluster["confidence"])
            for member_idx in cluster["member_indices"]:
                event = batch[member_idx]
                assignments[event.id] = TemplateAssignment(
                    template_id=template_id,
                    template_label=label,
                    confidence=confidence,
                )

        for event in batch:
            if event.id not in assignments:
                assignments.update(self._fallback_assignments([event]))

        return assignments
