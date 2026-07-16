"""Tests for the smart_correlation module: TemplateDetector and AlertReducer."""

from datetime import datetime, timezone

import pytest

from redsec.models.event import EventType, RedSecEvent, Severity, ToolName
from redsec.smart_correlation.detector import TemplateAssignment, TemplateDetector
from redsec.smart_correlation.reducer import AlertReducer, ReductionMetrics


def make_event(
    description: str,
    target: str = "192.168.1.1",
    severity: Severity = Severity.info,
    tool: ToolName = ToolName.nuclei,
    event_type: EventType = EventType.vuln_found,
) -> RedSecEvent:
    """Return a minimal RedSecEvent for smart_correlation tests."""
    return RedSecEvent(
        tool=tool,
        event_type=event_type,
        severity=severity,
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        target=target,
        description=description,
    )


class TestTemplateDetectorGrouping:
    def test_groups_by_tool_and_event_type(self):
        detector = TemplateDetector()
        events = [
            make_event("a", tool=ToolName.nuclei, event_type=EventType.vuln_found),
            make_event("b", tool=ToolName.nuclei, event_type=EventType.vuln_found),
            make_event("c", tool=ToolName.nmap, event_type=EventType.port_scan),
        ]
        groups = detector._group_events(events)
        assert set(groups.keys()) == {("nuclei", "vuln_found"), ("nmap", "port_scan")}
        assert len(groups[("nuclei", "vuln_found")]) == 2
        assert len(groups[("nmap", "port_scan")]) == 1

    def test_empty_event_list(self):
        detector = TemplateDetector()
        assert detector.detect([]) == {}

    def test_single_event_batch_is_singleton_without_llm_call(self, monkeypatch):
        detector = TemplateDetector()

        def _boom(*args, **kwargs):
            raise AssertionError("LLM client should not be called for a batch of 1")

        monkeypatch.setattr(detector, "_get_client", _boom)
        events = [make_event("only finding")]
        assignments = detector.detect(events)

        assert len(assignments) == 1
        assignment = assignments[events[0].id]
        assert assignment.confidence == 1.0
        assert assignment.template_id.startswith("singleton_")


class TestTemplateDetectorGracefulFailure:
    def test_llm_error_falls_back_to_singleton_templates(self, monkeypatch):
        detector = TemplateDetector()

        def _raise(*args, **kwargs):
            raise RuntimeError("simulated API failure")

        monkeypatch.setattr(detector, "_detect_batch", _raise)

        events = [make_event(f"finding {i}") for i in range(5)]
        assignments = detector.detect(events)

        assert len(assignments) == len(events)
        for event in events:
            assert event.id in assignments
            assert assignments[event.id].confidence == 1.0

    def test_missing_sdk_treated_as_failure(self, monkeypatch):
        detector = TemplateDetector()

        def _raise_import_error():
            raise ImportError("anthropic not installed")

        monkeypatch.setattr(detector, "_get_client", _raise_import_error)

        # 3 events sharing the same tool/event_type => single batch that
        # will attempt a real (>1 event) LLM call and hit _get_client().
        events = [make_event(f"finding {i}") for i in range(3)]
        assignments = detector.detect(events)

        assert len(assignments) == 3

    def test_one_bad_batch_does_not_affect_other_batches(self, monkeypatch):
        detector = TemplateDetector()

        def _fake_detect_batch(tool, event_type, batch):
            if tool == "nuclei":
                raise RuntimeError("simulated failure for nuclei batch")
            return {
                event.id: TemplateAssignment(
                    template_id=f"{tool}_{event_type}_c0",
                    template_label="clustered ok",
                    confidence=0.95,
                )
                for event in batch
            }

        monkeypatch.setattr(detector, "_detect_batch", _fake_detect_batch)

        events = [
            make_event("a", tool=ToolName.nuclei, event_type=EventType.vuln_found),
            make_event("b", tool=ToolName.nuclei, event_type=EventType.vuln_found),
            make_event("c", tool=ToolName.nmap, event_type=EventType.port_scan),
            make_event("d", tool=ToolName.nmap, event_type=EventType.port_scan),
        ]
        assignments = detector.detect(events)

        assert len(assignments) == 4
        # nuclei batch failed -> singleton fallback.
        assert assignments[events[0].id].template_id.startswith("singleton_")
        assert assignments[events[1].id].template_id.startswith("singleton_")
        # nmap batch succeeded -> shared cluster template.
        assert assignments[events[2].id].template_id == assignments[events[3].id].template_id
        assert assignments[events[2].id].template_label == "clustered ok"


class TestTemplateDetectorSuccessPath:
    def test_clusters_to_assignments(self, monkeypatch):
        detector = TemplateDetector()
        events = [
            make_event("Open port 22/tcp"),
            make_event("Open port 80/tcp"),
            make_event("Directory /admin found"),
        ]

        def _fake_detect_batch(tool, event_type, batch):
            return detector._clusters_to_assignments(
                tool,
                event_type,
                batch,
                [
                    {"label": "Open port findings", "confidence": 0.9, "member_indices": [0, 1]},
                    {"label": "Directory discovery", "confidence": 0.8, "member_indices": [2]},
                ],
            )

        monkeypatch.setattr(detector, "_detect_batch", _fake_detect_batch)
        assignments = detector.detect(events)

        assert assignments[events[0].id].template_id == assignments[events[1].id].template_id
        assert assignments[events[2].id].template_id != assignments[events[0].id].template_id
        assert assignments[events[0].id].template_label == "Open port findings"
        assert assignments[events[2].id].template_label == "Directory discovery"

    def test_unreferenced_index_falls_back_to_singleton(self):
        detector = TemplateDetector()
        events = [make_event("a"), make_event("b"), make_event("c")]

        # LLM response only accounts for indices 0 and 1; index 2 is missing.
        assignments = detector._clusters_to_assignments(
            "nuclei",
            "vuln_found",
            events,
            [{"label": "cluster a", "confidence": 0.7, "member_indices": [0, 1]}],
        )

        assert len(assignments) == 3
        assert assignments[events[2].id].template_id.startswith("singleton_")


class TestTemplateDetectorChunking:
    def test_large_batch_split_into_chunks_with_dissimilar_labels_stay_separate(self, monkeypatch):
        detector = TemplateDetector()
        events = [make_event(f"finding {i}") for i in range(65)]  # > _CHUNK_THRESHOLD

        seen_batch_sizes = []
        # Distinct, genuinely dissimilar labels per chunk so the cross-chunk
        # merge pass must NOT collapse them (false-merge guard). Must not
        # differ by only a trailing character, or similarity ratio stays high.
        dissimilar_labels = [
            "Missing X-Frame-Options Security Header",
            "Exposed AWS S3 Bucket Listing",
            "Default Nginx Welcome Page Exposed",
        ]
        call_count = [0]

        def _fake_detect_batch(tool, event_type, batch):
            seen_batch_sizes.append(len(batch))
            label = dissimilar_labels[call_count[0]]
            call_count[0] += 1
            return detector._clusters_to_assignments(
                tool,
                event_type,
                batch,
                [{"label": label, "confidence": 0.9, "member_indices": list(range(len(batch)))}],
            )

        monkeypatch.setattr(detector, "_detect_batch", _fake_detect_batch)
        assignments = detector.detect(events)

        assert len(assignments) == 65
        # Batch of 65 should be split into sub-batches of at most 25.
        assert all(size <= 25 for size in seen_batch_sizes)
        assert len(seen_batch_sizes) > 1
        # Dissimilar labels across sub-batches must not be merged together.
        template_ids = {a.template_id for a in assignments.values()}
        assert len(template_ids) == len(seen_batch_sizes)

    def test_near_duplicate_labels_across_chunks_merge_into_one_template(self, monkeypatch):
        detector = TemplateDetector()
        events = [make_event(f"finding {i}") for i in range(40)]  # > _CHUNK_THRESHOLD -> 2 chunks

        # These are the exact labels observed in practice when the same
        # underlying issue is clustered independently in two sub-batches.
        near_duplicate_labels = [
            "Weak SSL/TLS Cipher Suite",
            "Weak SSL/TLS Cipher Suite Enabled",
        ]

        def _fake_detect_batch(tool, event_type, batch):
            chunk_idx = 0 if event_type.endswith("_chunk0") else 1
            return detector._clusters_to_assignments(
                tool,
                event_type,
                batch,
                [
                    {
                        "label": near_duplicate_labels[chunk_idx],
                        "confidence": 0.9,
                        "member_indices": list(range(len(batch))),
                    }
                ],
            )

        monkeypatch.setattr(detector, "_detect_batch", _fake_detect_batch)
        assignments = detector.detect(events)

        assert len(assignments) == 40
        template_ids = {a.template_id for a in assignments.values()}
        labels = {a.template_label for a in assignments.values()}
        # Near-duplicate labels from separate chunks must merge into one
        # canonical template_id/template_label pair.
        assert len(template_ids) == 1
        assert len(labels) == 1
        assert labels == {"Weak SSL/TLS Cipher Suite"}  # first-seen label wins

    def test_small_batch_not_chunked(self, monkeypatch):
        detector = TemplateDetector()
        events = [make_event(f"finding {i}") for i in range(10)]

        calls = []

        def _fake_detect_batch(tool, event_type, batch):
            calls.append((tool, event_type, len(batch)))
            return detector._clusters_to_assignments(
                tool, event_type, batch, [{"label": "c", "confidence": 0.9, "member_indices": list(range(len(batch)))}]
            )

        monkeypatch.setattr(detector, "_detect_batch", _fake_detect_batch)
        detector.detect(events)

        assert len(calls) == 1
        assert calls[0][1] == "vuln_found"  # event_type unchanged, no chunk suffix


class TestAlertReducer:
    def test_empty_events(self):
        reducer = AlertReducer()
        reduced, metrics = reducer.reduce([], {})
        assert reduced == []
        assert metrics == ReductionMetrics(raw_count=0, reduced_count=0, reduction_pct=0.0)

    def test_collapses_same_template_and_target(self):
        events = [
            make_event("Open port 22/tcp", target="10.0.0.1", severity=Severity.low),
            make_event("Open port 80/tcp", target="10.0.0.1", severity=Severity.high),
            make_event("Open port 443/tcp", target="10.0.0.1", severity=Severity.medium),
        ]
        assignments = {
            e.id: TemplateAssignment(
                template_id="tmpl_open_port", template_label="Open port findings", confidence=0.9
            )
            for e in events
        }

        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, assignments)

        assert len(reduced) == 1
        rep = reduced[0]
        assert rep.severity == Severity.high.value
        assert "template:tmpl_open_port" in rep.tags
        assert rep.raw["template_label"] == "Open port findings"
        assert rep.raw["occurrence_count"] == 3

        assert metrics.raw_count == 3
        assert metrics.reduced_count == 1
        assert metrics.reduction_pct == pytest.approx(66.67, abs=0.01)

    def test_different_targets_stay_separate(self):
        events = [
            make_event("Open port 22/tcp", target="10.0.0.1"),
            make_event("Open port 22/tcp", target="10.0.0.2"),
        ]
        assignments = {
            e.id: TemplateAssignment(
                template_id="tmpl_open_port", template_label="Open port findings", confidence=0.9
            )
            for e in events
        }
        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, assignments)

        assert len(reduced) == 2
        assert metrics.reduction_pct == 0.0

    def test_different_templates_stay_separate(self):
        events = [
            make_event("Open port 22/tcp", target="10.0.0.1"),
            make_event("Directory /admin found", target="10.0.0.1"),
        ]
        assignments = {
            events[0].id: TemplateAssignment(
                template_id="tmpl_port", template_label="Open port findings", confidence=0.9
            ),
            events[1].id: TemplateAssignment(
                template_id="tmpl_dir", template_label="Directory discovery", confidence=0.9
            ),
        }
        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, assignments)

        assert len(reduced) == 2
        assert metrics.reduction_pct == 0.0

    def test_events_without_assignment_treated_as_singletons(self):
        events = [make_event("finding a"), make_event("finding b")]
        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, {})

        assert len(reduced) == 2
        assert metrics.reduction_pct == 0.0

    def test_original_events_not_mutated(self):
        event = make_event("Open port 22/tcp", target="10.0.0.1")
        original_tags = list(event.tags)
        original_raw = dict(event.raw)
        assignments = {
            event.id: TemplateAssignment(
                template_id="tmpl_a", template_label="label", confidence=0.9
            )
        }

        reducer = AlertReducer()
        reduced, _ = reducer.reduce([event], assignments)

        assert event.tags == original_tags
        assert event.raw == original_raw
        assert reduced[0].tags != event.tags
        assert reduced[0].raw != event.raw

    def test_reduction_math_with_mixed_groups(self):
        # 5 raw events -> 2 representative groups.
        events = [
            make_event("port a", target="10.0.0.1"),
            make_event("port b", target="10.0.0.1"),
            make_event("port c", target="10.0.0.1"),
            make_event("dir a", target="10.0.0.2"),
            make_event("dir b", target="10.0.0.2"),
        ]
        assignments = {
            events[0].id: TemplateAssignment(template_id="t_port", template_label="ports", confidence=0.9),
            events[1].id: TemplateAssignment(template_id="t_port", template_label="ports", confidence=0.9),
            events[2].id: TemplateAssignment(template_id="t_port", template_label="ports", confidence=0.9),
            events[3].id: TemplateAssignment(template_id="t_dir", template_label="dirs", confidence=0.9),
            events[4].id: TemplateAssignment(template_id="t_dir", template_label="dirs", confidence=0.9),
        }

        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, assignments)

        assert metrics.raw_count == 5
        assert metrics.reduced_count == 2
        assert metrics.reduction_pct == pytest.approx(60.0, abs=0.01)
        assert len(reduced) == 2

    def test_template_coverage_counts_distinct_hosts_across_targets(self):
        # Same template ("ports") appears on 3 different hosts -> not collapsed
        # by (template_id, target), but should be counted as coverage=3.
        events = [
            make_event("port a", target="10.0.0.1"),
            make_event("port b", target="10.0.0.2"),
            make_event("port c", target="10.0.0.3"),
            make_event("dir a", target="10.0.0.1"),
        ]
        assignments = {
            events[0].id: TemplateAssignment(template_id="t_port", template_label="ports", confidence=0.9),
            events[1].id: TemplateAssignment(template_id="t_port", template_label="ports", confidence=0.9),
            events[2].id: TemplateAssignment(template_id="t_port", template_label="ports", confidence=0.9),
            events[3].id: TemplateAssignment(template_id="t_dir", template_label="dirs", confidence=0.9),
        }

        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, assignments)

        # Existing per-(template_id, target) collapse is unaffected: 4 raw -> 4 reduced.
        assert metrics.raw_count == 4
        assert metrics.reduced_count == 4
        assert metrics.reduction_pct == 0.0

        assert metrics.template_coverage == {"ports": 3, "dirs": 1}
        assert metrics.most_widespread_template == "ports"

    def test_template_coverage_excludes_singletons(self):
        events = [make_event("a"), make_event("b")]
        reducer = AlertReducer()
        reduced, metrics = reducer.reduce(events, {})

        assert metrics.template_coverage == {}
        assert metrics.most_widespread_template is None
