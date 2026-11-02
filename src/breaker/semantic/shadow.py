from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ShadowExample:
    decision_family: str
    deterministic_input: Mapping[str, Any]
    known_truth: Any
    answer: Any | None
    confidence: float | None


def evaluate_shadow(examples: tuple[ShadowExample, ...] | list[ShadowExample]) -> Mapping[str, Mapping[str, Any]]:
    grouped: dict[str, list[ShadowExample]] = defaultdict(list)
    for item in examples:
        grouped[item.decision_family].append(item)
    output: dict[str, Mapping[str, Any]] = {}
    for family, items in sorted(grouped.items()):
        answered = [item for item in items if item.answer is not None]
        correct = sum(item.answer == item.known_truth for item in answered)
        incorrect = len(answered) - correct
        confidences = [float(item.confidence) for item in answered if item.confidence is not None]
        output[family] = {
            "sample_count": len(items),
            "correct": correct,
            "incorrect": incorrect,
            "ambiguous": sum(item.answer == "AMBIGUOUS" for item in answered),
            "abstention_or_escalation": len(items) - len(answered),
            "mean_confidence": round(sum(confidences) / len(confidences), 6) if confidences else None,
            "answered_accuracy": round(correct / len(answered), 6) if answered else None,
            "calibration_note": "descriptive only; promotion requires a larger held-out sample" if answered else "not measurable",
        }
    return output
