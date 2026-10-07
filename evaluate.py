import json

from core.event_loader import load_events
from detect.rule_detector import detect_attack_chain


def load_ground_truth():
    with open("data/ground_truth.json", "r") as file:
        return json.load(file)


def evaluate_detector():
    events = load_events()
    ground_truth = load_ground_truth()

    detection = detect_attack_chain(events)

    attack_event_ids = {
        item["event_id"]
        for item in ground_truth
        if item["label"] == "ATTACK"
    }

    predicted_event_ids = {
        event_id
        for stage in detection["stages"]
        for event_id in stage["event_ids"]
    }

    true_positive = bool(
        predicted_event_ids & attack_event_ids
    )

    false_positive = bool(
        predicted_event_ids - attack_event_ids
    )

    false_negative = bool(
        attack_event_ids - predicted_event_ids
    )

    true_negative = (
        not predicted_event_ids
        and not attack_event_ids
    )

    precision = (
        true_positive /
        (true_positive + false_positive)
        if (true_positive + false_positive) > 0
        else 0
    )

    recall = (
        true_positive /
        (true_positive + false_negative)
        if (true_positive + false_negative) > 0
        else 0
    )

    false_positive_rate = (
        false_positive /
        (false_positive + true_negative)
        if (false_positive + true_negative) > 0
        else 0
    )

    print("=== TechO Detector Evaluation ===")

    print(f"\nActual attack events: {len(attack_event_ids)}")
    print(f"Predicted attack events: {len(predicted_event_ids)}")

    print(f"\nDecision: {detection['decision']}")
    print(f"Risk: {detection['risk']}")
    print(f"Attack DNA: {detection['attack_dna']}")
    print(f"Attack User: {detection.get('user')}")

    print("\n=== Classification Metrics ===")

    print(
        f"Precision: {precision * 100:.2f}%"
    )

    print(
        f"Recall: {recall * 100:.2f}%"
    )

    print(
        f"False Positive Rate: "
        f"{false_positive_rate * 100:.2f}%"
    )

    print("\n=== Detected Stages ===")

    for stage in detection["stages"]:
        print(
            f"{stage['stage']}: "
            f"{stage['event_ids']}"
        )


if __name__ == "__main__":
    evaluate_detector()