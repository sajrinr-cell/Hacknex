import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)
from core.anomaly_detector import detect_anomalies
from core.event_loader import load_events
from core.temporal_graph import build_temporal_graph
from core.behavior_score import calculate_behavior_score
from core.risk_engine import calculate_risk_score
from core.context_analyzer import analyze_context

from detect.rule_detector import detect_attack_chain

from explain.alert_explainer import explain_alert
from explain.counterfactual import calculate_counterfactual


def run_pipeline():
    events = load_events()

    graph = build_temporal_graph(events)

    detection = detect_attack_chain(events)

    behavior_score = calculate_behavior_score(events)

    user_risks = calculate_risk_score(events)
    anomalies = detect_anomalies(events)
    context = analyze_context(
        events,
        detection
    )

    explanation = explain_alert(detection)

    counterfactual = calculate_counterfactual(
        detection
    )

    return {
        "event_count": len(events),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "detection": detection,
        "behavior_score": behavior_score,
        "user_risks": user_risks,
        "context": context,
        "explanation": explanation,
        "anomalies": anomalies,
        "whatif": counterfactual
    }


if __name__ == "__main__":
    result = run_pipeline()

    print("=== TechO Pipeline Test ===")
    print("Total events:", result["event_count"])
    print("Graph nodes:", result["graph_nodes"])
    print("Graph edges:", result["graph_edges"])
    anomaly_count = sum(
        1
        for item in result["anomalies"]
        if item["anomaly"]
    )

    print("Actual anomalies:", anomaly_count)