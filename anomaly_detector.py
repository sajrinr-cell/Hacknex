import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)
from sklearn.ensemble import IsolationForest


def detect_anomalies(events):

    features = []

    for event in events:

        features.append([
            event.confidence,
            len(event.action),
            len(event.source),
            len(event.object)
        ])

    model = IsolationForest(
        contamination=0.1,
        random_state=42
    )

    predictions = model.fit_predict(features)

    anomaly_results = []

    for event, prediction in zip(events, predictions):

        anomaly_results.append({
            "event_id": event.event_id,
            "user": event.user,
            "action": event.action,
            "anomaly": prediction == -1
        })

    return anomaly_results
if __name__ == "__main__":

    from core.event_loader import load_events

    events = load_events()

    results = detect_anomalies(events)

    print("=== TechO Anomaly Detection ===")

    for result in results:

        if result["anomaly"]:

            print(
                f"Anomaly: "
                f"{result['event_id']} | "
                f"{result['user']} | "
                f"{result['action']}"
            )

    print("\nAnomaly detection completed.")