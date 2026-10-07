from datetime import datetime


REQUIRED_STAGES = [
    "LOGIN",
    "FILE_ACCESS",
    "PRIV_ESC",
    "USB_CONNECT",
    "FILE_COPY"
]


def analyze_context(events, detection):
    if detection["decision"] != "ALERT":
        return {
            "context": "COINCIDENCE",
            "confidence": 0,
            "time_window_seconds": 0
        }

    event_map = {
        event.event_id: event
        for event in events
    }

    detected_events = []

    for stage in detection["stages"]:
        for event_id in stage["event_ids"]:
            if event_id in event_map:
                detected_events.append(
                    event_map[event_id]
                )

    if not detected_events:
        return {
            "context": "COINCIDENCE",
            "confidence": 0,
            "time_window_seconds": 0
        }

    timestamps = [
        datetime.fromisoformat(
            event.corrected_timestamp
        )
        for event in detected_events
    ]

    time_window = (
        max(timestamps) - min(timestamps)
    ).total_seconds()

    matched = sum(
        stage["stage"] in REQUIRED_STAGES
        for stage in detection["stages"]
    )

    confidence = int(
        (matched / len(REQUIRED_STAGES)) * 100
    )

    if (
        matched == len(REQUIRED_STAGES)
        and time_window <= 300
    ):
        context = "ATTACK_SEQUENCE"

    elif matched == len(REQUIRED_STAGES):
        context = "SLOW_ATTACK"

    else:
        context = "SUSPICIOUS_ACTIVITY"

    return {
        "context": context,
        "confidence": confidence,
        "time_window_seconds": int(time_window)
    }