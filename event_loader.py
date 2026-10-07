import json
from core.event_schema import Event


def load_events(file_path="data/events.json"):
    with open(file_path, "r") as file:
        data = json.load(file)

    events = []

    for item in data:
        event = Event(
            event_id=item["event_id"],
            source=item["source"],
            raw_timestamp=item["raw_timestamp"],
            corrected_timestamp=item["corrected_timestamp"],
            user=item["user"],
            device=item["device"],
            ip=item["ip"],
            action=item["action"],
            object=item["object"],
            confidence=item["confidence"]
        )

        events.append(event)

    return events