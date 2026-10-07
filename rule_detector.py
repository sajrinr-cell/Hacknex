ATTACK_CHAIN = [
    "LOGIN",
    "FILE_ACCESS",
    "PRIV_ESC",
    "USB_CONNECT",
    "FILE_COPY"
]


def detect_attack_chain(events):
    events = sorted(
        events,
        key=lambda event: event.corrected_timestamp
    )

    users = set(
        event.user
        for event in events
    )

    for user in users:
        user_events = [
            event
            for event in events
            if event.user == user
        ]

        for i in range(len(user_events)):
            matched_events = []
            stage_index = 0

            for event in user_events[i:]:
                if (
                    stage_index < len(ATTACK_CHAIN)
                    and event.action == ATTACK_CHAIN[stage_index]
                ):
                    matched_events.append(event)
                    stage_index += 1

                    if stage_index == len(ATTACK_CHAIN):
                        return {
                            "decision": "ALERT",
                            "risk": 92,
                            "user": user,
                            "stages": [
                                {
                                    "stage": event.action,
                                    "event_ids": [event.event_id]
                                }
                                for event in matched_events
                            ],
                            "attack_dna": ">".join(
                                event.action
                                for event in matched_events
                            )
                        }

    return {
        "decision": "WATCH",
        "risk": 0,
        "user": None,
        "stages": [],
        "attack_dna": ""
    }