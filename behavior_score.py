from collections import defaultdict


SUSPICIOUS_ACTIONS = {
    "PRIV_ESC": 25,
    "USB_CONNECT": 20,
    "FILE_COPY": 25,
    "FILE_ACCESS": 10
}


def calculate_behavior_score(events):
    user_scores = defaultdict(int)

    for event in events:
        if event.action in SUSPICIOUS_ACTIONS:
            user_scores[event.user] += SUSPICIOUS_ACTIONS[event.action]

    return {
        user: min(score, 100)
        for user, score in user_scores.items()
    }