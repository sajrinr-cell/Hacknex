from collections import defaultdict


ACTION_RISK = {
    "LOGIN": 5,
    "FILE_ACCESS": 10,
    "PRIV_ESC": 25,
    "USB_CONNECT": 20,
    "FILE_COPY": 25
}


def calculate_risk_score(events):
    user_risks = defaultdict(int)

    events = sorted(
        events,
        key=lambda event: event.corrected_timestamp
    )

    for event in events:
        user = event.user
        user_risks[user] += ACTION_RISK.get(
            event.action,
            0
        )

    return {
        user: min(score, 100)
        for user, score in user_risks.items()
    }


def calculate_ml_risk(events, anomalies):
    ml_risks = defaultdict(int)

    for anomaly in anomalies:

        if anomaly["anomaly"]:
            user = anomaly["user"]

            ml_risks[user] += 10

    return {
        user: min(score, 30)
        for user, score in ml_risks.items()
    }
def calculate_final_risk(user_risks, ml_risks):
    final_risks = {}

    users = set(user_risks) | set(ml_risks)

    for user in users:
        rule_risk = user_risks.get(user, 0)
        ml_risk = ml_risks.get(user, 0)

        final_risk = min(
            rule_risk + ml_risk,
            100
        )

        final_risks[user] = final_risk

    return final_risks