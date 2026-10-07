import json
import random
from datetime import datetime, timedelta

random.seed(42)

BASE_TIME = datetime(2026, 10, 7, 2, 0, 0)

events = []
ground_truth = []

event_counter = 1


def add_event(
    source,
    timestamp,
    user,
    device,
    ip,
    action,
    obj,
    confidence,
    label="NORMAL",
    attack_id=None
):
    global event_counter

    event_id = f"E{event_counter:06d}"

    event = {
        "event_id": event_id,
        "source": source,
        "raw_timestamp": timestamp.isoformat(),
        "corrected_timestamp": timestamp.isoformat(),
        "user": user,
        "device": device,
        "ip": ip,
        "action": action,
        "object": obj,
        "confidence": confidence
    }

    events.append(event)

    ground_truth.append({
        "event_id": event_id,
        "label": label,
        "attack_id": attack_id
    })

    event_counter += 1


# -------------------------
# NORMAL USER ACTIVITY
# -------------------------

users = [f"u{i}" for i in range(1, 21)]

for user in users:
    device = f"d{random.randint(1, 10)}"
    ip = f"10.0.0.{random.randint(2, 50)}"

    for _ in range(5):
        timestamp = BASE_TIME + timedelta(
            minutes=random.randint(0, 300)
        )

        add_event(
            source="auth_log",
            timestamp=timestamp,
            user=user,
            device=device,
            ip=ip,
            action="LOGIN",
            obj="system",
            confidence=0.95
        )


# -------------------------
# ATTACK CHAIN
# LOGIN -> FILE_ACCESS -> PRIV_ESC -> USB_CONNECT -> FILE_COPY
# -------------------------

attack_id = "ATTACK_001"

attack_user = "u99"
attack_device = "d99"
attack_ip = "10.0.0.99"

attack_start = BASE_TIME + timedelta(minutes=120)

attack_events = [
    ("auth_log", "LOGIN", "system"),
    ("file_log", "FILE_ACCESS", "confidential_report.pdf"),
    ("security_log", "PRIV_ESC", "admin"),
    ("usb_log", "USB_CONNECT", "usb_77"),
    ("file_log", "FILE_COPY", "confidential_report.pdf")
]

for i, (source, action, obj) in enumerate(attack_events):
    timestamp = attack_start + timedelta(minutes=i * 2)

    add_event(
        source=source,
        timestamp=timestamp,
        user=attack_user,
        device=attack_device,
        ip=attack_ip,
        action=action,
        obj=obj,
        confidence=0.95,
        label="ATTACK",
        attack_id=attack_id
    )


# -------------------------
# HARD NEGATIVE 1
# LEGITIMATE ADMIN BACKUP
# -------------------------

admin_id = "HARD_NEGATIVE_001"

admin_events = [
    ("auth_log", "LOGIN", "system"),
    ("file_log", "FILE_ACCESS", "backup_data"),
    ("file_log", "FILE_COPY", "backup_data")
]

admin_start = BASE_TIME + timedelta(minutes=180)

for i, (source, action, obj) in enumerate(admin_events):
    timestamp = admin_start + timedelta(minutes=i * 3)

    add_event(
        source=source,
        timestamp=timestamp,
        user="admin01",
        device="backup_server",
        ip="10.0.0.10",
        action=action,
        obj=obj,
        confidence=0.95,
        label="HARD_NEGATIVE",
        attack_id=admin_id
    )


# -------------------------
# HARD NEGATIVE 2
# LEGITIMATE USB USAGE
# -------------------------

usb_id = "HARD_NEGATIVE_002"

usb_events = [
    ("auth_log", "LOGIN", "system"),
    ("usb_log", "USB_CONNECT", "usb_legal"),
    ("file_log", "FILE_COPY", "presentation.pptx")
]

usb_start = BASE_TIME + timedelta(minutes=220)

for i, (source, action, obj) in enumerate(usb_events):
    timestamp = usb_start + timedelta(minutes=i * 2)

    add_event(
        source=source,
        timestamp=timestamp,
        user="u10",
        device="d10",
        ip="10.0.0.20",
        action=action,
        obj=obj,
        confidence=0.95,
        label="HARD_NEGATIVE",
        attack_id=usb_id
    )


# -------------------------
# SORT EVENTS BY TIME
# -------------------------

events.sort(key=lambda x: x["corrected_timestamp"])


# -------------------------
# SAVE LOGS
# -------------------------

with open("data/events.json", "w") as f:
    json.dump(events, f, indent=4)


# -------------------------
# SAVE GROUND TRUTH
# -------------------------

with open("data/ground_truth.json", "w") as f:
    json.dump(ground_truth, f, indent=4)


print(f"Generated {len(events)} events.")
print("Saved: data/events.json")
print("Saved: data/ground_truth.json")