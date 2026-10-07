import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from core.event_loader import load_events


def plot_attack_timeline():
    events = load_events()

    attack_actions = {
        "LOGIN",
        "FILE_ACCESS",
        "PRIV_ESC",
        "USB_CONNECT",
        "FILE_COPY"
    }

    attack_events = [
        event
        for event in events
        if event.action in attack_actions
        and event.user == "u99"
    ]

    attack_events.sort(
        key=lambda event: event.corrected_timestamp
    )

    timestamps = [
        mdates.datestr2num(
            event.corrected_timestamp
        )
        for event in attack_events
    ]

    labels = [
        event.action
        for event in attack_events
    ]

    plt.figure(figsize=(12, 5))

    plt.plot(
        timestamps,
        range(len(attack_events)),
        marker="o"
    )

    for i, label in enumerate(labels):
        plt.annotate(
            label,
            (timestamps[i], i),
            xytext=(10, 5),
            textcoords="offset points"
        )

    plt.gca().xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M:%S")
    )

    plt.xlabel("Time")
    plt.ylabel("Attack Stage")

    plt.title(
        "TechO Attack Timeline - User u99"
    )

    plt.grid(True)
    plt.tight_layout()

    plt.savefig(
        "dashboard/attack_timeline.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "Timeline saved: dashboard/attack_timeline.png"
    )


if __name__ == "__main__":
    plot_attack_timeline()