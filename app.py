import sys
import os
import streamlit as st


sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


from core.pipeline import run_pipeline


st.set_page_config(
    page_title="TechO",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ TechO")
st.subheader("AI-Powered Cyber Threat Intelligence")


result = run_pipeline()

st.sidebar.title("🔎 Investigation")

selected_user = st.sidebar.selectbox(
    "Select User",
    list(result["user_risks"].keys())
)

anomalies = result["anomalies"]

anomalous_events = [
    item
    for item in anomalies
    if item["anomaly"]
    and item["user"] == selected_user
]

detection = result["detection"]
context = result["context"]
user_risks = result["user_risks"]
ml_risks = result.get(
    "ml_risks",
    {}
)
from core.event_loader import load_events

events = load_events()

selected_events = [
    event
    for event in events
    if event.user == selected_user
]
from core.event_loader import load_events

events = load_events()

selected_events = [
    event
    for event in events
    if event.user == selected_user
]

# Security Alert

if detection["decision"] == "ALERT":
    st.error(
        f"🚨 SECURITY ALERT | Risk Score: "
        f"{detection['risk']}/100"
    )
else:
    st.success(
        "✅ No active attack detected"
    )


# Detection Overview

st.markdown("## Detection Overview")


col1, col2, col3, col4 = st.columns(4)


with col1:
    st.metric(
        "Decision",
        detection["decision"]
    )


with col2:
    st.metric(
        "Risk Score",
        f"{detection['risk']}/100"
    )


with col3:
    st.metric(
        "Context",
        context["context"]
    )


with col4:
    st.metric(
        "Confidence",
        f"{context['confidence']}%"
    )


# Attack Context

# Attack Context

st.markdown("## Attack Context")
detection = result["detection"]
context = result["context"]
user_risks = result["user_risks"]

behavior_scores = result.get(
    "behavior_scores",
    result.get("behavior_score", {})
)

selected_risk = user_risks.get(
    selected_user,
    0
)

selected_behavior = behavior_scores.get(
    selected_user,
    0
)
selected_ml_risk = ml_risks.get(
    selected_user,
    0
)
if selected_risk >= 80:
    risk_level = "HIGH RISK"

elif selected_risk >= 50:
    risk_level = "MEDIUM RISK"

else:
    risk_level = "LOW RISK"

col1, col2, col3, col4, col5 = st.columns(5)


with col1:
    st.metric(
        "Selected User",
        selected_user
    )


with col2:
    st.metric(
        "Risk Score",
        f"{selected_risk}/100"
    )


with col3:
    st.metric(
        "Behavior Score",
        f"{selected_behavior}/100"
    )


with col4:
    st.metric(
        "Attack Type",
        context["context"]
    )
with col5:
    st.metric(
    "Risk Level",
    risk_level
)
st.markdown("## 🤖 ML Anomaly Detection")

st.metric(
    "Anomalous Events",
    len(anomalous_events)
)

if anomalous_events:

    anomaly_table = []

    for item in anomalous_events:
        anomaly_table.append({
            "Event ID": item["event_id"],
            "User": item["user"],
            "Action": item["action"]
        })

    st.dataframe(
        anomaly_table,
        use_container_width=True,
        hide_index=True
    )

else:
    st.success("No anomalous events detected.")
st.metric(
    "ML Risk Contribution",
    f"{selected_ml_risk}/30"
)    
# Attack DNA

# Attack DNA

st.markdown("## Attack DNA")


if selected_user == detection.get("user"):

    st.code(
        detection["attack_dna"]
    )

else:

    st.info(
        f"No complete attack chain detected for {selected_user}."
    )

# Detected Attack Stages

# Detected Attack Stages

# Detected Attack Stages

st.markdown("## Detected Attack Stages")


if selected_user == detection.get("user"):

    stage_cols = st.columns(
        len(detection["stages"])
    )

    for i, stage in enumerate(
        detection["stages"]
    ):

        with stage_cols[i]:

            st.markdown(
                f"### {i + 1}. {stage['stage']}"
            )

            st.success(
                f"Event: {stage['event_ids'][0]}"
            )

            if i < len(detection["stages"]) - 1:
                st.markdown("⬇️")

else:

    st.info(
        f"No attack stages detected for {selected_user}."
    )
# User Event Summary

st.markdown("## User Event Summary")


suspicious_actions = {
    "PRIV_ESC",
    "USB_CONNECT",
    "FILE_COPY"
}


suspicious_event_count = sum(
    1
    for event in selected_events
    if event.action in suspicious_actions
)


col1, col2, col3 = st.columns(3)


with col1:
    st.metric(
        "Total Events",
        len(selected_events)
    )


with col2:
    st.metric(
        "Suspicious Events",
        suspicious_event_count
    )


with col3:
    st.metric(
        "User Risk",
        f"{user_risks.get(selected_user, 0)}/100"
    )
# User Event Investigation

st.markdown("## User Event Investigation")


if selected_events:

    st.write(
        f"Events associated with **{selected_user}**:"
    )


    actions = sorted(
        set(
            event.action
            for event in selected_events
        )
    )


    selected_action = st.selectbox(
        "Filter by Action",
        ["ALL"] + actions
    )


    if selected_action == "ALL":

        filtered_events = selected_events

    else:

        filtered_events = [
            event
            for event in selected_events
            if event.action == selected_action
        ]


    event_table = []

    for event in filtered_events:

        event_table.append({
            "Event ID": event.event_id,
            "Timestamp": event.corrected_timestamp,
            "Action": event.action,
            "Source": event.source,
            "Device": event.device,
            "IP Address": event.ip
        })

    st.dataframe(
        event_table,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        f"No events found for {selected_user}."
    )
# Investigation Report

st.markdown("## Investigation Report")


report_lines = [
    "TechO Cyber Threat Intelligence Report",
    "====================================",
    "",
    f"Investigated User: {selected_user}",
    f"Risk Score: {user_risks.get(selected_user, 0)}/100",
    f"Behavior Score: {behavior_scores.get(selected_user, 0)}/100",
    f"Total Events: {len(selected_events)}",
    f"Suspicious Events: {suspicious_event_count}",
    "",
    "Attack Context:",
    context["context"],
    "",
    "Attack DNA:",
    detection["attack_dna"]
    if selected_user == detection.get("user")
    else "No complete attack chain detected.",
    "",
    "Events:"
]


for event in selected_events:

    report_lines.append(
        f"{event.event_id} | "
        f"{event.corrected_timestamp} | "
        f"{event.action} | "
        f"{event.source} | "
        f"{event.device} | "
        f"{event.ip}"
    )


report_text = "\n".join(report_lines)


st.download_button(
    label="📥 Download Investigation Report",
    data=report_text,
    file_name=f"TechO_{selected_user}_report.txt",
    mime="text/plain"
)
# Explanation

st.markdown("## Why Was This Detected?")


for reason in result["explanation"]["why"]:
    st.write(
        f"• {reason}"
    )


# Counterfactual Analysis

# Counterfactual Analysis

st.markdown("## Counterfactual Analysis")

whatif = result["whatif"]

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Original Risk",
        f"{detection['risk']}/100"
    )

with col2:
    st.metric(
        f"Risk Without {whatif['removed_stage']}",
        f"{whatif['risk_without_usb']}/100"
    )

with col3:
    st.metric(
        "Result",
        whatif["decision"]
    )

if "impact" in whatif:
    st.info(
        f"💡 {whatif['impact']}"
    )

# User Risk Scores

# User Risk Scores

st.markdown("## User Risk Scores")


sorted_risks = sorted(
    user_risks.items(),
    key=lambda item: item[1],
    reverse=True
)


for user, risk in sorted_risks:

    col1, col2 = st.columns([1, 4])

    with col1:
        st.write(
            f"**{user}**"
        )

    with col2:
        st.progress(
            risk / 100
        )

        st.caption(
            f"Risk: {risk}/100"
        )

# Behavior Scores

# Behavior Scores

st.markdown("## Behavior Scores")


sorted_behavior = sorted(
    behavior_scores.items(),
    key=lambda item: item[1],
    reverse=True
)


for user, score in sorted_behavior:

    col1, col2 = st.columns([1, 4])

    with col1:
        st.write(
            f"**{user}**"
        )

    with col2:
        st.progress(
            score / 100
        )

        st.caption(
            f"Behavior Score: {score}/100"
        )


# Attack Timeline

# Attack Timeline

st.markdown("## Attack Timeline")


timeline_path = os.path.join(
    os.path.dirname(__file__),
    "attack_timeline.png"
)


if os.path.exists(timeline_path):

    st.success(
        "Attack timeline successfully generated."
    )

    st.image(
        timeline_path,
        caption=(
            f"Attack Timeline - "
            f"{detection.get('user', 'Unknown')}"
        ),
        use_container_width=True
    )

else:

    st.warning(
        "Attack timeline image not found."
    )


# System Information

# System Information

st.markdown("## System Information")


col1, col2, col3 = st.columns(3)


with col1:
    st.metric(
        "Total Events",
        result["event_count"]
    )


with col2:
    st.metric(
        "Graph Nodes",
        result["graph_nodes"]
    )


with col3:
    st.metric(
        "Graph Edges",
        result["graph_edges"]
    )


st.caption(
    "TechO processed the event dataset and constructed "
    "a temporal graph for attack analysis."
)
